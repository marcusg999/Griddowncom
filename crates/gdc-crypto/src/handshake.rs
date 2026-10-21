//! The join handshake: `Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s`, direct link only.
//!
//! # Why this pattern
//!
//! **Noise rather than a hand-rolled exchange** because Bridgefy's four-message
//! TOFU exchange is the direct cause of three published findings (A-1, A-2,
//! C-3), and because a pattern with a written security proof, a test-vector
//! suite and a reviewed Rust implementation (`snow`) is strictly better than
//! anything invented here.
//!
//! **XX** because neither side can know the other's static key beforehand:
//! statics are *per-session* and the peer may have started its session a second
//! ago. XX is the pattern for exactly that case — mutual static transmission,
//! mutual authentication, identity hiding for both parties.
//!
//! **psk0** — the channel pre-shared key mixed in *before* the first ephemeral
//! — because that is what makes holding the QR the thing that proves
//! membership. With `psk0`, message 1 already carries an AEAD tag under a
//! chaining key derived from the channel PSK, so a device without the invite
//! cannot produce a message 1 that is accepted, cannot read message 2, and
//! cannot learn either static. Later placements (`psk3`) would let any passer-by
//! get as far as reading the responder's static. Rejecting a non-member at the
//! first byte also means a stranger cannot make us do a Diffie-Hellman.
//!
//! What this buys, stated exactly: a session key is authenticated *against the
//! channel key*. Impersonation inside a channel is then structurally
//! impossible, because there is no claimed identifier to impersonate — identity
//! *is* the static key, and presenting a key requires its private half. The
//! residual attack is a channel member running two handshakes as a
//! man-in-the-middle, which is what the short authentication string is for.
//!
//! # Why it cannot be completed through an intermediary
//!
//! Three things, in layers:
//!
//! 1. `gdc-wire` refuses to relay [`Kind::Handshake`] at all, and we additionally
//!    require `ttl == 1` on every handshake frame, so a conforming relay cannot
//!    carry one and a non-conforming one is visible.
//! 2. The Noise **prologue** contains a [`LinkBinding`] supplied by the
//!    transport. A middle device necessarily has two different links, so the two
//!    ends mix different prologues, their chaining keys diverge, and the
//!    handshake fails at message 1 — before any key is exchanged. This is the
//!    structural answer, not a human one.
//! 3. A member that bypasses both and runs two handshakes ends up with two
//!    different handshake hashes, so the two humans read different short
//!    authentication strings. That is the last line, and it is a human one.
//!
//! # Frame sizes
//!
//! The Noise payloads are padded to fixed sizes chosen so each handshake
//! message lands *exactly* on a bucket, so handshake frames leak nothing by
//! length either: 64, 128, 128 bytes of body, i.e. 96 + 160 + 160 = 416 bytes
//! on the wire for the whole join. Three messages, two round trips; the
//! initiator can send its first encrypted record immediately after message 3.

use gdc_wire::{Flags, Frame, Kind, MsgId};
use snow::params::NoiseParams;

use crate::channel::{ChannelId, ChannelKeys};
use crate::error::{CryptoError, Rejected};
use crate::identity::{SessionIdentity, SessionKey};
use crate::kdf::{derive, L_SAS};
use crate::rng::Rng;

const PATTERN: &str = "Noise_XXpsk0_25519_ChaChaPoly_BLAKE2s";
const PROLOGUE_DOMAIN: &[u8] = b"gdc/v1/join";

/// Body length of each handshake message, by index.
const MSG_LENS: [usize; 3] = [64, 128, 128];
/// Noise payload length of each handshake message, by index.
const PAYLOAD_LENS: [usize; 3] = [16, 32, 64];

/// Which side of the handshake this is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Role {
    /// Scanned the QR and spoke first.
    Initiator,
    /// Showed the QR and answered.
    Responder,
}

/// A value that identifies one direct link, identically at both of its ends.
///
/// Mixed into the Noise prologue. The transport must supply a value that is the
/// same on both endpoints of a link and different for different links — for
/// example a hash of the two endpoint addresses in a canonical order together
/// with a connection-local nonce. That is what makes a relayed handshake fail by
/// construction instead of by convention.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LinkBinding(Vec<u8>);

impl LinkBinding {
    /// Longest permitted binding.
    pub const MAX_LEN: usize = 64;

    /// Bind to a direct link.
    pub fn direct(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.len() > Self::MAX_LEN {
            return Err(CryptoError::LinkBindingTooLong);
        }
        Ok(LinkBinding(bytes.to_vec()))
    }

    /// No link binding.
    ///
    /// Layer 2 of the three defences above is switched off: a handshake can
    /// then complete through a man-in-the-middle that owns both links, and only
    /// the short authentication string will catch it. Acceptable in tests and
    /// on a transport that genuinely cannot name its links; never the default.
    pub fn unbound() -> Self {
        LinkBinding(Vec::new())
    }

    /// The binding bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A short authentication string for two humans to compare out loud.
///
/// Eight decimal digits, about 26.6 bits, derived from the Noise handshake hash
/// — which covers both ephemerals, both X25519 statics and both Ed25519
/// identity keys, because every handshake payload is mixed into `h`. An active
/// man-in-the-middle has to commit to its substitution before it learns either
/// string, so it wins with probability about one in 10^8 per attempt.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sas([u8; 8]);

impl Sas {
    /// The eight digits, grouped for reading aloud.
    pub fn digits(&self) -> String {
        let v = u64::from_be_bytes(self.0) % 100_000_000;
        format!("{:04} {:04}", v / 10_000, v % 10_000)
    }

    /// The raw bytes the digits come from.
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl core::fmt::Debug for Sas {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Sas({})", self.digits())
    }
}

/// An in-progress join.
pub struct Handshake {
    noise: snow::HandshakeState,
    role: Role,
    channel: ChannelId,
    tag: gdc_wire::ChanTag,
    local_ed: [u8; 32],
    remote_ed: Option<SessionKey>,
    step: usize,
}

impl core::fmt::Debug for Handshake {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Handshake")
            .field("role", &self.role)
            .field("channel", &self.channel)
            .field("step", &self.step)
            .finish()
    }
}

impl Handshake {
    /// Start a handshake in `role` for `keys`, bound to `link`.
    pub fn new(
        role: Role,
        identity: &SessionIdentity,
        keys: &ChannelKeys,
        link: &LinkBinding,
        epoch: u64,
    ) -> Result<Self, CryptoError> {
        if keys.expired(epoch) {
            return Err(CryptoError::ChannelExpired);
        }
        let params: NoiseParams = PATTERN.parse().map_err(|_| CryptoError::Handshake)?;
        let mut prologue = Vec::with_capacity(PROLOGUE_DOMAIN.len() + 17 + link.0.len());
        prologue.extend_from_slice(PROLOGUE_DOMAIN);
        prologue.push(gdc_wire::WIRE_VERSION);
        prologue.extend_from_slice(keys.bind());
        prologue.extend_from_slice(link.as_bytes());

        let builder = snow::Builder::new(params)
            .local_private_key(identity.handshake_secret())
            .psk(0, keys.psk())
            .prologue(&prologue);
        let noise = match role {
            Role::Initiator => builder.build_initiator(),
            Role::Responder => builder.build_responder(),
        }
        .map_err(|_| CryptoError::Handshake)?;

        Ok(Handshake {
            noise,
            role,
            channel: keys.id(),
            tag: keys.tag_for(epoch),
            local_ed: identity.session_key().0,
            remote_ed: None,
            step: 0,
        })
    }

    /// Which channel this join is for.
    pub fn channel(&self) -> ChannelId {
        self.channel
    }

    /// Whether it is this side's turn to write.
    pub fn our_turn(&self) -> bool {
        self.step < 3 && (self.step % 2 == 0) == (self.role == Role::Initiator)
    }

    /// Whether all three messages have been exchanged.
    pub fn is_complete(&self) -> bool {
        self.step >= 3 && self.noise.is_handshake_finished()
    }

    /// Produce the next handshake frame.
    pub fn write_frame(&mut self, rng: &mut impl Rng) -> Result<Frame, CryptoError> {
        if !self.our_turn() {
            return Err(CryptoError::HandshakeOrder);
        }
        let i = self.step;
        let mut payload = vec![0u8; PAYLOAD_LENS[i]];
        if i > 0 {
            payload[..32].copy_from_slice(&self.local_ed);
        }
        let mut body = vec![0u8; MSG_LENS[i]];
        let n = self
            .noise
            .write_message(&payload, &mut body)
            .map_err(|_| CryptoError::Handshake)?;
        if n != MSG_LENS[i] {
            return Err(CryptoError::Handshake);
        }
        let mut id = [0u8; 16];
        rng.fill(&mut id);
        // ttl 1: a handshake is for the peer in front of us and nobody else.
        let frame = Frame::new(
            Kind::Handshake,
            Flags::empty(),
            1,
            MsgId(id),
            self.tag,
            &body,
            &mut |b: &mut [u8]| rng.fill(b),
        )
        .map_err(|_| CryptoError::Handshake)?;
        self.step += 1;
        Ok(frame)
    }

    /// Consume the peer's handshake frame.
    pub fn read_frame(&mut self, frame: &Frame) -> Result<(), CryptoError> {
        if frame.hdr.kind != Kind::Handshake || frame.hdr.ttl != 1 {
            return Err(CryptoError::HandshakeNotDirect);
        }
        if frame.hdr.tag != self.tag {
            return Err(CryptoError::HandshakeNotDirect);
        }
        if self.our_turn() || self.step >= 3 {
            return Err(CryptoError::HandshakeOrder);
        }
        let i = self.step;
        if frame.body().len() != MSG_LENS[i] {
            return Err(CryptoError::Handshake);
        }
        let mut payload = vec![0u8; PAYLOAD_LENS[i]];
        let n = self
            .noise
            .read_message(frame.body(), &mut payload)
            .map_err(|_| CryptoError::Handshake)?;
        if n != PAYLOAD_LENS[i] {
            return Err(CryptoError::Handshake);
        }
        if i == 0 {
            // Message 1 carries no identity; its padding must be zero so it
            // cannot be used as a covert channel by a modified client.
            if payload.iter().any(|b| *b != 0) {
                return Err(CryptoError::Handshake);
            }
        } else {
            let mut ed = [0u8; 32];
            ed.copy_from_slice(&payload[..32]);
            if ed25519_dalek::VerifyingKey::from_bytes(&ed).is_err() {
                return Err(CryptoError::BadPeerIdentity);
            }
            if payload[32..].iter().any(|b| *b != 0) {
                return Err(CryptoError::Handshake);
            }
            self.remote_ed = Some(SessionKey(ed));
        }
        self.step += 1;
        Ok(())
    }

    /// Finish, yielding a session.
    pub fn finish(self) -> Result<Session, CryptoError> {
        if !self.is_complete() {
            return Err(CryptoError::HandshakeOrder);
        }
        let remote = self.remote_ed.ok_or(CryptoError::BadPeerIdentity)?;
        let mut remote_x = [0u8; 32];
        let rs = self
            .noise
            .get_remote_static()
            .ok_or(CryptoError::Handshake)?;
        if rs.len() != 32 {
            return Err(CryptoError::Handshake);
        }
        remote_x.copy_from_slice(rs);
        let sas = Sas(*derive::<8>(self.noise.get_handshake_hash(), L_SAS));
        let transport = self
            .noise
            .into_stateless_transport_mode()
            .map_err(|_| CryptoError::Handshake)?;
        Ok(Session {
            channel: self.channel,
            remote,
            remote_x,
            sas,
            confirmed: false,
            transport,
        })
    }
}

/// A completed join.
///
/// `remote` is the peer's *verified* session key: it arrived inside a Noise
/// payload authenticated by a static key the pattern proved possession of. All
/// per-peer state anywhere in this crate is keyed on this value and never on
/// anything the peer merely claimed, which is rule 10.
pub struct Session {
    channel: ChannelId,
    remote: SessionKey,
    remote_x: [u8; 32],
    sas: Sas,
    confirmed: bool,
    transport: snow::StatelessTransportState,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Session")
            .field("channel", &self.channel)
            .field("remote", &self.remote)
            .field("sas", &self.sas)
            .field("confirmed", &self.confirmed)
            .finish()
    }
}

impl Session {
    /// Which channel the join was for.
    pub fn channel(&self) -> ChannelId {
        self.channel
    }

    /// The peer's verified session key.
    pub fn remote(&self) -> SessionKey {
        self.remote
    }

    /// The peer's verified Noise static.
    pub fn remote_handshake_key(&self) -> [u8; 32] {
        self.remote_x
    }

    /// The string to show the user.
    pub fn sas(&self) -> Sas {
        self.sas
    }

    /// Record that the two humans read the same string.
    pub fn confirm_sas(&mut self) {
        self.confirmed = true;
    }

    /// Whether the string was confirmed. The roster will not promote an entry
    /// to verified without this.
    pub fn sas_confirmed(&self) -> bool {
        self.confirmed
    }

    /// Encrypt a direct message to this peer.
    ///
    /// Stateless transport mode with an explicit nonce, because a mesh delivers
    /// out of order and a stateful counter would desynchronise. Replay is the
    /// caller's windowed check, as for channel traffic.
    pub fn seal_direct(&self, nonce: u64, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut out = vec![0u8; payload.len() + 16];
        let n = self
            .transport
            .write_message(nonce, payload, &mut out)
            .map_err(|_| CryptoError::Handshake)?;
        out.truncate(n);
        Ok(out)
    }

    /// Decrypt a direct message from this peer.
    pub fn open_direct(&self, nonce: u64, ct: &[u8]) -> Result<Vec<u8>, Rejected> {
        let want = ct.len().checked_sub(16).ok_or(Rejected)?;
        let mut out = vec![0u8; want];
        let n = self
            .transport
            .read_message(nonce, ct, &mut out)
            .map_err(|_| Rejected)?;
        out.truncate(n);
        Ok(out)
    }
}
