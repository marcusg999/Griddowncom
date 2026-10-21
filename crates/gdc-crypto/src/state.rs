//! The whole crypto state of one node, and the two ways it ends.
//!
//! `CryptoState` owns the session identity, every installed channel, the tag
//! matcher and the roster, so that "wipe everything" is one call on one object
//! rather than a checklist spread over a codebase.
//!
//! * [`CryptoState::new_identity`] ends the session. The old X25519 and Ed25519
//!   keys are zeroized, every send counter and replay window is dropped, and the
//!   roster is cleared, so the new session shares no key material and no state
//!   with the old one. Installed channels survive, because the alternative is
//!   making a user re-scan a QR to change nickname, and because channel
//!   membership is observable by design in a channel-first address scheme —
//!   pretending otherwise would be a privacy claim we cannot keep.
//! * [`CryptoState::panic_wipe`] ends everything. Identity, channels, keys,
//!   tags, roster: zeroized in place and then dropped.

use std::collections::HashMap;

use gdc_wire::{ChanTag, Flags, Frame, Kind};

use crate::audit::{Audit, SecretAudit};
use crate::channel::{ChannelId, ChannelKeys};
use crate::clock::Clock;
use crate::error::{CryptoError, Rejected, SealError};
use crate::handshake::{Handshake, LinkBinding, Role, Session};
use crate::identity::{Nickname, SessionIdentity, SessionKey};
use crate::invite::ChannelInvite;
use crate::message::{self, ChannelSlot, Opened, RecordType};
use crate::rng::Rng;
use crate::roster::Roster;
use crate::tag::{epoch_of, TagMatcher, MAX_TAG_CANDIDATES};

/// One node's crypto state.
pub struct CryptoState<R: Rng, C: Clock> {
    rng: R,
    clock: C,
    identity: Option<SessionIdentity>,
    channels: HashMap<ChannelId, ChannelSlot>,
    matcher: TagMatcher,
    roster: Roster,
}

impl<R: Rng, C: Clock> core::fmt::Debug for CryptoState<R, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CryptoState")
            .field("identity", &self.identity)
            .field("channels", &self.channels.len())
            .field("roster", &self.roster.len())
            .finish()
    }
}

impl<R: Rng, C: Clock> CryptoState<R, C> {
    /// Start a session.
    pub fn new(mut rng: R, clock: C, nick: &str) -> Result<Self, CryptoError> {
        let nick = Nickname::new(nick)?;
        let identity = SessionIdentity::new(&mut rng, nick);
        Ok(CryptoState {
            rng,
            clock,
            identity: Some(identity),
            channels: HashMap::new(),
            matcher: TagMatcher::new(),
            roster: Roster::new(),
        })
    }

    /// Current wall-clock seconds, from the injected clock.
    pub fn now(&self) -> u64 {
        self.clock.unix_secs()
    }

    /// Current tag epoch.
    pub fn epoch(&self) -> u64 {
        epoch_of(self.now())
    }

    /// The session identity, if the state has not been wiped.
    pub fn identity(&self) -> Option<&SessionIdentity> {
        self.identity.as_ref()
    }

    /// This session's key.
    pub fn session_key(&self) -> Option<SessionKey> {
        self.identity.as_ref().map(|i| i.session_key())
    }

    /// The roster.
    pub fn roster(&self) -> &Roster {
        &self.roster
    }

    /// The roster, mutably, so a UI can promote an entry after confirming a SAS.
    pub fn roster_mut(&mut self) -> &mut Roster {
        &mut self.roster
    }

    /// End this session and start a new one under a fresh keypair.
    pub fn new_identity(&mut self, nick: &str) -> Result<(), CryptoError> {
        let nick = Nickname::new(nick)?;
        if let Some(id) = self.identity.as_mut() {
            id.wipe();
        }
        self.identity = None;
        for slot in self.channels.values_mut() {
            slot.reset_session_state();
        }
        self.roster.clear();
        self.identity = Some(SessionIdentity::new(&mut self.rng, nick));
        self.tick();
        Ok(())
    }

    /// Zeroize every secret in place without dropping anything.
    ///
    /// Exists so the wipe test can read the bytes back and prove they are zero,
    /// rather than proving only that a value went out of scope.
    pub fn wipe_secrets_in_place(&mut self) {
        if let Some(id) = self.identity.as_mut() {
            id.wipe();
        }
        for slot in self.channels.values_mut() {
            slot.keys.wipe();
        }
    }

    /// Destroy everything. Nothing survives: no identity, no channel, no tag,
    /// no roster row, no counter.
    pub fn panic_wipe(&mut self) {
        self.wipe_secrets_in_place();
        self.identity = None;
        self.channels.clear();
        self.matcher.clear();
        self.roster.clear();
    }

    /// Mint a channel locally and return its invite for display as a QR.
    pub fn create_channel(
        &mut self,
        lifetime_hours: u16,
    ) -> Result<(ChannelId, ChannelInvite), CryptoError> {
        let epoch = self.epoch();
        let invite = ChannelInvite::generate(&mut self.rng, epoch, lifetime_hours);
        let id = invite.channel_id();
        let keys = ChannelKeys::install(ChannelInvite::decode(&invite.encode()[..])
            .map_err(|_| CryptoError::Handshake)?, epoch)?;
        self.channels.insert(id, ChannelSlot::new(keys));
        self.tick();
        Ok((id, invite))
    }

    /// Install a channel from a scanned invite. The invite is consumed.
    pub fn join_channel(&mut self, invite: ChannelInvite) -> Result<ChannelId, CryptoError> {
        let epoch = self.epoch();
        let keys = ChannelKeys::install(invite, epoch)?;
        let id = keys.id();
        self.channels.insert(id, ChannelSlot::new(keys));
        self.tick();
        Ok(id)
    }

    /// Every installed channel.
    pub fn channel_ids(&self) -> Vec<ChannelId> {
        let mut v: Vec<ChannelId> = self.channels.keys().copied().collect();
        v.sort();
        v
    }

    /// A channel's keys, for building a handshake.
    pub fn channel_keys(&self, id: ChannelId) -> Option<&ChannelKeys> {
        self.channels.get(&id).map(|s| &s.keys)
    }

    /// The channel's current tag.
    pub fn channel_tag(&self, id: ChannelId) -> Option<ChanTag> {
        let epoch = self.epoch();
        self.channels.get(&id).map(|s| s.keys.tag_for(epoch))
    }

    /// Whether any channel this device holds matches `tag`, for the three live
    /// epochs. This is all a relay is told.
    pub fn holds_tag(&self, tag: &ChanTag) -> bool {
        self.matcher.holds(tag)
    }

    /// The tag matcher, for a relay that wants to inspect candidates.
    pub fn matcher(&self) -> &TagMatcher {
        &self.matcher
    }

    /// The tag matcher, mutably, so a collision can be engineered in a test.
    pub fn matcher_mut(&mut self) -> &mut TagMatcher {
        &mut self.matcher
    }

    /// Roll channels and the tag table forward to the current epoch.
    pub fn tick(&mut self) {
        let epoch = self.epoch();
        let mut dead = Vec::new();
        for (id, slot) in self.channels.iter_mut() {
            if slot.keys.advance_to(epoch).is_err() {
                dead.push(*id);
            } else {
                slot.prune(epoch);
            }
        }
        for id in dead {
            if let Some(mut slot) = self.channels.remove(&id) {
                slot.keys.wipe();
            }
        }
        self.matcher
            .refresh(self.channels.values().map(|s| &s.keys), epoch);
    }

    /// Seal a record for a channel.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        &mut self,
        channel: ChannelId,
        kind: Kind,
        flags: Flags,
        ttl: u8,
        rtype: RecordType,
        payload: &[u8],
    ) -> Result<Frame, SealError> {
        self.tick();
        let epoch = epoch_of(self.clock.unix_secs());
        let CryptoState {
            rng,
            identity,
            channels,
            ..
        } = self;
        let identity = identity.as_ref().ok_or(SealError::NoIdentity)?;
        let slot = channels
            .get_mut(&channel)
            .ok_or(SealError::UnknownChannel)?;
        message::seal(slot, identity, epoch, kind, flags, ttl, rtype, payload, rng)
    }

    /// Seal a presence beacon carrying this session's nickname.
    pub fn seal_presence(&mut self, channel: ChannelId, ttl: u8) -> Result<Frame, SealError> {
        let nick = self
            .identity
            .as_ref()
            .ok_or(SealError::NoIdentity)?
            .nickname();
        let payload = nick.as_bytes().to_vec();
        self.seal(
            channel,
            Kind::Presence,
            Flags::empty(),
            ttl,
            RecordType::Presence,
            &payload,
        )
    }

    /// Open a frame, or reject it.
    ///
    /// Always performs exactly [`MAX_TAG_CANDIDATES`] open attempts, each
    /// costing one AEAD decryption and one Ed25519 verification, whatever the
    /// frame is and whatever state this node is in. An unknown tag, a Poly1305
    /// mismatch, a bad signature and a replayed counter are therefore the same
    /// amount of work and the same [`Rejected`] value.
    pub fn open(&mut self, frame: &Frame) -> Result<Opened, Rejected> {
        let now = self.clock.unix_secs();
        let epoch = epoch_of(now);
        let cands: Vec<(ChannelId, u64)> = self.matcher.candidates(&frame.hdr.tag).to_vec();
        let mut found: Option<Opened> = None;
        for i in 0..MAX_TAG_CANDIDATES {
            let got = match cands.get(i).copied() {
                Some((id, e)) => {
                    let slot = self.channels.get_mut(&id);
                    message::try_open(slot, e, &frame.hdr, frame.body())
                }
                None => message::try_open(None, epoch, &frame.hdr, frame.body()),
            };
            if found.is_none() {
                found = got;
            }
        }
        let opened = found.ok_or(Rejected)?;
        let nick = if opened.record.rtype == RecordType::Presence {
            Nickname::from_wire(&opened.record.payload).ok()
        } else {
            None
        };
        self.roster
            .observe(opened.channel, opened.sender, nick, now);
        Ok(opened)
    }

    /// What a relay must run before forwarding, for any frame, including one
    /// for a channel it does not hold.
    ///
    /// Rule 4 is "never relay unparsed bytes". This re-decodes the frame from
    /// its canonical encoding and refuses anything that does not round-trip
    /// exactly, so a frame with trailing bytes, a bad bucket, a reserved byte in
    /// use or an inflated TTL is dropped rather than amplified. The work is
    /// bounded by one bucket-sized copy; there is no expansion step anywhere in
    /// this crate, which is why no decompression bomb is reachable.
    pub fn relay_check(frame: &Frame) -> Result<(), Rejected> {
        let bytes = frame.encode();
        if bytes.len() > gdc_wire::HEADER_LEN + *gdc_wire::BUCKETS.last().unwrap() as usize {
            return Err(Rejected);
        }
        let back = Frame::decode(&bytes).map_err(|_| Rejected)?;
        if back != *frame || !frame.hdr.kind.is_relayable() {
            return Err(Rejected);
        }
        Ok(())
    }

    /// Begin a join as the initiator, over a direct link.
    pub fn begin_join(
        &mut self,
        channel: ChannelId,
        link: &LinkBinding,
    ) -> Result<Handshake, CryptoError> {
        let epoch = self.epoch();
        let identity = self.identity.as_ref().ok_or(CryptoError::UnknownChannel)?;
        let keys = self
            .channels
            .get(&channel)
            .map(|s| &s.keys)
            .ok_or(CryptoError::UnknownChannel)?;
        Handshake::new(Role::Initiator, identity, keys, link, epoch)
    }

    /// Begin a join as the responder, resolving the channel from the frame's tag.
    pub fn accept_join(
        &mut self,
        frame: &Frame,
        link: &LinkBinding,
    ) -> Result<Handshake, CryptoError> {
        if frame.hdr.kind != Kind::Handshake || frame.hdr.ttl != 1 {
            return Err(CryptoError::HandshakeNotDirect);
        }
        let epoch = self.epoch();
        let cands: Vec<(ChannelId, u64)> = self.matcher.candidates(&frame.hdr.tag).to_vec();
        let identity = self.identity.as_ref().ok_or(CryptoError::UnknownChannel)?;
        for (id, _) in cands {
            let Some(keys) = self.channels.get(&id).map(|s| &s.keys) else {
                continue;
            };
            let mut hs = Handshake::new(Role::Responder, identity, keys, link, epoch)?;
            if hs.read_frame(frame).is_ok() {
                return Ok(hs);
            }
        }
        Err(CryptoError::Handshake)
    }

    /// Record a confirmed session in the roster.
    pub fn confirm_session(&mut self, session: &Session) -> bool {
        self.roster.mark_verified(session)
    }
}

impl<R: Rng, C: Clock> SecretAudit for CryptoState<R, C> {
    fn audit(&self) -> Audit {
        let mut a = self
            .identity
            .as_ref()
            .map(|i| i.audit())
            .unwrap_or_default();
        for slot in self.channels.values() {
            a = a.plus(slot.keys.audit());
        }
        a
    }
}
