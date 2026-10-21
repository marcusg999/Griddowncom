//! Ephemeral session identity.
//!
//! A session runs from launch until an explicit new-identity or a panic wipe.
//! There is no account, nothing is written to disk by this crate, and two
//! sessions on the same handset share no key material, so they are unlinkable
//! by anything on the wire.
//!
//! One 32-byte seed produces two keys, by label:
//!
//! * an **X25519 static** used only as the Noise static for the join handshake;
//! * an **Ed25519 key** used only to sign records, and which *is* the session's
//!   identity as far as the roster and every message are concerned.
//!
//! Two keys rather than one because the X25519 key has to be a Diffie-Hellman
//! key for Noise and the signing key has to be a signature key for records, and
//! reusing one key for both roles means either a non-standard construction
//! (XEdDSA) or hand-rolled curve conversion. The two are bound together by the
//! handshake: the Ed25519 public key travels in the Noise handshake payload, so
//! it is mixed into the handshake hash and therefore covered by the short
//! authentication string the two humans compare.
//!
//! A nickname binds to [`SessionKey`], not to a person. Nothing authenticates a
//! nickname and nothing is supposed to; it is a label on a key, the key is what
//! is authenticated, and the roster says which keys a human has actually
//! confirmed.

use ed25519_dalek::{Signer, SigningKey};
use zeroize::{Zeroize, Zeroizing};

use crate::audit::{Audit, SecretAudit};
use crate::error::CryptoError;
use crate::kdf::{derive, L_SESSION_ED, L_SESSION_X};
use crate::rng::Rng;

/// Longest nickname, in bytes of UTF-8.
///
/// Eleven, not a rounder number, because a presence beacon is
/// `[`crate::BODY_OVERHEAD`] + nickname` bytes of body and 11 is the largest
/// value that still lands a beacon in the 128-byte bucket. A 12-byte nickname
/// would double the airtime of the most frequent frame in the system.
pub const MAX_NICK_LEN: usize = 11;

/// The identity of a session: its Ed25519 public key.
///
/// Every record is signed under this key, and the roster, the replay windows
/// and every other piece of per-peer state in this crate are keyed on it. They
/// are keyed on it *after* a signature has verified under it, never on a
/// claimed id and never on a link address — which is the whole of rule 10.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionKey(pub [u8; 32]);

impl core::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SessionKey({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

/// A short display label bound to a [`SessionKey`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Nickname {
    bytes: [u8; MAX_NICK_LEN],
    len: u8,
}

impl Nickname {
    /// Validate and store a nickname.
    ///
    /// Refuses empty, over-long, and anything containing a control character,
    /// so a nickname cannot carry an escape sequence into a terminal or a
    /// zero-width run into a roster row.
    pub fn new(s: &str) -> Result<Self, CryptoError> {
        let b = s.as_bytes();
        if b.is_empty() || b.len() > MAX_NICK_LEN {
            return Err(CryptoError::BadNickname);
        }
        if s.chars().any(|c| c.is_control()) {
            return Err(CryptoError::BadNickname);
        }
        let mut bytes = [0u8; MAX_NICK_LEN];
        bytes[..b.len()].copy_from_slice(b);
        Ok(Nickname {
            bytes,
            len: b.len() as u8,
        })
    }

    /// Validate a nickname arriving from the wire.
    pub(crate) fn from_wire(b: &[u8]) -> Result<Self, CryptoError> {
        let s = core::str::from_utf8(b).map_err(|_| CryptoError::BadNickname)?;
        Nickname::new(s)
    }

    /// The nickname's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// The nickname as a string.
    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("?")
    }
}

impl core::fmt::Debug for Nickname {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self.as_str())
    }
}

/// An X25519 + Ed25519 keypair for one session, plus its nickname.
///
/// Deliberately not `Clone`: a secret with two owners is a secret with two
/// chances of surviving a wipe.
pub struct SessionIdentity {
    seed: Zeroizing<[u8; 32]>,
    x_secret: Zeroizing<[u8; 32]>,
    x_public: [u8; 32],
    ed_secret: Zeroizing<[u8; 32]>,
    ed_public: [u8; 32],
    nick: Nickname,
}

impl core::fmt::Debug for SessionIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SessionIdentity")
            .field("session_key", &SessionKey(self.ed_public))
            .field("nick", &self.nick)
            .field("secrets", &"<redacted>")
            .finish()
    }
}

impl SessionIdentity {
    /// Generate a session identity from injected randomness.
    pub fn new(rng: &mut impl Rng, nick: Nickname) -> Self {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill(&mut seed[..]);
        Self::from_seed(seed, nick)
    }

    fn from_seed(seed: Zeroizing<[u8; 32]>, nick: Nickname) -> Self {
        let x_secret = derive::<32>(&seed[..], L_SESSION_X);
        let x_public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*x_secret))
            .to_bytes();
        let ed_secret = derive::<32>(&seed[..], L_SESSION_ED);
        let ed_public = SigningKey::from_bytes(&ed_secret).verifying_key().to_bytes();
        SessionIdentity {
            seed,
            x_secret,
            x_public,
            ed_secret,
            ed_public,
            nick,
        }
    }

    /// This session's identity key.
    pub fn session_key(&self) -> SessionKey {
        SessionKey(self.ed_public)
    }

    /// This session's Noise static public key.
    pub fn handshake_public(&self) -> [u8; 32] {
        self.x_public
    }

    pub(crate) fn handshake_secret(&self) -> &[u8; 32] {
        &self.x_secret
    }

    /// The nickname bound to this session key.
    pub fn nickname(&self) -> Nickname {
        self.nick
    }

    /// Rebind the nickname. The key does not change, so the roster entry does
    /// not change identity — only its label.
    pub fn set_nickname(&mut self, nick: Nickname) {
        self.nick = nick;
    }

    /// Sign `msg` in `domain`.
    pub(crate) fn sign(&self, domain: &[u8], msg: &[u8]) -> [u8; 64] {
        let sk = SigningKey::from_bytes(&self.ed_secret);
        let mut buf = Vec::with_capacity(domain.len() + 1 + msg.len());
        buf.extend_from_slice(domain);
        buf.push(0x00);
        buf.extend_from_slice(msg);
        sk.sign(&buf).to_bytes()
    }

    /// Zeroize every secret in place, leaving the public parts and the structure
    /// so a test can assert on the bytes.
    pub fn wipe(&mut self) {
        self.seed.zeroize();
        self.x_secret.zeroize();
        self.ed_secret.zeroize();
    }
}

impl SecretAudit for SessionIdentity {
    fn audit(&self) -> Audit {
        Audit::of(&[&self.seed[..], &self.x_secret[..], &self.ed_secret[..]])
    }
}

/// Verify a detached record signature.
pub(crate) fn verify(key: &[u8; 32], domain: &[u8], msg: &[u8], sig: &[u8; 64]) -> bool {
    use ed25519_dalek::Verifier;
    let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(key) else {
        return false;
    };
    let mut buf = Vec::with_capacity(domain.len() + 1 + msg.len());
    buf.extend_from_slice(domain);
    buf.push(0x00);
    buf.extend_from_slice(msg);
    vk.verify(&buf, &ed25519_dalek::Signature::from_bytes(sig))
        .is_ok()
}
