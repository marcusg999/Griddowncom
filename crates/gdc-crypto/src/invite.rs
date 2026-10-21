//! The QR payload: how a channel is handed to another human.
//!
//! # Format
//!
//! Fixed length, 44 bytes, little in it that a future version cannot replace:
//!
//! | off | len | field            | why it is here                              |
//! |-----|-----|------------------|---------------------------------------------|
//! |   0 |   1 | `ver`            | hard version gate; v1 only                  |
//! |   1 |   1 | `auth`           | channel authentication mode; only `0x00`    |
//! |   2 |  32 | `root`           | the channel root secret, and the whole      |
//! |     |     |                  | reason the QR has to be shown in person     |
//! |  34 |   4 | `created_epoch`  | tag epoch the channel was created in        |
//! |  38 |   2 | `lifetime_hours` | validity window; keys self-destruct after   |
//! |  40 |   4 | `check`          | HMAC over bytes 0..40 keyed by `root`       |
//!
//! There is no channel name and no creator name. A label is local to each
//! device, because a name in the QR would be a name on a sticker on a lamp post.
//!
//! `created_epoch` and `lifetime_hours` are what makes the message-root ratchet
//! deterministic for a late joiner, and what lets a device throw the keys away
//! on its own without being told to.
//!
//! `check` is a 4-byte HMAC under the root itself. It cannot prove the invite
//! came from anyone, and it is not meant to: it catches a field-shifted,
//! truncated or wrong-type payload *before* any key material is installed, so a
//! mis-scan is a clean refusal instead of a channel nobody else is in.
//!
//! # Text form
//!
//! 71 characters of unpadded uppercase RFC 4648 base32, prefixed `GDC1:`, for a
//! 76-character string. Uppercase base32 plus `:` is entirely inside the QR
//! alphanumeric character set, so the code encodes in alphanumeric mode rather
//! than byte mode and fits a 29x29 (version 3) symbol at error-correction level
//! M, whose alphanumeric capacity is 77. That matters in a product whose whole
//! onboarding story is "point the camera at the other phone".

use zeroize::Zeroizing;

use crate::kdf::{derive, mac, L_CHAN_ID, L_INVITE_CHECK};
use crate::rng::Rng;

/// Binary invite length in bytes.
pub const INVITE_LEN: usize = 44;
/// Text invite length in characters, including the `GDC1:` prefix.
pub const INVITE_TEXT_LEN: usize = 5 + 71;
/// The only channel authentication mode in v1: every record carries an Ed25519
/// signature by the sender's session key.
pub const AUTH_MODE_SIGNED: u8 = 0x00;

const INVITE_VERSION: u8 = 1;
const PREFIX: &str = "GDC1:";
const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const B32_CHARS: usize = 71;

/// Why an invite was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum InviteError {
    /// Not [`INVITE_LEN`] bytes, or not [`INVITE_TEXT_LEN`] characters.
    #[error("invite has the wrong length")]
    BadLength,
    /// Unsupported version byte.
    #[error("unsupported invite version")]
    BadVersion,
    /// Unsupported authentication mode.
    #[error("unsupported channel authentication mode")]
    BadAuthMode,
    /// A character outside the base32 alphabet, or a non-canonical tail.
    #[error("invite is not valid base32")]
    BadAlphabet,
    /// Missing or wrong `GDC1:` prefix.
    #[error("invite has the wrong prefix")]
    BadPrefix,
    /// The integrity check failed. The scan was corrupt; no keys were touched.
    #[error("invite failed its integrity check")]
    BadCheck,
    /// `lifetime_hours` was zero.
    #[error("invite has a zero lifetime")]
    ZeroLifetime,
}

/// A channel root plus the metadata a joiner needs, as carried by a QR code.
///
/// Holds secret material, so it is not `Clone` and its `Debug` is redacted. It
/// is consumed by value when a channel is installed, which is what guarantees
/// the root does not outlive the install.
pub struct ChannelInvite {
    root: Zeroizing<[u8; 32]>,
    created_epoch: u32,
    lifetime_hours: u16,
}

impl core::fmt::Debug for ChannelInvite {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChannelInvite")
            .field("root", &"<redacted>")
            .field("created_epoch", &self.created_epoch)
            .field("lifetime_hours", &self.lifetime_hours)
            .finish()
    }
}

impl ChannelInvite {
    /// Mint a new channel. The root never comes from anywhere but the CSPRNG,
    /// and never from anything compiled into the binary.
    pub fn generate(rng: &mut impl Rng, created_epoch: u64, lifetime_hours: u16) -> Self {
        let mut root = Zeroizing::new([0u8; 32]);
        rng.fill(&mut root[..]);
        ChannelInvite {
            root,
            created_epoch: created_epoch.min(u32::MAX as u64) as u32,
            lifetime_hours: lifetime_hours.max(1),
        }
    }

    /// The channel root. Crate-internal: nothing outside this crate is allowed
    /// to hold it, so there is no path by which it reaches a log or a frame.
    pub(crate) fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Tag epoch in which this channel was created.
    pub fn created_epoch(&self) -> u64 {
        self.created_epoch as u64
    }

    /// How many tag epochs the channel is valid for.
    pub fn lifetime_hours(&self) -> u16 {
        self.lifetime_hours
    }

    /// The local handle for this channel. Derived, never transmitted.
    pub fn channel_id(&self) -> crate::ChannelId {
        crate::ChannelId(*derive::<8>(&self.root[..], L_CHAN_ID))
    }

    fn body(&self) -> Zeroizing<[u8; INVITE_LEN]> {
        let mut out = Zeroizing::new([0u8; INVITE_LEN]);
        out[0] = INVITE_VERSION;
        out[1] = AUTH_MODE_SIGNED;
        out[2..34].copy_from_slice(&self.root[..]);
        out[34..38].copy_from_slice(&self.created_epoch.to_be_bytes());
        out[38..40].copy_from_slice(&self.lifetime_hours.to_be_bytes());
        let check = mac::<4>(&self.root, L_INVITE_CHECK, &out[..40]);
        out[40..44].copy_from_slice(&check);
        out
    }

    /// Encode to the 44-byte binary form.
    pub fn encode(&self) -> Zeroizing<[u8; INVITE_LEN]> {
        self.body()
    }

    /// Decode the 44-byte binary form.
    ///
    /// Every field is bounded by a constant and the length is checked first, so
    /// nothing here is sized by the input.
    pub fn decode(src: &[u8]) -> Result<Self, InviteError> {
        if src.len() != INVITE_LEN {
            return Err(InviteError::BadLength);
        }
        if src[0] != INVITE_VERSION {
            return Err(InviteError::BadVersion);
        }
        if src[1] != AUTH_MODE_SIGNED {
            return Err(InviteError::BadAuthMode);
        }
        let mut root = Zeroizing::new([0u8; 32]);
        root.copy_from_slice(&src[2..34]);
        let want = mac::<4>(&root, L_INVITE_CHECK, &src[..40]);
        // Not a secret comparison (the key is in the payload), but constant
        // time anyway: there is no reason for any comparison in this crate to
        // be the one that is not.
        if !bool::from(subtle::ConstantTimeEq::ct_eq(&want[..], &src[40..44])) {
            return Err(InviteError::BadCheck);
        }
        let mut e = [0u8; 4];
        e.copy_from_slice(&src[34..38]);
        let mut l = [0u8; 2];
        l.copy_from_slice(&src[38..40]);
        let lifetime_hours = u16::from_be_bytes(l);
        if lifetime_hours == 0 {
            return Err(InviteError::ZeroLifetime);
        }
        Ok(ChannelInvite {
            root,
            created_epoch: u32::from_be_bytes(e),
            lifetime_hours,
        })
    }

    /// Encode to the 76-character text form that goes into the QR.
    pub fn to_text(&self) -> Zeroizing<String> {
        let bin = self.body();
        let mut s = String::with_capacity(INVITE_TEXT_LEN);
        s.push_str(PREFIX);
        b32_encode(&bin[..], &mut s);
        Zeroizing::new(s)
    }

    /// Decode the text form produced by [`ChannelInvite::to_text`].
    pub fn from_text(s: &str) -> Result<Self, InviteError> {
        if s.len() != INVITE_TEXT_LEN {
            return Err(InviteError::BadLength);
        }
        let Some(rest) = s.strip_prefix(PREFIX) else {
            return Err(InviteError::BadPrefix);
        };
        let bin = b32_decode(rest)?;
        ChannelInvite::decode(&bin[..])
    }
}

fn b32_encode(src: &[u8], out: &mut String) {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in src {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32[((acc << (5 - bits)) & 31) as usize] as char);
    }
}

/// Decode exactly [`B32_CHARS`] base32 characters into [`INVITE_LEN`] bytes.
///
/// The output buffer is sized by a constant, never by the input, and a
/// non-canonical tail (stray bits in the final character) is refused rather
/// than silently accepted, so one invite has exactly one encoding.
fn b32_decode(s: &str) -> Result<Zeroizing<[u8; INVITE_LEN]>, InviteError> {
    if s.len() != B32_CHARS {
        return Err(InviteError::BadLength);
    }
    let mut out = Zeroizing::new([0u8; INVITE_LEN]);
    let mut n = 0usize;
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for c in s.bytes() {
        let v = match B32.iter().position(|&x| x == c) {
            Some(v) => v as u32,
            None => return Err(InviteError::BadAlphabet),
        };
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            if n >= INVITE_LEN {
                return Err(InviteError::BadLength);
            }
            out[n] = ((acc >> bits) & 0xff) as u8;
            n += 1;
        }
    }
    if n != INVITE_LEN || (acc & ((1u32 << bits) - 1)) != 0 {
        return Err(InviteError::BadAlphabet);
    }
    Ok(out)
}
