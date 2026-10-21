//! Channel keys, ephemeral session identity, rotating channel tags, the join
//! handshake, and AEAD message protection for GridDown.
//!
//! Everything here exists to hold the floor set by Part 3 of
//! `docs/research/BRIDGEFY-FINDINGS.md`. The expensive privacy properties are
//! deliberately *not* bought: there is no cover traffic, no timing
//! unlinkability, no sender anonymity against a local radio observer. The cheap
//! ones are bought in full, because shipping them broken is the one failure mode
//! that would make this project a re-run of the Bridgefy papers.
//!
//! # The ordering rule
//!
//! This crate contains **no compression**, and that is a decision rather than an
//! omission.
//!
//! The 2022 paper recovered Bridgefy's broadcast plaintext because gzip ran
//! *before* encryption, so ciphertext length was a function of plaintext
//! content, and maximum-likelihood estimation over lengths observed across
//! several hops did the rest — without the network key. The rule that kills it
//! is "encrypt before compress, or compress inside the AEAD".
//!
//! We could obey that rule and still compress: deflate the record, then seal it.
//! We do not, for four reasons.
//!
//! 1. It would not actually be free of the leak. The bucket a frame lands in is
//!    chosen from the sealed length. If that length depended on compressibility,
//!    bucket choice would become a (coarse, ~2.3-bit) function of plaintext
//!    content, and the attack in the paper is precisely an aggregation of a
//!    coarse per-hop length signal. Choosing the bucket from the *plaintext*
//!    length is what makes the leak zero rather than small.
//! 2. There is nothing to win. The payload ceiling is
//!    [`gdc_wire::MAX_BODY_LEN`] = 500 bytes of short text. Deflate on inputs
//!    that size saves little and expands inputs under about 64 bytes, and the
//!    frame is padded to a fixed bucket afterwards regardless, so in the common
//!    case a saved byte buys literally nothing on the wire.
//! 3. A decompressor is the D-1 attack surface. Bridgefy's ~10 KB
//!    decompression bomb froze every receiving client and, because forwarding
//!    happened before parsing, took out the network. The cheapest way to have no
//!    decompression bomb is to have no decompressor.
//! 4. The padding that fills a bucket lives *inside* the AEAD (see
//!    [`message`]), so there is no length field, no padding check and therefore
//!    no padding oracle. Adding a compressor would add a second variable-length
//!    stage inside that envelope for no benefit.
//!
//! If a future payload type ever needs an expansion step, [`expand_bounded`] is
//! the only permitted primitive and [`gdc_wire::MAX_EXPANDED_LEN`] is the only
//! ceiling. A test asserts that the message path never calls it.
//!
//! # Determinism
//!
//! Randomness and time are injected ([`Rng`], [`Clock`]). Nothing in this crate
//! reads the ambient clock or the ambient CSPRNG on its own initiative, so every
//! behaviour a test cares about can be pinned.

#![forbid(unsafe_code)]

mod audit;
mod channel;
mod clock;
mod error;
mod handshake;
mod identity;
mod invite;
mod kdf;
mod message;
mod rng;
mod roster;
mod state;
mod tag;

pub use audit::{Audit, SecretAudit};
pub use channel::{ChannelId, ChannelKeys};
pub use clock::{Clock, FixedClock, SystemClock};
pub use error::{CryptoError, Rejected, SealError};
pub use handshake::{Handshake, LinkBinding, Role, Sas, Session};
pub use identity::{Nickname, SessionIdentity, SessionKey};
pub use invite::{ChannelInvite, InviteError, AUTH_MODE_SIGNED, INVITE_LEN, INVITE_TEXT_LEN};
pub use message::{Opened, Record, RecordType, max_payload, smallest_bucket_for, BODY_OVERHEAD,
    MAX_COUNTER_JUMP, MAX_SENDERS_PER_EPOCH, MAX_SKIPPED_KEYS, WIRE_OVERHEAD};
pub use rng::{OsRng, Rng, TestRng};
pub use roster::{Roster, RosterEntry, Verification, MAX_ROSTER};
pub use state::CryptoState;
pub use tag::{epoch_of, tag_for_epoch, TagMatcher, MAX_TAG_CANDIDATES};

/// The only permitted expansion primitive in the stack.
///
/// There is no compressor in this crate, so nothing calls this on the message
/// path. It exists so that if anything ever does, the ceiling is one constant in
/// one place, enforced *before* the output buffer is sized, and a fuzz target can
/// point at it. An attacker-supplied declared length never sizes an allocation:
/// `declared` is checked first, and the buffer is grown to whatever the step
/// actually produces.
pub fn expand_bounded(
    declared: usize,
    mut step: impl FnMut(&mut Vec<u8>) -> Result<(), CryptoError>,
) -> Result<Vec<u8>, CryptoError> {
    if declared > gdc_wire::MAX_EXPANDED_LEN {
        return Err(CryptoError::ExpansionCeiling);
    }
    let mut out = Vec::new();
    step(&mut out)?;
    if out.len() > gdc_wire::MAX_EXPANDED_LEN {
        // Belt and braces: a step that lies about its output is still bounded.
        out.clear();
        out.shrink_to_fit();
        return Err(CryptoError::ExpansionCeiling);
    }
    Ok(out)
}
