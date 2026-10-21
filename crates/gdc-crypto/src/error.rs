//! Error types.
//!
//! Note the asymmetry, which is deliberate. Anything on the *send* side may
//! report a detailed reason, because the only consumer is our own UI. Anything
//! on the *receive* side collapses to [`Rejected`], which carries no
//! information at all, because a receive-side error code is an oracle. Bridgefy
//! lost one-to-one plaintext to exactly that: delivery receipts distinguished a
//! padding failure from a MAC failure.

use thiserror::Error;

/// Every receive-path failure, from every cause, is this value.
///
/// It has no variants and no payload on purpose: an unknown channel tag, a
/// Poly1305 mismatch, a bad signature, a replayed counter, a counter too far
/// ahead, a malformed record and an expired channel are indistinguishable to the
/// caller, and the caller has no way to accidentally forward the distinction to
/// the network.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
#[error("rejected")]
pub struct Rejected;

/// Send-path failures. Local, never derived from remote input.
#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum SealError {
    /// Payload exceeds [`gdc_wire::MAX_BODY_LEN`].
    #[error("payload too large")]
    PayloadTooLarge,
    /// The payload cannot fit any bucket in the ladder once framed.
    #[error("payload does not fit the bucket ladder")]
    NoBucket,
    /// No such channel is installed.
    #[error("unknown channel")]
    UnknownChannel,
    /// The channel's validity window has passed; its keys are gone.
    #[error("channel expired")]
    ChannelExpired,
    /// No session identity; the state has been wiped.
    #[error("no session identity")]
    NoIdentity,
    /// 65 536 messages from one sender in one epoch. Wait for the next epoch.
    #[error("send counter exhausted for this epoch")]
    CounterExhausted,
    /// A wire-level constraint rejected the frame.
    #[error("wire: {0}")]
    Wire(gdc_wire::WireError),
}

impl From<gdc_wire::WireError> for SealError {
    fn from(e: gdc_wire::WireError) -> Self {
        SealError::Wire(e)
    }
}

/// Setup and handshake failures. These are local or direct-link only, never
/// reached by a relayed frame, so they may be specific.
#[derive(Clone, PartialEq, Eq, Debug, Error)]
pub enum CryptoError {
    /// An expansion step hit [`gdc_wire::MAX_EXPANDED_LEN`].
    #[error("expansion ceiling")]
    ExpansionCeiling,
    /// The nickname was empty, too long, or contained control characters.
    #[error("invalid nickname")]
    BadNickname,
    /// Handshake could not be built or advanced.
    #[error("handshake failed")]
    Handshake,
    /// A handshake frame arrived that could not have come over a direct link.
    #[error("handshake frame was not direct")]
    HandshakeNotDirect,
    /// Handshake step called out of order.
    #[error("handshake out of order")]
    HandshakeOrder,
    /// The peer's advertised identity key was not a valid point.
    #[error("bad peer identity")]
    BadPeerIdentity,
    /// No such channel is installed.
    #[error("unknown channel")]
    UnknownChannel,
    /// The channel's validity window has passed.
    #[error("channel expired")]
    ChannelExpired,
    /// Link binding longer than [`crate::LinkBinding::MAX_LEN`].
    #[error("link binding too long")]
    LinkBindingTooLong,
}
