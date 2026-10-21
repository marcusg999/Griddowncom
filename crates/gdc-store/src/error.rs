//! Refusals.
//!
//! Nothing in this crate panics on anything that could have arrived over a
//! radio. Every rejection is a value, every rejection says which ceiling it
//! hit, and the set is closed so that a caller can match exhaustively.

use gdc_wire::WireError;

/// Why an offered envelope was not taken into the courier store.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum Refused {
    /// We have seen this message id before. The cheapest and most common path.
    #[error("duplicate message id")]
    Duplicate,
    /// This source class has spent its admission tokens.
    #[error("source class is over its admission rate")]
    RateLimited,
    /// The store is full and this envelope's class is not entitled to displace
    /// anyone. See [`crate::courier`] for the fairness rule.
    #[error("store full and class is already at or above its fair share")]
    ClassAtShare,
    /// The frame kind cannot be carried as courier mail.
    #[error("frame kind is not carryable")]
    NotCarryable,
    /// The frame is dead on arrival.
    #[error("frame has no hops left")]
    Exhausted,
    /// The offered envelope claims a copy budget larger than the ceiling.
    #[error("copy budget exceeds the ceiling")]
    BudgetTooLarge,
    /// The frame's bucket is larger than anything we will carry.
    #[error("frame too large to carry")]
    TooLarge,
}

/// Why a message could not be put in the author's outbox.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum OutboxFull {
    #[error("outbox already holds the maximum number of messages")]
    Messages,
    #[error("outbox already holds the maximum number of bytes")]
    Bytes,
    #[error("message id is already queued")]
    Duplicate,
}

/// Failures parsing or applying a reconciliation digest.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum ReconError {
    #[error("digest is truncated: need {need} bytes, got {got}")]
    Truncated { need: usize, got: usize },
    #[error("digest declares {0} items, over the ceiling")]
    TooManyItems(usize),
    #[error("digest is {0} bytes, over the ceiling")]
    TooLarge(usize),
    #[error("unsupported digest scheme {0}")]
    BadScheme(u8),
    #[error("golomb parameter {0} is out of range")]
    BadParam(u8),
    #[error("digest body is malformed")]
    Malformed,
}

/// Errors at the store's own boundary.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum StoreError {
    #[error("wire: {0}")]
    Wire(#[from] WireError),
    #[error("no key for any channel matching this tag")]
    UnknownTag,
    #[error("channel table is full")]
    ChannelTableFull,
    #[error("no such message in the outbox")]
    NoSuchMessage,
}
