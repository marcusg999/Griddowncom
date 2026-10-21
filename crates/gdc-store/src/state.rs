//! Honest delivery state.
//!
//! `docs/METRICS.md` grades the message screen on whether a first-time user can
//! state correctly, unprompted, whether their message has actually been
//! delivered. That is a storage problem before it is a UI problem: the screen
//! can only tell the truth if this crate distinguishes the cases and refuses to
//! collapse them.
//!
//! Five states, and the transitions between them are one-way. There is no path
//! from any delivered state back to queued, and no path from expired to
//! delivered, so a stale receipt arriving late cannot rewrite history into
//! something more flattering.
//!
//! What is deliberately *not* here: "delivered to Bob". Addressing is
//! channel-first and identity is ephemeral, so the honest claim is that at
//! least one member of the channel has the message. Claiming a person would be
//! a lie we are not in a position to check.

use crate::types::Millis;

/// Why a message never arrived. The UI needs the distinction: the first is bad
/// luck, the second is a fact about the recipient, the third is our fault.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UndeliveredReason {
    /// Nobody was ever met who could take it, or everyone who took it failed.
    NoCarrierFound,
    /// A direct message whose ephemeral recipient was gone. There is no
    /// mailbox to leave it in, because there is no account behind the key.
    RecipientGone,
    /// Ran out of hops or carry window while in flight.
    CarryWindowClosed,
}

impl UndeliveredReason {
    /// Plain words for the message screen. Kept here rather than in the shell
    /// so that iOS and Android cannot drift into saying different things.
    #[must_use]
    pub fn user_text(self) -> &'static str {
        match self {
            UndeliveredReason::NoCarrierFound => "Not sent. Nobody came in range.",
            UndeliveredReason::RecipientGone => "Not sent. That person has left.",
            UndeliveredReason::CarryWindowClosed => "Not sent. It was carried too long.",
        }
    }
}

/// What we are entitled to say about a message.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DeliveryState {
    /// In our own outbox, nobody else has a copy.
    Queued {
        attempts: u8,
        next_attempt: Millis,
    },
    /// At least one other device is carrying a copy. This is the state
    /// `Flags::WAS_CARRIED` exists to report, and the only honest thing to say
    /// is that it left the building, not that it arrived.
    Carried { carriers: u8, since: Millis },
    /// A member of the target channel acknowledged it. Not "Bob got it".
    DeliveredToChannel { at: Millis, acks: u8 },
    /// Someone in the channel opened it.
    ReadBySomeone { at: Millis, readers: u8 },
    /// Gone, and never arrived as far as we know.
    ExpiredUndelivered {
        at: Millis,
        reason: UndeliveredReason,
    },
}

impl DeliveryState {
    /// Rank for the one-way transition rule.
    fn rank(self) -> u8 {
        match self {
            DeliveryState::Queued { .. } => 0,
            DeliveryState::Carried { .. } => 1,
            DeliveryState::DeliveredToChannel { .. } => 2,
            DeliveryState::ReadBySomeone { .. } => 3,
            DeliveryState::ExpiredUndelivered { .. } => 4,
        }
    }

    #[must_use]
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            DeliveryState::ReadBySomeone { .. } | DeliveryState::ExpiredUndelivered { .. }
        )
    }

    #[must_use]
    pub fn is_delivered(self) -> bool {
        matches!(
            self,
            DeliveryState::DeliveredToChannel { .. } | DeliveryState::ReadBySomeone { .. }
        )
    }

    /// Apply a candidate state, keeping whichever claim is both later in the
    /// sequence and still true.
    ///
    /// Expiry is special: it may only be entered from a non-delivered state.
    /// A message that was delivered and then timed out locally is delivered,
    /// and a delivery receipt that arrives after we gave up corrects the record
    /// rather than being discarded.
    pub fn advance(&mut self, candidate: DeliveryState) -> bool {
        let cur = *self;
        let allow = match (cur, candidate) {
            (_, DeliveryState::ExpiredUndelivered { .. }) => !cur.is_delivered(),
            (DeliveryState::ExpiredUndelivered { .. }, c) => c.is_delivered(),
            (a, b) => b.rank() > a.rank(),
        };
        if allow {
            *self = candidate;
        }
        allow
    }

    /// Single-word label for the message screen. The copy lives next to the
    /// state so that the two cannot fall out of step.
    #[must_use]
    pub fn user_text(self) -> &'static str {
        match self {
            DeliveryState::Queued { .. } => "Waiting for someone in range",
            DeliveryState::Carried { .. } => "Being carried",
            DeliveryState::DeliveredToChannel { .. } => "Delivered to the channel",
            DeliveryState::ReadBySomeone { .. } => "Read by someone in the channel",
            DeliveryState::ExpiredUndelivered { reason, .. } => reason.user_text(),
        }
    }
}

/// One reported state change, so the layer above can refresh exactly the rows
/// that moved instead of re-reading the whole outbox.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StateChange {
    pub msg_id: gdc_wire::MsgId,
    pub from: DeliveryState,
    pub to: DeliveryState,
}
