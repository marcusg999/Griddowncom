//! The boundary with `gdc-store`. Narrow on purpose.
//!
//! Routing decides *now*. The store decides *later*. The handoff is the single
//! moment where routing concludes that there is no useful next hop at this
//! instant and that the frame's only remaining chance is a human walking.
//!
//! # What crosses the boundary, and what does not
//!
//! Routing hands over a frame **only** when the frame was admitted, was
//! verified as far as it can be, and still has hop budget left, but there is no
//! candidate link worth using. Specifically:
//!
//! | Situation | Handed to store? |
//! |---|---|
//! | No fresh neighbour other than the one that gave it to us | yes, `NoCandidates` |
//! | Candidates exist but every one is predicted dead inside the horizon | yes, `AllLinksDying` |
//! | Candidates exist but all of them already hold the frame | yes, `NoProgress` |
//! | We authored it and nobody is in range | yes, `NothingInRange` |
//! | TTL spent | **no** — dropped, and the TTL controller is told it clipped |
//! | Refused by a rate limiter | **no** — dropped. The store must never become the retry amplifier for a flooder |
//! | Failed verification | **no** — dropped. Nothing unauthenticated is ever persisted |
//! | Duplicate | **no** — we have already dealt with it |
//!
//! The two "no" rows that matter are the last three. If rate-limited or forged
//! frames could enter the store, an attacker would get free persistence and a
//! second delivery attempt per frame, which is strictly worse than the flood we
//! are trying to beat.
//!
//! # Coming back
//!
//! The store re-offers a frame through [`crate::Router::reoffer`]. Rules:
//!
//! * The frame is handed over **as received**, with its TTL unchanged. The
//!   relay path then decrements it, so being carried costs exactly one hop like
//!   any other relay. A carried frame cannot launder itself into a fresh hop
//!   budget.
//! * `reoffer` bypasses our own duplicate suppression for the *transmit*
//!   decision — we are deliberately re-sending something we have seen — but
//!   every receiver's suppression still applies, so a re-offer into a cluster
//!   that already has the frame costs one transmission and stops.
//! * The router sets `Flags::WAS_CARRIED`, which is what lets a UI honestly
//!   distinguish "carried" from "relayed" and what tells downstream nodes this
//!   frame travelled in a pocket.
//! * `expires_at_ms` is advice from routing about when the frame stops being
//!   worth carrying; the store owns the real expiry policy and its own memory
//!   ceiling.

use gdc_wire::{ChanTag, Frame, MsgId};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandoffReason {
    /// The only link we have is the one it arrived on.
    NoCandidates,
    /// Links exist but none is predicted to survive the horizon.
    AllLinksDying,
    /// Every candidate is already known to hold this frame.
    NoProgress,
    /// We authored it and have no neighbours at all.
    NothingInRange,
}

/// Everything the store needs, and nothing it does not.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StoreHandoff {
    pub frame: Frame,
    pub msg_id: MsgId,
    pub tag: ChanTag,
    pub reason: HandoffReason,
    /// Routing's advice on when carrying stops being worthwhile.
    pub expires_at_ms: u64,
    /// True if we are a member of this channel. A member can tell whether the
    /// frame is still wanted; a stranger is carrying blind and the store may
    /// want to rank it lower.
    pub member: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use gdc_wire::{Flags, Kind};

    #[test]
    fn handoff_carries_the_frame_unmodified() {
        let f = Frame::new(
            Kind::ChannelMsg,
            Flags::empty(),
            5,
            MsgId([1; 16]),
            ChanTag([2; 8]),
            &[0u8; 8],
            &mut |b| b.fill(0),
        )
        .expect("frame");
        let h = StoreHandoff {
            frame: f.clone(),
            msg_id: f.hdr.msg_id,
            tag: f.hdr.tag,
            reason: HandoffReason::NoCandidates,
            expires_at_ms: 1_000,
            member: true,
        };
        assert_eq!(h.frame.hdr.ttl, 5, "the store receives it as received");
    }
}
