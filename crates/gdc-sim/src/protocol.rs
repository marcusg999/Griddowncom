//! The protocol-under-test interface.
//!
//! One trait, so the simulator can run any mesh stack interchangeably: ours,
//! the Bridgefy model, the bitchat model. `gdc-baseline` implements this same
//! trait, so it is deliberately narrow and deliberately neutral:
//!
//! * A **pure flood** implements it by rebroadcasting anything whose `MsgId` it
//!   has not seen, ignoring `PeerInfo`, `rssi_dbm` and the link/broadcast
//!   distinction entirely.
//! * A **source-routing stack with neighbour tables** implements it by building
//!   its tables from `on_link_up` / `on_link_down` / `on_receive`, and by
//!   choosing which link to answer on when offered a `SendSlot::Link`.
//!
//! Nothing in here hands a stack information a real implementation would not
//! have. In particular there is no neighbour list, no node count, no global
//! position and no topology query: a stack that wants a neighbour table must
//! build one. Peers are identified by an opaque [`PeerId`] that stands in for a
//! per-session ephemeral key, so a stack cannot use it to index anything global.

use crate::clock::SimTime;
use crate::phy::PhyMode;
use crate::platform::{AppState, Platform};
use gdc_wire::{ChanTag, Frame, MsgId};
use rand::RngCore;
use rand_chacha::ChaCha20Rng;

/// Opaque handle for a peer, stable for as long as that peer's session lasts.
///
/// Stands in for the peer's ephemeral session key. Not a node index: it is
/// derived from the world seed so a stack cannot reverse it into one.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct PeerId(pub u64);

/// Handle for an established connection-oriented link.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct LinkId(pub u32);

/// What a stack learns about a peer when a link comes up.
///
/// Platform and app state are included because they are genuinely discoverable
/// (a presence frame can carry them) and because a stack that wants to avoid
/// electing a backgrounded iPhone as a relay must be able to. A flood is free
/// to ignore them.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct PeerInfo {
    pub peer: PeerId,
    pub platform: Platform,
    pub app_state: AppState,
    /// False when the peer's advertisement carried no local name, i.e. a
    /// backgrounded iOS peripheral.
    pub identified_from_advertisement: bool,
    pub rssi_dbm: f64,
    /// Negotiated ATT MTU, i.e. the most this link will carry in one write.
    pub mtu: usize,
    /// Round-trip time a stack should expect on this link.
    pub conn_interval: SimTime,
}

/// Where a received frame came from.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct FrameSource {
    pub peer: PeerId,
    /// `None` when the frame arrived in a connectionless broadcast.
    pub link: Option<LinkId>,
    pub rssi_dbm: f64,
    pub mode: PhyMode,
}

/// An opportunity to put one frame on the air.
///
/// The simulator offers these; it never asks a stack to invent its own
/// schedule. That keeps airtime accounting honest and makes two stacks
/// comparable: both get the same slots in the same world.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SendSlot {
    /// A connectionless broadcast slot (a BLE advertising event).
    ///
    /// `budget_bytes` is what this platform and app state can actually put in
    /// an advertisement. On iOS it is zero in every app state, because
    /// CoreBluetooth exposes no extended advertising; a stack offered a
    /// zero-budget slot must return `None` and use links instead.
    Broadcast {
        budget_bytes: usize,
        mode: PhyMode,
    },
    /// A scheduled connection event on an established link.
    Link {
        link: LinkId,
        peer: PeerId,
        budget_bytes: usize,
        mode: PhyMode,
    },
}

impl SendSlot {
    pub fn budget_bytes(self) -> usize {
        match self {
            SendSlot::Broadcast { budget_bytes, .. } => budget_bytes,
            SendSlot::Link { budget_bytes, .. } => budget_bytes,
        }
    }

    pub fn link(self) -> Option<LinkId> {
        match self {
            SendSlot::Broadcast { .. } => None,
            SendSlot::Link { link, .. } => Some(link),
        }
    }
}

/// A message handed to the stack by the application layer.
#[derive(Clone, PartialEq, Debug)]
pub struct AppMessage {
    /// Identity the harness tracks delivery by. A stack must carry it, in the
    /// header or in its own payload, or its deliveries cannot be counted.
    pub id: MsgId,
    pub channel: ChanTag,
    pub body: Vec<u8>,
    pub urgent: bool,
    pub want_ack: bool,
    pub created_at: SimTime,
}

/// Everything a stack may do to the world, and everything it may know about
/// the moment it is in.
///
/// Holding the RNG here rather than inside the stack is what makes a run
/// reproducible: a stack that reaches for ambient randomness breaks
/// determinism, and the only randomness on offer is this one.
pub struct StackCtx<'a> {
    pub node: PeerId,
    pub now: SimTime,
    /// The stack's own platform and app state. A stack legitimately knows this
    /// about itself and may adapt to it.
    pub platform: Platform,
    pub app_state: AppState,
    rng: &'a mut ChaCha20Rng,
    deliveries: &'a mut Vec<Delivery>,
    log: &'a mut Vec<StackNote>,
}

/// An application-layer delivery the stack is reporting.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Delivery {
    pub app_id: MsgId,
    pub at: SimTime,
}

/// A free-form note a stack can leave for the harness. Counted, not
/// interpreted; useful for "I suppressed a duplicate" style instrumentation
/// without widening the trait.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct StackNote {
    pub kind: &'static str,
    pub count: u32,
}

impl<'a> StackCtx<'a> {
    pub fn new(
        node: PeerId,
        now: SimTime,
        platform: Platform,
        app_state: AppState,
        rng: &'a mut ChaCha20Rng,
        deliveries: &'a mut Vec<Delivery>,
        log: &'a mut Vec<StackNote>,
    ) -> Self {
        StackCtx {
            node,
            now,
            platform,
            app_state,
            rng,
            deliveries,
            log,
        }
    }

    /// The only randomness a stack may use.
    pub fn rng(&mut self) -> &mut ChaCha20Rng {
        self.rng
    }

    pub fn fill_random(&mut self, buf: &mut [u8]) {
        self.rng.fill_bytes(buf);
    }

    /// A fresh per-message identifier, as `gdc-wire` requires: random, never
    /// derived from content or identity.
    pub fn fresh_msg_id(&mut self) -> MsgId {
        let mut b = [0u8; 16];
        self.rng.fill_bytes(&mut b);
        MsgId(b)
    }

    /// Report that an application message has arrived at this node.
    ///
    /// Idempotent from the harness's point of view: repeated reports of the
    /// same `app_id` at the same node are counted as redundant receptions, not
    /// as extra deliveries.
    pub fn deliver_to_app(&mut self, app_id: MsgId) {
        self.deliveries.push(Delivery {
            app_id,
            at: self.now,
        });
    }

    pub fn note(&mut self, kind: &'static str) {
        if let Some(n) = self.log.iter_mut().find(|n| n.kind == kind) {
            n.count = n.count.saturating_add(1);
        } else {
            self.log.push(StackNote { kind, count: 1 });
        }
    }
}

/// A mesh stack under test.
///
/// Three responsibilities and nothing else: receive a frame on a link, be
/// offered a send opportunity, be ticked with a clock.
pub trait MeshStack {
    /// Stable name, used only for the sealed label mapping in the blind rig.
    /// The critic never sees it.
    fn name(&self) -> &'static str;

    /// Called at the scenario's tick interval. The only place a stack may do
    /// timer-driven work: expiry, retransmission decisions, neighbour ageing.
    fn on_tick(&mut self, ctx: &mut StackCtx<'_>);

    /// A connection-oriented link to a peer is now usable.
    fn on_link_up(&mut self, ctx: &mut StackCtx<'_>, link: LinkId, peer: PeerInfo);

    /// A link has gone. Pedestrian motion makes this frequent.
    fn on_link_down(&mut self, ctx: &mut StackCtx<'_>, link: LinkId);

    /// A frame arrived, over a link or in a broadcast.
    fn on_receive(&mut self, ctx: &mut StackCtx<'_>, src: FrameSource, frame: &Frame);

    /// The radio is about to be free. Return a frame to put on the air, or
    /// `None` to stay quiet. Returning a frame larger than
    /// `slot.budget_bytes()` is treated as returning `None`.
    fn on_send_opportunity(&mut self, ctx: &mut StackCtx<'_>, slot: SendSlot) -> Option<Frame>;

    /// The application wants a message sent.
    fn on_app_message(&mut self, ctx: &mut StackCtx<'_>, msg: &AppMessage);
}

/// A stack and the factory that builds it, so the harness can instantiate one
/// per node without the stack type leaking into the engine.
pub type StackFactory = Box<dyn Fn(PeerId) -> Box<dyn MeshStack>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::sequential;

    struct Silent;
    impl MeshStack for Silent {
        fn name(&self) -> &'static str {
            "silent"
        }
        fn on_tick(&mut self, _c: &mut StackCtx<'_>) {}
        fn on_link_up(&mut self, _c: &mut StackCtx<'_>, _l: LinkId, _p: PeerInfo) {}
        fn on_link_down(&mut self, _c: &mut StackCtx<'_>, _l: LinkId) {}
        fn on_receive(&mut self, _c: &mut StackCtx<'_>, _s: FrameSource, _f: &Frame) {}
        fn on_send_opportunity(
            &mut self,
            _c: &mut StackCtx<'_>,
            _s: SendSlot,
        ) -> Option<Frame> {
            None
        }
        fn on_app_message(&mut self, _c: &mut StackCtx<'_>, _m: &AppMessage) {}
    }

    #[test]
    fn the_trait_is_implementable_without_touching_anything_else() {
        let mut rng = sequential(1, "t");
        let mut del = Vec::new();
        let mut log = Vec::new();
        let mut ctx = StackCtx::new(
            PeerId(1),
            SimTime::ZERO,
            Platform::Android,
            AppState::Background,
            &mut rng,
            &mut del,
            &mut log,
        );
        let mut s = Silent;
        s.on_tick(&mut ctx);
        assert!(s
            .on_send_opportunity(
                &mut ctx,
                SendSlot::Broadcast {
                    budget_bytes: 255,
                    mode: PhyMode::Ble1M
                }
            )
            .is_none());
        assert_eq!(s.name(), "silent");
    }

    #[test]
    fn msg_ids_are_random_and_notes_accumulate() {
        let mut rng = sequential(2, "t");
        let mut del = Vec::new();
        let mut log = Vec::new();
        let mut ctx = StackCtx::new(
            PeerId(1),
            SimTime::ZERO,
            Platform::Ios,
            AppState::Foreground,
            &mut rng,
            &mut del,
            &mut log,
        );
        let a = ctx.fresh_msg_id();
        let b = ctx.fresh_msg_id();
        assert_ne!(a, b);
        ctx.note("dup");
        ctx.note("dup");
        assert_eq!(log[0].count, 2);
    }
}
