//! Link and timing model: channels, airtime, contention, queues.
//!
//! The part that matters most here is contention. A flood that works at 5 nodes
//! and dies at 150 must actually die in the simulator, otherwise there is
//! nothing to beat. Three mechanisms make that happen, and all three are real:
//!
//! 1. **Channel collisions.** Connectionless broadcasts land on one of three
//!    advertising channels. Two overlapping transmissions on the same channel
//!    destroy each other unless one is `capture_threshold_db` stronger.
//! 2. **A node's radio is singular.** It cannot transmit two frames at once,
//!    and it cannot hear anything while it is transmitting.
//! 3. **Finite queues.** Every node has a bounded outbound queue. Under a
//!    flood at high density the queue is the binding constraint long before
//!    the air is, which is exactly what happens on a real phone.
//!
//! `docs/BRIEF.md` requires an explicit ceiling on every allocation driven by
//! remote input; [`LinkConfig::max_queue_frames`] is that ceiling for the
//! simulator's own buffers.

use crate::clock::SimTime;
use crate::phy::PhyMode;
use crate::provenance::{ParamDoc, ParamSource};
use serde::{Deserialize, Serialize};

/// Global link-layer knobs that are not per-platform.
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct LinkConfig {
    /// BLE primary advertising channels: 37, 38, 39.
    pub adv_channels: u32,
    /// Data channels available to a connection after channel-map negotiation.
    pub data_channels: u32,
    /// Default ATT MTU before negotiation. The negotiated value comes from the
    /// platform profile.
    pub att_mtu_default: usize,
    /// Bytes of ATT overhead per write.
    pub att_overhead_bytes: usize,
    /// Outbound queue ceiling per node, in frames.
    pub max_queue_frames: usize,
    /// How long a link may be below the usability threshold before it is torn
    /// down. Without grace, pedestrian shadowing flaps every link constantly.
    pub link_drop_grace: SimTime,
    /// Received power below this much above sensitivity counts as unusable for
    /// keeping a connection alive.
    pub link_keep_margin_db: f64,
    /// Interval at which stacks are ticked.
    pub tick_interval: SimTime,
    /// How often connectivity, neighbour geometry and shadowing are refreshed.
    pub world_step: SimTime,
    /// Maximum simultaneous connection attempts a node will have outstanding.
    pub max_pending_connects: usize,
}

impl Default for LinkConfig {
    fn default() -> Self {
        LinkConfig {
            adv_channels: 3,
            data_channels: 37,
            att_mtu_default: 23,
            att_overhead_bytes: 3,
            max_queue_frames: 64,
            link_drop_grace: SimTime::from_secs(3),
            link_keep_margin_db: -3.0,
            tick_interval: SimTime::from_millis_f64(500.0),
            world_step: SimTime::from_secs(1),
            max_pending_connects: 2,
        }
    }
}

impl LinkConfig {
    pub fn provenance(&self) -> Vec<ParamDoc> {
        vec![
            ParamDoc::new(
                "adv_channels",
                f64::from(self.adv_channels),
                "",
                ParamSource::spec(
                    "Bluetooth Core: three primary advertising channels (37, 38, 39). \
                     Sets the collision probability for connectionless flooding, so \
                     it is the main reason a broadcast flood degrades with density.",
                ),
            ),
            ParamDoc::new(
                "data_channels",
                f64::from(self.data_channels),
                "",
                ParamSource::spec("Bluetooth Core: 37 data channels with frequency hopping."),
            ),
            ParamDoc::new(
                "max_queue_frames",
                self.max_queue_frames as f64,
                "frames",
                ParamSource::assumed(
                    "Outbound queue ceiling per node. Chosen so that a TTL-100 flood \
                     at 150 nodes overflows it, because on a real phone it does. \
                     Also the explicit allocation ceiling docs/BRIEF.md requires.",
                ),
            ),
            ParamDoc::new(
                "link_drop_grace_s",
                self.link_drop_grace.as_secs_f64(),
                "s",
                ParamSource::assumed(
                    "Supervision-timeout-like grace before a weak link is torn down. \
                     Shorter values make link survival collapse under pedestrian \
                     shadowing; longer ones hide real churn.",
                ),
            ),
            ParamDoc::new(
                "tick_interval_ms",
                self.tick_interval.as_millis_f64(),
                "ms",
                ParamSource::assumed(
                    "How often a stack gets a timer. Identical for both arms of a \
                     blind comparison, so it cannot favour either.",
                ),
            ),
        ]
    }

    /// Payload a single GATT write carries at a negotiated MTU.
    pub fn write_payload(&self, mtu: usize) -> usize {
        mtu.saturating_sub(self.att_overhead_bytes)
    }
}

/// One transmission on the air.
#[derive(Clone, PartialEq, Debug)]
pub struct Transmission {
    pub tx: u32,
    pub start: SimTime,
    pub end: SimTime,
    /// Channel index. Advertising transmissions draw from `adv_channels`,
    /// connection events from `data_channels`.
    pub channel: u32,
    pub connectionless: bool,
    pub mode: PhyMode,
    pub bytes: usize,
}

impl Transmission {
    pub fn overlaps(&self, other: &Transmission) -> bool {
        self.start < other.end && other.start < self.end
    }
}

/// Decide whether an interferer destroys a wanted packet.
///
/// Returns true when the wanted packet survives. A same-channel overlapping
/// transmission kills it unless the wanted signal is at least
/// `capture_threshold_db` stronger at the receiver.
pub fn survives_interferer(
    wanted_rx_dbm: f64,
    interferer_rx_dbm: f64,
    capture_threshold_db: f64,
) -> bool {
    if !interferer_rx_dbm.is_finite() {
        return true;
    }
    if !wanted_rx_dbm.is_finite() {
        return false;
    }
    wanted_rx_dbm - interferer_rx_dbm >= capture_threshold_db
}

/// A bounded outbound queue. Drops at the tail and counts the drops, because a
/// silent drop is the difference between a flood that looks fine and one that
/// has collapsed.
#[derive(Clone, Debug, Default)]
pub struct BoundedQueue<T> {
    items: std::collections::VecDeque<T>,
    cap: usize,
    pub dropped: u64,
}

impl<T> BoundedQueue<T> {
    pub fn new(cap: usize) -> Self {
        BoundedQueue {
            items: std::collections::VecDeque::new(),
            cap: cap.max(1),
            dropped: 0,
        }
    }

    pub fn push(&mut self, item: T) -> bool {
        if self.items.len() >= self.cap {
            self.dropped = self.dropped.saturating_add(1);
            return false;
        }
        self.items.push_back(item);
        true
    }

    pub fn pop(&mut self) -> Option<T> {
        self.items.pop_front()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_lets_a_strong_packet_through_a_weak_collision() {
        assert!(survives_interferer(-60.0, -80.0, 6.0));
        assert!(!survives_interferer(-80.0, -78.0, 6.0));
        // No interferer at all.
        assert!(survives_interferer(-90.0, f64::NEG_INFINITY, 6.0));
    }

    #[test]
    fn overlap_is_half_open_so_back_to_back_packets_do_not_collide() {
        let a = Transmission {
            tx: 0,
            start: SimTime::from_micros(0),
            end: SimTime::from_micros(100),
            channel: 37,
            connectionless: true,
            mode: PhyMode::Ble1M,
            bytes: 96,
        };
        let b = Transmission {
            tx: 1,
            start: SimTime::from_micros(100),
            end: SimTime::from_micros(200),
            ..a.clone()
        };
        assert!(!a.overlaps(&b));
        let c = Transmission {
            start: SimTime::from_micros(99),
            ..b.clone()
        };
        assert!(a.overlaps(&c));
    }

    #[test]
    fn the_queue_has_a_hard_ceiling_and_counts_what_it_loses() {
        let mut q = BoundedQueue::new(2);
        assert!(q.push(1));
        assert!(q.push(2));
        assert!(!q.push(3));
        assert_eq!(q.dropped, 1);
        assert_eq!(q.len(), 2);
        assert_eq!(q.pop(), Some(1));
        assert!(q.push(4));
        // A zero capacity is coerced to one rather than wedging the node.
        let mut z: BoundedQueue<u8> = BoundedQueue::new(0);
        assert!(z.push(1));
        assert!(!z.push(2));
    }
}
