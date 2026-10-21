//! What the device actually observes about how social its surroundings are.
//!
//! The adaptive copy budget needs one number: the rate at which this device
//! meets peers it has *not* met before. Novelty is the right signal and
//! re-encounter is the wrong one. Five phones sitting together in a stairwell
//! meet each other constantly and that tells you nothing about whether a
//! message can leave the stairwell. A phone that meets a stranger every thirty
//! seconds is in a stream of people, and a stream of people is carrying
//! capacity.
//!
//! Two rates are kept. The overall novel-peer rate says how much carrying
//! capacity exists. The per-channel novel-member rate says how much of that
//! capacity ends at the destination, and is used directly when there is enough
//! of it, because it is the quantity the delivery model actually wants.
//!
//! Everything here is bounded and holds no peer identifiers. The window is a
//! queue of timestamps; the novelty test is a salted Bloom filter. A seized
//! device yields "this phone met about forty new people in the last ten
//! minutes", not a list of who they were.

use crate::limits::{
    ENCOUNTER_WINDOW_MS, MAX_CHANNELS, MAX_ENCOUNTER_SAMPLES, MAX_MEMBER_SAMPLES,
    MIN_OBSERVATION_MS,
};
use crate::tags::ChannelId;
use crate::types::{Millis, NoveltyFilter, PeerId};
use std::collections::VecDeque;

/// Encounters per second, scaled by 1e6 so the policy stays in integer
/// arithmetic. Floating point would be fine numerically and is avoided because
/// a reproducible number is worth more than a tidy one.
#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
pub struct MicroRate(pub u64);

/// What the meter is prepared to claim.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RateEstimate {
    /// Not enough observation time to say anything.
    Unknown,
    /// Novel in-channel encounters, directly observed.
    Member(MicroRate),
    /// Novel encounters overall, to be discounted by the member-fraction prior.
    Overall(MicroRate),
}

#[derive(Clone, Debug)]
struct MemberWindow {
    channel: ChannelId,
    times: VecDeque<Millis>,
}

/// Sliding-window novelty meter.
#[derive(Clone, Debug)]
pub struct EncounterMeter {
    novelty: NoveltyFilter,
    novel: VecDeque<Millis>,
    members: Vec<MemberWindow>,
    session_start: Millis,
    last_seen: Millis,
    total_novel: u64,
}

impl EncounterMeter {
    #[must_use]
    pub fn new(salt: u64, session_start: Millis) -> Self {
        EncounterMeter {
            novelty: NoveltyFilter::new(salt),
            novel: VecDeque::new(),
            members: Vec::new(),
            session_start,
            last_seen: session_start,
            total_novel: 0,
        }
    }

    /// Record a peer encounter.
    ///
    /// `shared` lists the channels this peer was observed to be a member of —
    /// learned from presence traffic whose tag we matched, which means we only
    /// ever learn it about channels we are already in. Bounded by the caller's
    /// own channel table.
    ///
    /// Returns whether the peer was novel.
    pub fn observe(&mut self, now: Millis, peer: PeerId, shared: &[ChannelId]) -> bool {
        self.last_seen = self.last_seen.max(now);
        if !self.novelty.observe(peer) {
            return false;
        }
        self.total_novel = self.total_novel.saturating_add(1);
        push_capped(&mut self.novel, now, MAX_ENCOUNTER_SAMPLES);
        for ch in shared.iter().take(MAX_CHANNELS) {
            if let Some(w) = self.members.iter_mut().find(|w| w.channel == *ch) {
                push_capped(&mut w.times, now, MAX_MEMBER_SAMPLES);
            } else if self.members.len() < MAX_CHANNELS {
                let mut times = VecDeque::new();
                times.push_back(now);
                self.members.push(MemberWindow {
                    channel: *ch,
                    times,
                });
            }
        }
        true
    }

    /// Drop samples that have fallen out of the window.
    ///
    /// Called from the store's tick so the estimate decays with time rather
    /// than only when a peer happens to arrive. Without this, a device that met
    /// a crowd at noon would still believe it was in a crowd at midnight.
    pub fn prune(&mut self, now: Millis) {
        let cutoff = now.0.saturating_sub(ENCOUNTER_WINDOW_MS);
        while self.novel.front().is_some_and(|t| t.0 < cutoff) {
            self.novel.pop_front();
        }
        for w in &mut self.members {
            while w.times.front().is_some_and(|t| t.0 < cutoff) {
                w.times.pop_front();
            }
        }
    }

    /// Effective averaging window: the configured window, or the whole session
    /// if it is younger. A device three seconds out of a wipe has not observed
    /// ten minutes of quiet and must not be allowed to claim it has.
    #[must_use]
    fn window_ms(&self, now: Millis) -> u64 {
        now.since(self.session_start).min(ENCOUNTER_WINDOW_MS)
    }

    #[must_use]
    pub fn novel_in_window(&self) -> usize {
        self.novel.len()
    }

    #[must_use]
    pub fn total_novel(&self) -> u64 {
        self.total_novel
    }

    #[must_use]
    pub fn members_in_window(&self, channel: ChannelId) -> usize {
        self.members
            .iter()
            .find(|w| w.channel == channel)
            .map_or(0, |w| w.times.len())
    }

    /// The best-supported estimate for `channel`.
    #[must_use]
    pub fn estimate(&self, now: Millis, channel: ChannelId) -> RateEstimate {
        let win = self.window_ms(now);
        if win < MIN_OBSERVATION_MS {
            return RateEstimate::Unknown;
        }
        let members = self.members_in_window(channel);
        if members >= crate::limits::MIN_MEMBER_SAMPLES {
            return RateEstimate::Member(micro_rate(members as u64, win));
        }
        let novel = self.novel.len();
        if novel >= crate::limits::MIN_NOVEL_SAMPLES {
            return RateEstimate::Overall(micro_rate(novel as u64, win));
        }
        // Observed long enough and met (almost) nobody. That is information,
        // not absence of information: this device is in a sparse place.
        RateEstimate::Overall(micro_rate(novel as u64, win))
    }

    /// Forget everything about who has been met.
    pub fn wipe(&mut self) {
        self.novelty.wipe();
        self.novel.clear();
        self.members.clear();
        self.total_novel = 0;
    }
}

fn push_capped(q: &mut VecDeque<Millis>, now: Millis, cap: usize) {
    if q.len() >= cap {
        // Dropping the oldest only coarsens the estimate. It can never make the
        // queue grow, which is the property that matters here.
        q.pop_front();
    }
    q.push_back(now);
}

/// `count / window` as encounters per second scaled by 1e6.
#[must_use]
pub fn micro_rate(count: u64, window_ms: u64) -> MicroRate {
    if window_ms == 0 {
        return MicroRate(0);
    }
    MicroRate(count.saturating_mul(1_000_000_000) / window_ms)
}
