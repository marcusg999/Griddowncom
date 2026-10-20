//! Every ceiling in the crate, in one place.
//!
//! The house rule is that any store whose size is driven by remote input has an
//! explicit bound. Collecting the bounds here means a reviewer can audit the
//! attack surface by reading one file, and a hostile-input test can assert
//! against the same constants the code enforces.
//!
//! The numbers are chosen against bitchat's, which is the design we are
//! blind-tested against. Where we are larger we say why, because "bigger
//! buffer" is not an argument on a phone.

/// Messages the author's own outbox will hold, in aggregate.
///
/// bitchat bounds its outbox at 100 messages *per peer*, which is not a bound
/// at all: the product of a per-peer cap and an unbounded peer set is
/// unbounded. The device constraint is total storage, so the cap is total.
pub const MAX_OUTBOX_MSGS: usize = 64;

/// Bytes the outbox will hold, in aggregate.
pub const MAX_OUTBOX_BYTES: usize = 64 * 1024;

/// Send attempts before a message is declared undeliverable.
pub const MAX_OUTBOX_ATTEMPTS: u8 = 8;

/// First retry delay. Doubles per attempt up to [`OUTBOX_BACKOFF_CAP_MS`].
pub const OUTBOX_BACKOFF_BASE_MS: u64 = 5_000;

/// Ceiling on the retry interval.
pub const OUTBOX_BACKOFF_CAP_MS: u64 = 600_000;

/// Jitter applied to each retry, as a fraction 1/N of the interval.
///
/// Not an anonymity measure — it exists so that a cluster of devices that all
/// lost the same link do not retry in lockstep and collide.
pub const OUTBOX_JITTER_FRACTION: u64 = 4;

/// How long the author keeps trying before reporting expired-undelivered.
pub const OUTBOX_LIFETIME_MS: u64 = 12 * 3600 * 1000;

/// Envelopes carried for other people's channels.
pub const MAX_COURIER_ENVELOPES: usize = 512;

/// Bytes carried for other people's channels.
///
/// bitchat allows 16 KiB. That is about 55 of our frames, which will not cross
/// a city. 128 KiB is roughly 450 typical envelopes and is still a rounding
/// error against a phone's memory; the real cost of carrying mail is radio
/// time, which the admission limiter below bounds, not bytes at rest.
pub const MAX_COURIER_BYTES: usize = 128 * 1024;

/// Longest a courier holds an envelope, measured from local receipt.
///
/// There is no timestamp in the cleartext header — deliberately, since one
/// would leak age to an observer — so a courier cannot know an envelope's true
/// age and must measure from when it first saw it. See `MAX_CARRY_MS`'s
/// interaction with the copy budget in the crate docs.
pub const MAX_CARRY_MS: u64 = 12 * 3600 * 1000;

/// Fairness classes for eviction. Fixed, so the class table cannot grow.
pub const SOURCE_CLASSES: usize = 64;

/// Envelopes one source class may hand over in a burst.
pub const ADMIT_BURST: u32 = 32;

/// Refill interval for one admission token, per source class.
pub const ADMIT_REFILL_MS: u64 = 10_000;

/// Minimum gap between delivery attempts of one envelope *to the same peer*.
///
/// bitchat throttles one attempt per envelope per 10 minutes globally. A
/// courier walking through a cluster is in contact for perhaps two minutes, so
/// that policy delivers at most one envelope per pass. Throttling per peer
/// instead lets a courier dump its whole bag on arrival and still refuses to
/// re-offer the same envelope to a peer that already declined it.
pub const DELIVERY_RETRY_MS: u64 = 60_000;

/// Peers remembered per envelope, for the per-peer delivery throttle.
pub const MAX_ATTEMPTED_PEERS: usize = 4;

/// Channels one device can hold keys for.
pub const MAX_CHANNELS: usize = 32;

/// Past tag epochs kept for matching, so a carried frame survives rotation.
///
/// `MAX_CARRY_MS / TAG_EPOCH_SECS` = 12, plus one for a frame minted just
/// before a boundary.
pub const TAG_RING_BACK: u32 = 13;

/// Future tag epochs kept, to tolerate clock skew between devices.
pub const TAG_RING_FWD: u32 = 1;

/// Tags held per channel: back epochs, the current one, and forward epochs.
pub const TAG_RING_LEN: usize = (TAG_RING_BACK + TAG_RING_FWD + 1) as usize;

/// Message ids remembered for duplicate suppression and set reconciliation.
pub const MAX_SEEN: usize = 2048;

/// Slots in the seen-log's open-addressed index. Power of two, >= 2x `MAX_SEEN`.
pub const SEEN_SLOTS: usize = 4096;

/// Probe limit for the seen-log index. Bounds the work an adversary who picks
/// message ids can force per insertion.
pub const SEEN_MAX_PROBE: usize = 64;

/// How far back reconciliation reaches. Beyond the longest deadline in
/// `docs/METRICS.md` there is nothing left to win by syncing.
pub const SYNC_WINDOW_MS: u64 = 2 * 3600 * 1000;

/// Ceiling on a reconciliation digest we will build or accept.
pub const MAX_DIGEST_BYTES: usize = 4096;

/// Ceiling on ids named in one reconciliation reply.
pub const MAX_RECON_REQUEST_IDS: usize = 256;

/// Novel-encounter timestamps retained for the rate estimate.
pub const MAX_ENCOUNTER_SAMPLES: usize = 256;

/// Novel in-channel encounter timestamps retained, per channel.
pub const MAX_MEMBER_SAMPLES: usize = 64;

/// Averaging window for the encounter-rate estimate.
pub const ENCOUNTER_WINDOW_MS: u64 = 600_000;

/// Below this much observation we decline to guess and use the default budget.
pub const MIN_OBSERVATION_MS: u64 = 60_000;

/// Bits in the novelty filter. 512 bytes; holds ~700 peers before the false
/// positive rate passes 3 %.
pub const NOVELTY_BITS: usize = 4096;

/// Hash functions in the novelty filter.
pub const NOVELTY_HASHES: usize = 3;

/// Floor on the adaptive copy budget. One copy is the wait phase of
/// spray-and-wait: hold it, deliver only to a channel member.
pub const COPY_BUDGET_MIN: u8 = 1;

/// Ceiling on the adaptive copy budget.
///
/// bitchat caps at 8 from a start of 4. The worst case here is 12 copies of a
/// 1024-byte frame, 12 KiB spread across twelve devices, bounded further by
/// [`MAX_OUTBOX_MSGS`]. The cost of the ceiling is paid by other people's
/// stores, which is why admission and fair eviction are not optional.
pub const COPY_BUDGET_MAX: u8 = 12;

/// Budget used when we have no observation yet.
///
/// Deliberately equal to bitchat's fixed budget: with no information we should
/// not claim to know better than the baseline. The policy only diverges once
/// it has measured something.
pub const COPY_BUDGET_DEFAULT: u8 = 4;

/// Deadline the budget policy solves for, in seconds.
///
/// The 30 min rung of `docs/METRICS.md`. The 30 s and 5 min rungs belong to the
/// live-link regime and no copy count rescues them; the 2 h rung arrives on the
/// tail of whatever the 30 min policy set in motion.
pub const TARGET_DEADLINE_SECS: u64 = 1800;

/// Prior for the fraction of novel peers that turn out to be channel members,
/// as a reciprocal. Used only until enough in-channel encounters are observed.
pub const MEMBER_FRACTION_PRIOR_RECIP: u64 = 4;

/// In-channel encounters required before the per-channel rate is trusted.
pub const MIN_MEMBER_SAMPLES: usize = 3;

/// Novel encounters required before the overall rate is trusted.
pub const MIN_NOVEL_SAMPLES: usize = 2;

/// `-ln(1 - 0.95)` scaled by 1000. The policy targets a 95 % chance of at
/// least one copy-holder meeting a channel member before the deadline.
pub const NEG_LN_MISS_X1000: u64 = 2996;

/// Expiry events reported from one sweep. The stores are bounded, so this only
/// bounds the size of one report, not the total work.
pub const MAX_EXPIRY_EVENTS_PER_TICK: usize = 64;
