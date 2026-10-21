//! Fragmentation and reassembly.
//!
//! A `gdc-wire` frame is up to `HEADER_LEN + 1024` = 1056 bytes. A BLE link
//! after MTU negotiation commonly carries 244 bytes per datagram, often 182,
//! and in the worst legal case 20 — the spec's 23-byte ATT MTU floor minus the
//! 3-byte ATT header. Every one of those has to work, so everything above this
//! module gets to pretend the link carries whole frames.
//!
//! # The threat model for this module specifically
//!
//! Reassembly is the single most attackable surface in the transport layer,
//! because it is the one place where a remote party's bytes cause us to
//! allocate and to hold state. `BRIDGEFY-FINDINGS` D-1 — the decompression bomb
//! that froze every client in range and was amplified network-wide by relaying
//! before parsing — is exactly this class of mistake: remote input driving
//! unbounded work with no ceiling anywhere.
//!
//! So every quantity an attacker controls has an explicit ceiling, and the
//! ceilings are enforced by construction rather than by a check somewhere:
//!
//! | attacker-controlled              | bound                                   |
//! |----------------------------------|-----------------------------------------|
//! | concurrent reassemblies per link | [`FragLimits::max_reassemblies_per_link`] |
//! | concurrent reassemblies total    | [`FragLimits::max_reassemblies_total`]  |
//! | total bytes buffered             | [`FragLimits::max_buffered_bytes`]      |
//! | lifetime of one reassembly       | [`FragLimits::reassembly_timeout`]      |
//! | fragments per message            | [`FragLimits::max_fragments`]           |
//! | reassembled size                 | [`MAX_FRAME_BYTES`]                     |
//!
//! Two subtleties that are easy to get wrong and are tested:
//!
//! * **The timeout runs from the first fragment, never from the last.** If it
//!   were refreshed on arrival, an attacker could hold a slot open for ever by
//!   dribbling one duplicate fragment per timeout period, and the concurrency
//!   bound would stop bounding anything.
//! * **Fragment geometry is canonical and checked, so fragments cannot
//!   overlap.** Each index maps to exactly one byte range, computed from the
//!   declared total length and fragment count, and a fragment whose payload
//!   length does not exactly match its range is rejected. This is the IP
//!   fragment-overlap bug, closed by construction rather than by a reassembly
//!   policy.

use crate::link::LinkId;
use crate::rng::RandSource;
use crate::time::Millis;
use gdc_wire::{Frame, WireError, BUCKETS, HEADER_LEN};

/// Largest thing we ever reassemble: a full `gdc-wire` frame.
///
/// Derived from the frozen wire contract rather than written down, so it cannot
/// drift away from it.
pub const MAX_FRAME_BYTES: usize = HEADER_LEN + 1024;

const _: () = assert!(MAX_FRAME_BYTES == HEADER_LEN + BUCKETS[BUCKETS.len() - 1] as usize);

/// Fragment header, on the wire, little-endian:
///
/// ```text
///   0        1        2        3        4        5
/// +--------+--------+--------+--------+--------+--------+
/// |      xid        |  idx   |  cnt   |     total       |
/// +--------+--------+--------+--------+--------+--------+
/// ```
///
/// Six bytes. At the 20-byte worst case that leaves 14 bytes of payload, so a
/// 1056-byte frame becomes 76 fragments — which is why
/// [`FragLimits::max_fragments`] defaults just above that and not higher.
///
/// `xid` is fresh randomness per transfer, scoped to one link. It is not derived
/// from content (which would let an observer confirm a guessed plaintext) and
/// not from identity (hard rule 6). Reuse within a link is handled by rejecting
/// a second transfer that declares different geometry under a live `xid`.
pub const FRAG_HEADER_LEN: usize = 6;

/// Smallest datagram we will fragment into: the ATT floor minus ATT overhead.
pub const MIN_DATAGRAM: usize = 20;

/// Payload bytes per fragment at the worst legal BLE MTU.
pub const MIN_FRAG_PAYLOAD: usize = MIN_DATAGRAM - FRAG_HEADER_LEN;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct FragHeader {
    pub xid: u16,
    pub idx: u8,
    pub cnt: u8,
    pub total: u16,
}

impl FragHeader {
    #[must_use]
    pub fn encode(&self) -> [u8; FRAG_HEADER_LEN] {
        let mut o = [0u8; FRAG_HEADER_LEN];
        o[0..2].copy_from_slice(&self.xid.to_le_bytes());
        o[2] = self.idx;
        o[3] = self.cnt;
        o[4..6].copy_from_slice(&self.total.to_le_bytes());
        o
    }

    /// Parse a header. Validates only what is self-contained; the limits in
    /// [`FragLimits`] are applied by the reassembler, which is the thing that
    /// has to hold the state.
    pub fn decode(src: &[u8]) -> Result<FragHeader, FragError> {
        if src.len() < FRAG_HEADER_LEN {
            return Err(FragError::ShortDatagram { got: src.len() });
        }
        let h = FragHeader {
            xid: u16::from_le_bytes([src[0], src[1]]),
            idx: src[2],
            cnt: src[3],
            total: u16::from_le_bytes([src[4], src[5]]),
        };
        if h.cnt == 0 {
            return Err(FragError::BadGeometry);
        }
        if h.idx >= h.cnt {
            return Err(FragError::BadGeometry);
        }
        if h.total as usize > MAX_FRAME_BYTES || h.total == 0 {
            return Err(FragError::TotalTooLarge { total: h.total });
        }
        // Canonical geometry. `stride` is implied by (total, cnt) and the count
        // must be the minimum that covers the total at that stride. This is
        // what makes every index map to exactly one range and makes overlapping
        // fragments unrepresentable rather than merely rejected.
        let stride = geometry_stride(h.total, h.cnt).ok_or(FragError::BadGeometry)?;
        let implied = h.total.div_ceil(stride);
        if implied != u16::from(h.cnt) {
            return Err(FragError::NonCanonicalGeometry);
        }
        Ok(h)
    }

    /// Byte range this fragment covers, given validated geometry.
    #[must_use]
    pub fn range(&self) -> Option<(usize, usize)> {
        let stride = geometry_stride(self.total, self.cnt)?;
        let start = usize::from(self.idx) * usize::from(stride);
        let end = (start + usize::from(stride)).min(usize::from(self.total));
        if start >= end {
            return None;
        }
        Some((start, end))
    }
}

/// `ceil(total / cnt)`, as a `u16`, or `None` if it does not fit.
fn geometry_stride(total: u16, cnt: u8) -> Option<u16> {
    if cnt == 0 || total == 0 {
        return None;
    }
    Some(total.div_ceil(u16::from(cnt)))
}

/// Every ceiling, in one struct, so a reviewer can see the whole bound surface
/// at once and a sweep can vary it.
#[derive(Clone, Copy, Debug)]
pub struct FragLimits {
    /// Concurrent partial messages from a single peer. A peer that wants to
    /// hold more state than this is simply refused; the oldest is not evicted,
    /// because evicting on a peer's behalf lets that peer destroy its own
    /// neighbours' progress.
    pub max_reassemblies_per_link: usize,
    /// Concurrent partial messages across every link. Bounds the damage from a
    /// crowd of hostile peers rather than one.
    pub max_reassemblies_total: usize,
    /// Total bytes held in partial messages across every link.
    ///
    /// The real memory bound. With the defaults below, the arithmetic worst
    /// case is `max_reassemblies_total * MAX_FRAME_BYTES` = 64 * 1056 = 66 kB,
    /// and this cap sits just under it so the byte bound is the binding one.
    pub max_buffered_bytes: usize,
    /// How long a partial message may live, measured from its **first**
    /// fragment.
    ///
    /// 10 s: long enough for 76 fragments at a pedestrian's link quality on a
    /// 20-byte MTU, short enough that a walked-away peer's state is gone before
    /// the next peer arrives.
    pub reassembly_timeout: Millis,
    /// Fragments per message.
    pub max_fragments: u8,
}

impl Default for FragLimits {
    fn default() -> Self {
        FragLimits {
            max_reassemblies_per_link: 4,
            max_reassemblies_total: 64,
            max_buffered_bytes: 64 * 1024,
            reassembly_timeout: Millis::secs(10),
            // 76 is the exact worst-case fragment count for a 1056-byte frame
            // at a 20-byte datagram. 80 leaves a little headroom for a sender
            // that chooses a smaller stride than it had to.
            max_fragments: 80,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum FragError {
    #[error("datagram of {got} bytes is shorter than a fragment header")]
    ShortDatagram { got: usize },
    #[error("fragment geometry is self-contradictory")]
    BadGeometry,
    #[error("fragment geometry is not canonical for its declared size")]
    NonCanonicalGeometry,
    #[error("declared total {total} exceeds the maximum frame size")]
    TotalTooLarge { total: u16 },
    #[error("fragment payload length does not match its declared range")]
    PayloadLengthMismatch,
    #[error("fragment contradicts the geometry already declared for this transfer")]
    GeometryConflict,
    #[error("fragment count {0} exceeds the limit")]
    TooManyFragments(u8),
    #[error("too many concurrent reassemblies")]
    TooManyReassemblies,
    #[error("reassembly buffer budget exhausted")]
    BufferBudgetExhausted,
    #[error("link datagram size {0} is below the minimum usable size")]
    DatagramTooSmall(usize),
    #[error("message of {0} bytes cannot be fragmented within the limits")]
    MessageTooLarge(usize),
    #[error(transparent)]
    Wire(#[from] WireError),
}

/// Split a frame into datagrams for a link of the given payload size.
///
/// `datagram` is [`crate::link::LinkSnapshot::datagram_payload`] — bytes
/// available after ATT overhead, before the fragment header.
///
/// A frame that fits in one datagram is still wrapped, with `cnt == 1`. One
/// code path, not two: the unfragmented case is where a second path would rot.
pub fn fragment(
    frame_bytes: &[u8],
    datagram: usize,
    limits: &FragLimits,
    rng: &mut dyn RandSource,
) -> Result<Vec<Vec<u8>>, FragError> {
    if datagram < MIN_DATAGRAM {
        return Err(FragError::DatagramTooSmall(datagram));
    }
    if frame_bytes.is_empty() || frame_bytes.len() > MAX_FRAME_BYTES {
        return Err(FragError::MessageTooLarge(frame_bytes.len()));
    }
    let stride = datagram - FRAG_HEADER_LEN;
    let cnt_usize = frame_bytes.len().div_ceil(stride);
    if cnt_usize > usize::from(limits.max_fragments) || cnt_usize > usize::from(u8::MAX) {
        return Err(FragError::MessageTooLarge(frame_bytes.len()));
    }
    let cnt = cnt_usize as u8;

    // Recompute the stride the receiver will derive from (total, cnt) and use
    // that, so the sender and receiver cannot disagree about geometry. For a
    // message that does not divide evenly this can be smaller than the link's
    // stride; a slightly under-filled datagram is a fair price for a geometry
    // both ends compute identically.
    let total = frame_bytes.len() as u16;
    let send_stride = usize::from(geometry_stride(total, cnt).ok_or(FragError::BadGeometry)?);

    let xid = (rng.next_u32() & 0xFFFF) as u16;
    let mut out = Vec::with_capacity(cnt_usize);
    for idx in 0..cnt {
        let start = usize::from(idx) * send_stride;
        let end = (start + send_stride).min(frame_bytes.len());
        let h = FragHeader {
            xid,
            idx,
            cnt,
            total,
        };
        let mut dg = Vec::with_capacity(FRAG_HEADER_LEN + (end - start));
        dg.extend_from_slice(&h.encode());
        dg.extend_from_slice(&frame_bytes[start..end]);
        out.push(dg);
    }
    Ok(out)
}

/// One partial message.
#[derive(Clone, Debug)]
struct Partial {
    xid: u16,
    cnt: u8,
    total: u16,
    buf: Vec<u8>,
    /// One bit per index. 80 fragments fits in two words with room to spare.
    have: u128,
    received: u8,
    /// First fragment's arrival. Never updated — see the module docs.
    started: Millis,
}

impl Partial {
    fn complete(&self) -> bool {
        self.received == self.cnt
    }
}

/// What came out of feeding a datagram in.
#[derive(Clone, Debug, PartialEq)]
pub enum Reassembled {
    /// Still waiting for more fragments.
    Partial,
    /// A complete frame. Already parsed by `gdc-wire`, so nothing above this
    /// layer ever sees unvalidated bytes.
    Frame(Frame),
    /// The datagram was accepted but was a duplicate of a fragment we had.
    /// Reported rather than silently swallowed so the metrics can see a peer
    /// that is wasting airtime.
    Duplicate,
}

/// Bounded reassembler. One per transport, shared across links.
#[derive(Debug)]
pub struct Reassembler {
    limits: FragLimits,
    /// Flat vector rather than a map: the whole point is that this is small and
    /// hard-bounded, and a linear scan over at most 64 entries beats a hash map
    /// that could grow.
    partials: Vec<(LinkId, Partial)>,
    buffered_bytes: usize,
    stats: FragStats,
}

/// Counters, for the metrics section and for proving the bounds bind.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FragStats {
    pub datagrams_in: u64,
    pub frames_out: u64,
    pub duplicates: u64,
    pub rejected_malformed: u64,
    pub rejected_over_limit: u64,
    pub timed_out: u64,
    /// High-water mark of concurrent reassemblies. A test asserts this never
    /// exceeds the configured ceiling under hostile input.
    pub peak_reassemblies: usize,
    pub peak_buffered_bytes: usize,
}

impl Reassembler {
    #[must_use]
    pub fn new(limits: FragLimits) -> Self {
        Reassembler {
            limits,
            partials: Vec::new(),
            buffered_bytes: 0,
            stats: FragStats::default(),
        }
    }

    #[must_use]
    pub fn stats(&self) -> FragStats {
        self.stats
    }

    #[must_use]
    pub fn in_flight(&self) -> usize {
        self.partials.len()
    }

    #[must_use]
    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    /// Drop partials older than the timeout. Called on every scheduling tick
    /// and at the top of every [`Reassembler::accept`], so a caller that
    /// forgets to tick cannot leak.
    pub fn expire(&mut self, now: Millis) {
        let timeout = self.limits.reassembly_timeout;
        let mut freed = 0usize;
        let mut dropped = 0u64;
        self.partials.retain(|(_, p)| {
            if now.since(p.started) >= timeout {
                freed += p.buf.len();
                dropped += 1;
                false
            } else {
                true
            }
        });
        self.buffered_bytes = self.buffered_bytes.saturating_sub(freed);
        self.stats.timed_out = self.stats.timed_out.saturating_add(dropped);
    }

    /// Drop every partial for a link. Called when a link drops, so a peer that
    /// walks away does not hold a slot until the timeout.
    pub fn drop_link(&mut self, link: LinkId) {
        let mut freed = 0usize;
        self.partials.retain(|(l, p)| {
            if *l == link {
                freed += p.buf.len();
                false
            } else {
                true
            }
        });
        self.buffered_bytes = self.buffered_bytes.saturating_sub(freed);
    }

    /// Clear everything. Part of the panic-wipe path: nothing survives a wipe.
    pub fn wipe(&mut self) {
        for (_, p) in &mut self.partials {
            p.buf.fill(0);
        }
        self.partials.clear();
        self.buffered_bytes = 0;
    }

    /// Feed one datagram received on `link`.
    ///
    /// Returns an error for anything malformed or over any limit. It never
    /// panics, never allocates more than the declared total of a single frame,
    /// and never leaves the buffer accounting inconsistent on an error path.
    pub fn accept(
        &mut self,
        link: LinkId,
        datagram: &[u8],
        now: Millis,
    ) -> Result<Reassembled, FragError> {
        self.stats.datagrams_in = self.stats.datagrams_in.saturating_add(1);
        self.expire(now);

        let h = match FragHeader::decode(datagram) {
            Ok(h) => h,
            Err(e) => {
                self.stats.rejected_malformed = self.stats.rejected_malformed.saturating_add(1);
                return Err(e);
            }
        };
        if h.cnt > self.limits.max_fragments {
            self.stats.rejected_over_limit = self.stats.rejected_over_limit.saturating_add(1);
            return Err(FragError::TooManyFragments(h.cnt));
        }
        let payload = &datagram[FRAG_HEADER_LEN..];
        let Some((start, end)) = h.range() else {
            self.stats.rejected_malformed = self.stats.rejected_malformed.saturating_add(1);
            return Err(FragError::BadGeometry);
        };
        // The payload must fill its range exactly. This is the check that makes
        // overlapping or short-padded fragments impossible.
        if payload.len() != end - start {
            self.stats.rejected_malformed = self.stats.rejected_malformed.saturating_add(1);
            return Err(FragError::PayloadLengthMismatch);
        }

        // Fast path: a single-fragment message never touches the partial table,
        // so a flood of complete small frames cannot consume reassembly slots.
        if h.cnt == 1 {
            return self.finish_bytes(payload.to_vec());
        }

        let slot = self
            .partials
            .iter()
            .position(|(l, p)| *l == link && p.xid == h.xid);

        let slot = match slot {
            Some(i) => {
                let p = &self.partials[i].1;
                if p.cnt != h.cnt || p.total != h.total {
                    self.stats.rejected_malformed =
                        self.stats.rejected_malformed.saturating_add(1);
                    return Err(FragError::GeometryConflict);
                }
                i
            }
            None => {
                // A new reassembly. Every ceiling is checked before a single
                // byte is allocated.
                let per_link = self.partials.iter().filter(|(l, _)| *l == link).count();
                if per_link >= self.limits.max_reassemblies_per_link
                    || self.partials.len() >= self.limits.max_reassemblies_total
                {
                    self.stats.rejected_over_limit =
                        self.stats.rejected_over_limit.saturating_add(1);
                    return Err(FragError::TooManyReassemblies);
                }
                let want = usize::from(h.total);
                if self.buffered_bytes + want > self.limits.max_buffered_bytes {
                    self.stats.rejected_over_limit =
                        self.stats.rejected_over_limit.saturating_add(1);
                    return Err(FragError::BufferBudgetExhausted);
                }
                // The allocation is exactly the declared total, which
                // `FragHeader::decode` has already bounded by MAX_FRAME_BYTES.
                self.buffered_bytes += want;
                self.partials.push((
                    link,
                    Partial {
                        xid: h.xid,
                        cnt: h.cnt,
                        total: h.total,
                        buf: vec![0u8; want],
                        have: 0,
                        received: 0,
                        started: now,
                    },
                ));
                self.stats.peak_reassemblies =
                    self.stats.peak_reassemblies.max(self.partials.len());
                self.stats.peak_buffered_bytes =
                    self.stats.peak_buffered_bytes.max(self.buffered_bytes);
                self.partials.len() - 1
            }
        };

        let bit = 1u128 << u32::from(h.idx);
        {
            let p = &mut self.partials[slot].1;
            if p.have & bit != 0 {
                self.stats.duplicates = self.stats.duplicates.saturating_add(1);
                return Ok(Reassembled::Duplicate);
            }
            // `end <= total == buf.len()` by construction of `range`.
            p.buf[start..end].copy_from_slice(payload);
            p.have |= bit;
            p.received = p.received.saturating_add(1);
            if !p.complete() {
                return Ok(Reassembled::Partial);
            }
        }

        let (_, done) = self.partials.swap_remove(slot);
        self.buffered_bytes = self.buffered_bytes.saturating_sub(done.buf.len());
        self.finish_bytes(done.buf)
    }

    /// Parse a fully reassembled frame.
    ///
    /// Note what this means for hard rule 4: a frame is parsed and structurally
    /// validated here, before anything above this layer — including the relay
    /// decision — sees it. Bridgefy forwarded unparsed bytes and turned one
    /// malformed message into a network-wide outage.
    fn finish_bytes(&mut self, bytes: Vec<u8>) -> Result<Reassembled, FragError> {
        match Frame::decode(&bytes) {
            Ok(f) => {
                self.stats.frames_out = self.stats.frames_out.saturating_add(1);
                Ok(Reassembled::Frame(f))
            }
            Err(e) => {
                self.stats.rejected_malformed = self.stats.rejected_malformed.saturating_add(1);
                Err(FragError::Wire(e))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::SplitMix64;
    use gdc_wire::{ChanTag, Flags, Kind, MsgId};

    fn frame(payload_len: usize) -> Frame {
        Frame::new(
            Kind::ChannelMsg,
            Flags::empty(),
            7,
            MsgId([3u8; 16]),
            ChanTag([4u8; 8]),
            &vec![0xA5u8; payload_len],
            &mut |b| b.fill(0x5A),
        )
        .expect("frame")
    }

    fn roundtrip(payload_len: usize, datagram: usize) {
        let f = frame(payload_len);
        let bytes = f.encode();
        let mut rng = SplitMix64::new(1);
        let limits = FragLimits::default();
        let dgs = fragment(&bytes, datagram, &limits, &mut rng).expect("fragment");
        assert!(
            dgs.iter().all(|d| d.len() <= datagram),
            "a fragment exceeded the link datagram size"
        );
        let mut r = Reassembler::new(limits);
        let mut got = None;
        for (i, d) in dgs.iter().enumerate() {
            match r.accept(LinkId(1), d, Millis(100)).expect("accept") {
                Reassembled::Frame(out) => {
                    assert_eq!(i, dgs.len() - 1, "completed early");
                    got = Some(out);
                }
                Reassembled::Partial => {}
                Reassembled::Duplicate => panic!("unexpected duplicate"),
            }
        }
        assert_eq!(got.expect("a frame"), f, "payload={payload_len} dg={datagram}");
        assert_eq!(r.in_flight(), 0, "state leaked after completion");
        assert_eq!(r.buffered_bytes(), 0, "bytes leaked after completion");
    }

    #[test]
    fn roundtrip_at_the_twenty_three_byte_worst_case() {
        // ATT MTU 23 - 3 ATT overhead = 20 bytes per datagram, 14 of payload.
        // This is the case everything else is designed around.
        for bucket in BUCKETS {
            roundtrip(bucket as usize, MIN_DATAGRAM);
        }
    }

    #[test]
    fn roundtrip_across_every_plausible_mtu() {
        for dg in [20usize, 21, 27, 100, 182, 244, 517, 1056, 2000] {
            for payload in [1usize, 63, 64, 65, 500, 1023, 1024] {
                roundtrip(payload, dg);
            }
        }
    }

    #[test]
    fn the_largest_frame_at_the_smallest_mtu_fits_the_fragment_limit() {
        let f = frame(1024);
        let bytes = f.encode();
        assert_eq!(bytes.len(), MAX_FRAME_BYTES);
        let mut rng = SplitMix64::new(9);
        let dgs = fragment(&bytes, MIN_DATAGRAM, &FragLimits::default(), &mut rng).unwrap();
        assert_eq!(dgs.len(), MAX_FRAME_BYTES.div_ceil(MIN_FRAG_PAYLOAD));
        assert_eq!(dgs.len(), 76);
        assert!(dgs.len() <= usize::from(FragLimits::default().max_fragments));
    }

    #[test]
    fn out_of_order_and_duplicate_delivery_still_reassembles() {
        let f = frame(512);
        let bytes = f.encode();
        let mut rng = SplitMix64::new(2);
        let mut dgs = fragment(&bytes, 40, &FragLimits::default(), &mut rng).unwrap();
        dgs.reverse();
        let mut r = Reassembler::new(FragLimits::default());
        // Feed every fragment twice, backwards.
        let mut frames = 0;
        let mut dups = 0;
        for d in dgs.iter().chain(dgs.iter()) {
            match r.accept(LinkId(7), d, Millis(0)).unwrap() {
                Reassembled::Frame(out) => {
                    assert_eq!(out, f);
                    frames += 1;
                }
                Reassembled::Duplicate => dups += 1,
                Reassembled::Partial => {}
            }
        }
        assert_eq!(frames, 1, "exactly one frame out");
        // The second pass's fragments arrive after the message completed, so
        // they start a fresh partial rather than being counted as duplicates of
        // a finished one. What matters is that no second frame came out and
        // nothing is unbounded.
        assert!(dups + r.in_flight() > 0);
    }

    // ---- hostile input: every bound must actually bound ----

    #[test]
    fn a_short_datagram_is_an_error_not_a_panic() {
        let mut r = Reassembler::new(FragLimits::default());
        for n in 0..FRAG_HEADER_LEN {
            let dg = vec![0xFFu8; n];
            assert!(matches!(
                r.accept(LinkId(1), &dg, Millis(0)),
                Err(FragError::ShortDatagram { .. })
            ));
        }
    }

    #[test]
    fn declared_total_above_the_frame_ceiling_is_refused_before_allocating() {
        let mut r = Reassembler::new(FragLimits::default());
        // total = 65535, cnt = 80. If this allocated, a single datagram would
        // cost 64 kB and eighty peers would cost 5 MB.
        let h = FragHeader {
            xid: 1,
            idx: 0,
            cnt: 80,
            total: u16::MAX,
        };
        let mut dg = h.encode().to_vec();
        dg.extend_from_slice(&[0u8; 14]);
        assert!(matches!(
            r.accept(LinkId(1), &dg, Millis(0)),
            Err(FragError::TotalTooLarge { .. })
        ));
        assert_eq!(r.buffered_bytes(), 0);
        assert_eq!(r.in_flight(), 0);
    }

    #[test]
    fn zero_count_and_out_of_range_index_are_refused() {
        let mut r = Reassembler::new(FragLimits::default());
        for (idx, cnt, total) in [(0u8, 0u8, 100u16), (5, 5, 100), (200, 3, 100), (0, 3, 0)] {
            let h = FragHeader { xid: 1, idx, cnt, total };
            let mut dg = h.encode().to_vec();
            dg.extend_from_slice(&[0u8; 14]);
            assert!(
                r.accept(LinkId(1), &dg, Millis(0)).is_err(),
                "idx={idx} cnt={cnt} total={total} was accepted"
            );
        }
        assert_eq!(r.in_flight(), 0);
    }

    #[test]
    fn overlapping_fragments_are_unrepresentable() {
        // Non-canonical geometry — a count that does not match the stride the
        // total implies — is the only way to express an overlap, and it is
        // rejected at parse time.
        let mut r = Reassembler::new(FragLimits::default());
        // total=100, cnt=50 implies stride=2 and a canonical count of 50: fine.
        let ok = FragHeader { xid: 1, idx: 0, cnt: 50, total: 100 };
        assert!(FragHeader::decode(&ok.encode()).is_ok());
        // total=100, cnt=80 implies stride=ceil(100/80)=2, whose canonical
        // count is 50, not 80. Rejected.
        let bad = FragHeader { xid: 1, idx: 0, cnt: 80, total: 100 };
        let mut dg = bad.encode().to_vec();
        dg.extend_from_slice(&[0u8; 2]);
        assert!(matches!(
            r.accept(LinkId(1), &dg, Millis(0)),
            Err(FragError::NonCanonicalGeometry)
        ));
    }

    #[test]
    fn a_fragment_that_underfills_its_range_is_refused() {
        let mut r = Reassembler::new(FragLimits::default());
        // total=100, cnt=10 -> stride 10, so fragment 0 must carry exactly 10
        // bytes. Offer 3.
        let h = FragHeader { xid: 1, idx: 0, cnt: 10, total: 100 };
        let mut dg = h.encode().to_vec();
        dg.extend_from_slice(&[0u8; 3]);
        assert!(matches!(
            r.accept(LinkId(1), &dg, Millis(0)),
            Err(FragError::PayloadLengthMismatch)
        ));
    }

    #[test]
    fn changing_geometry_mid_transfer_is_refused() {
        let mut r = Reassembler::new(FragLimits::default());
        let a = FragHeader { xid: 42, idx: 0, cnt: 10, total: 100 };
        let mut dg = a.encode().to_vec();
        dg.extend_from_slice(&[1u8; 10]);
        assert_eq!(
            r.accept(LinkId(1), &dg, Millis(0)).unwrap(),
            Reassembled::Partial
        );
        // Same xid, same link, different declared geometry.
        let b = FragHeader { xid: 42, idx: 1, cnt: 20, total: 200 };
        let mut dg2 = b.encode().to_vec();
        dg2.extend_from_slice(&[2u8; 10]);
        assert!(matches!(
            r.accept(LinkId(1), &dg2, Millis(0)),
            Err(FragError::GeometryConflict)
        ));
        assert_eq!(r.in_flight(), 1, "the conflicting fragment created no slot");
    }

    #[test]
    fn fragment_count_above_the_limit_is_refused() {
        let limits = FragLimits {
            max_fragments: 8,
            ..FragLimits::default()
        };
        let mut r = Reassembler::new(limits);
        // total=90, cnt=9 is canonical (stride 10) but over the cap of 8.
        let h = FragHeader { xid: 1, idx: 0, cnt: 9, total: 90 };
        let mut dg = h.encode().to_vec();
        dg.extend_from_slice(&[0u8; 10]);
        assert!(matches!(
            r.accept(LinkId(1), &dg, Millis(0)),
            Err(FragError::TooManyFragments(9))
        ));
        assert_eq!(r.in_flight(), 0);
    }

    #[test]
    fn concurrent_reassembly_count_is_bounded_per_link_and_overall() {
        let limits = FragLimits {
            max_reassemblies_per_link: 3,
            max_reassemblies_total: 5,
            ..FragLimits::default()
        };
        let mut r = Reassembler::new(limits);
        // One hostile peer opens as many transfers as it can.
        let mut refused = 0;
        for xid in 0..200u16 {
            let h = FragHeader { xid, idx: 0, cnt: 10, total: 100 };
            let mut dg = h.encode().to_vec();
            dg.extend_from_slice(&[0u8; 10]);
            if r.accept(LinkId(1), &dg, Millis(0)).is_err() {
                refused += 1;
            }
        }
        assert!(refused > 190);
        assert_eq!(r.in_flight(), 3, "per-link bound did not bind");

        // A crowd of peers, one transfer each, hits the global bound.
        for link in 2..50u32 {
            let h = FragHeader { xid: 1, idx: 0, cnt: 10, total: 100 };
            let mut dg = h.encode().to_vec();
            dg.extend_from_slice(&[0u8; 10]);
            let _ = r.accept(LinkId(link), &dg, Millis(0));
        }
        assert_eq!(r.in_flight(), 5, "global bound did not bind");
        assert!(r.stats().peak_reassemblies <= 5);
    }

    #[test]
    fn buffered_bytes_are_bounded_under_a_flood() {
        // Generous slot counts, tight byte budget: the byte budget must be the
        // thing that binds, because it is the one that maps to memory.
        let limits = FragLimits {
            max_reassemblies_per_link: 64,
            max_reassemblies_total: 1024,
            max_buffered_bytes: 4096,
            ..FragLimits::default()
        };
        let mut r = Reassembler::new(limits);
        for link in 0..64u32 {
            for xid in 0..64u16 {
                // Each opens a 1056-byte reassembly: 4096 of combined ceiling
                // allows three.
                let h = FragHeader {
                    xid,
                    idx: 0,
                    cnt: 76,
                    total: MAX_FRAME_BYTES as u16,
                };
                let mut dg = h.encode().to_vec();
                dg.extend_from_slice(&[0u8; 14]);
                let _ = r.accept(LinkId(link), &dg, Millis(0));
            }
        }
        assert!(
            r.buffered_bytes() <= 4096,
            "buffered {} bytes over a 4096 ceiling",
            r.buffered_bytes()
        );
        assert!(r.stats().peak_buffered_bytes <= 4096);
        assert!(r.stats().rejected_over_limit > 0, "the bound was never hit");
    }

    #[test]
    fn the_timeout_runs_from_the_first_fragment_not_the_last() {
        // The refresh attack: dribble one duplicate per period and the slot
        // would live for ever if the timeout were refreshed on arrival.
        let limits = FragLimits {
            reassembly_timeout: Millis(1_000),
            max_reassemblies_per_link: 1,
            ..FragLimits::default()
        };
        let mut r = Reassembler::new(limits);
        let h = FragHeader { xid: 1, idx: 0, cnt: 10, total: 100 };
        let mut dg = h.encode().to_vec();
        dg.extend_from_slice(&[0u8; 10]);
        assert_eq!(
            r.accept(LinkId(1), &dg, Millis(0)).unwrap(),
            Reassembled::Partial
        );
        // Keep poking it just inside the timeout window.
        for t in [100u64, 200, 300, 900] {
            let _ = r.accept(LinkId(1), &dg, Millis(t));
        }
        assert_eq!(r.in_flight(), 1);
        // One tick past the timeout measured from the FIRST fragment.
        r.expire(Millis(1_000));
        assert_eq!(r.in_flight(), 0, "the slot was held open by duplicates");
        assert_eq!(r.buffered_bytes(), 0);
        assert_eq!(r.stats().timed_out, 1);
    }

    #[test]
    fn a_dropped_link_releases_its_state_immediately() {
        let mut r = Reassembler::new(FragLimits::default());
        for link in 1..4u32 {
            let h = FragHeader { xid: 1, idx: 0, cnt: 10, total: 100 };
            let mut dg = h.encode().to_vec();
            dg.extend_from_slice(&[0u8; 10]);
            r.accept(LinkId(link), &dg, Millis(0)).unwrap();
        }
        assert_eq!(r.in_flight(), 3);
        r.drop_link(LinkId(2));
        assert_eq!(r.in_flight(), 2);
        assert_eq!(r.buffered_bytes(), 200);
        r.wipe();
        assert_eq!(r.in_flight(), 0);
        assert_eq!(r.buffered_bytes(), 0);
    }

    #[test]
    fn a_reassembled_but_invalid_frame_is_rejected_not_forwarded() {
        // Hard rule 4: parse before relay. A complete reassembly of garbage
        // must come back as an error, never as a Frame the caller might relay.
        let mut r = Reassembler::new(FragLimits::default());
        let h = FragHeader { xid: 1, idx: 0, cnt: 1, total: 40 };
        let mut dg = h.encode().to_vec();
        dg.extend_from_slice(&[0xFFu8; 40]);
        assert!(matches!(
            r.accept(LinkId(1), &dg, Millis(0)),
            Err(FragError::Wire(_))
        ));
        assert_eq!(r.stats().frames_out, 0);
    }

    #[test]
    fn single_fragment_messages_never_consume_a_slot() {
        // Otherwise a flood of valid one-datagram frames would exhaust the
        // reassembly table as effectively as a flood of partials.
        let f = frame(1);
        let bytes = f.encode();
        assert!(bytes.len() <= 2000);
        let mut rng = SplitMix64::new(3);
        let dgs = fragment(&bytes, 2000, &FragLimits::default(), &mut rng).unwrap();
        assert_eq!(dgs.len(), 1);
        let mut r = Reassembler::new(FragLimits::default());
        for _ in 0..1000 {
            assert!(matches!(
                r.accept(LinkId(1), &dgs[0], Millis(0)),
                Ok(Reassembled::Frame(_))
            ));
        }
        assert_eq!(r.in_flight(), 0);
        assert_eq!(r.buffered_bytes(), 0);
    }

    #[test]
    fn fragmenting_refuses_an_impossible_link() {
        let mut rng = SplitMix64::new(4);
        let limits = FragLimits::default();
        let bytes = frame(64).encode();
        for dg in 0..MIN_DATAGRAM {
            assert!(matches!(
                fragment(&bytes, dg, &limits, &mut rng),
                Err(FragError::DatagramTooSmall(_))
            ));
        }
        // And refuses a message that cannot be covered within max_fragments.
        let tight = FragLimits {
            max_fragments: 4,
            ..limits
        };
        assert!(matches!(
            fragment(&bytes, MIN_DATAGRAM, &tight, &mut rng),
            Err(FragError::MessageTooLarge(_))
        ));
        // And an empty or oversized message.
        assert!(fragment(&[], 244, &limits, &mut rng).is_err());
        assert!(fragment(&vec![0u8; MAX_FRAME_BYTES + 1], 244, &limits, &mut rng).is_err());
    }

    #[test]
    fn fuzzish_sweep_of_hostile_headers_never_panics_and_stays_bounded() {
        // Not a real fuzz target — that belongs in the harness — but a wide
        // deterministic sweep over the whole attacker-controlled header space
        // with mismatched payload lengths.
        let limits = FragLimits::default();
        let mut r = Reassembler::new(limits);
        let mut rng = SplitMix64::new(0xDEAD_BEEF);
        for i in 0..200_000u32 {
            let mut dg = Vec::with_capacity(32);
            dg.extend_from_slice(&(rng.next_u32() as u16).to_le_bytes());
            dg.push((rng.next_u32() & 0xFF) as u8);
            dg.push((rng.next_u32() & 0xFF) as u8);
            dg.extend_from_slice(&(rng.next_u32() as u16).to_le_bytes());
            let plen = (rng.next_u32() % 40) as usize;
            dg.resize(FRAG_HEADER_LEN + plen, 0x5A);
            let _ = r.accept(LinkId(i % 8), &dg, Millis(u64::from(i)));
            assert!(r.in_flight() <= limits.max_reassemblies_total);
            assert!(r.buffered_bytes() <= limits.max_buffered_bytes);
        }
        assert!(r.stats().datagrams_in == 200_000);
    }
}
