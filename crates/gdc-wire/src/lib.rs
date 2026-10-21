//! The on-wire contract. Owned by the orchestrator, depended on by every piece.
//!
//! Changing anything in here requires agreement from the transport, routing and
//! crypto builders, because all three are pinned to it.
//!
//! Two rules from `docs/research/BRIDGEFY-FINDINGS.md` are enforced structurally
//! here rather than left to reviewer diligence:
//!
//! * A frame's on-wire length is drawn from a fixed ladder of buckets and never
//!   varies with payload content, so length carries no information about the
//!   plaintext. This is the structural answer to the compression side channel
//!   that recovered Bridgefy's broadcast plaintext.
//! * Nothing in the cleartext header identifies a person, a device or a
//!   conversation. Relays get exactly what they need to drop duplicates and
//!   decrement a hop counter, and not one byte more.

#![forbid(unsafe_code)]

use core::fmt;

/// Wire format version. Bump on any incompatible change below.
pub const WIRE_VERSION: u8 = 1;

/// Cleartext header length in bytes.
pub const HEADER_LEN: usize = 32;

/// Ciphertext size ladder. Every frame body is padded up to one of these.
///
/// Chosen so the common cases land in the bottom two rungs: a canned-pad
/// selection plus a location pin fits in 64, and the great majority of typed
/// messages fit in 256. The 1024 rung exists for fragment carriers and sync
/// digests, not for user text.
pub const BUCKETS: [u16; 5] = [64, 128, 256, 512, 1024];

/// Hard ceiling on any decompression or expansion step, anywhere in the stack.
///
/// Bridgefy's decompression bomb worked because no such ceiling existed. This
/// constant exists so that the limit is one number, in one place, that a fuzz
/// target can assert against.
pub const MAX_EXPANDED_LEN: usize = 4096;

/// Largest user-visible message body, in bytes of UTF-8.
pub const MAX_BODY_LEN: usize = 500;

/// Default hop limit.
///
/// Bridgefy ships 100 by default and 250 on its Long Reach profile, with no
/// degree awareness, which is why its flood collapses under density. We start
/// from a small number and earn any increase with measurements.
pub const DEFAULT_TTL: u8 = 7;

/// Absolute hop ceiling. A frame arriving with more than this is dropped, not
/// clamped, because an inflated TTL is a flooding attack.
pub const MAX_TTL: u8 = 12;

/// How long a channel tag stays valid. Tags rotate so that a passive observer
/// cannot link a channel's traffic across epochs.
pub const TAG_EPOCH_SECS: u64 = 3600;

/// Frame kinds. Cleartext, because a relay must route without decrypting.
///
/// This is a deliberate, bounded metadata disclosure: an observer learns the
/// shape of traffic but not its channel, its author or its content.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Kind {
    /// A message addressed to a channel.
    ChannelMsg = 0,
    /// Liveness beacon that populates the roster.
    Presence = 1,
    /// A sealed envelope being carried for a channel that is not reachable yet.
    Courier = 2,
    /// Set-reconciliation digest for backlog sync between two peers.
    Sync = 3,
    /// Session establishment. Never relayed; direct link only.
    Handshake = 4,
    /// One piece of a frame too large for the link MTU.
    Fragment = 5,
}

impl Kind {
    pub fn from_u8(v: u8) -> Result<Self, WireError> {
        Ok(match v {
            0 => Kind::ChannelMsg,
            1 => Kind::Presence,
            2 => Kind::Courier,
            3 => Kind::Sync,
            4 => Kind::Handshake,
            5 => Kind::Fragment,
            other => return Err(WireError::UnknownKind(other)),
        })
    }

    /// Whether a relay is permitted to forward this kind at all.
    ///
    /// Handshakes are excluded: a session may only be established across a link
    /// both parties can see, never through an intermediary who could substitute
    /// keys. That is the structural answer to the attacker-in-the-middle finding.
    pub fn is_relayable(self) -> bool {
        !matches!(self, Kind::Handshake)
    }
}

bitflags_lite! {
    /// Cleartext flags. Keep this set small; every bit is metadata.
    pub struct Flags: u8 {
        /// Author asserts this is life-safety traffic. Schedulers may prioritise
        /// it. Unauthenticated by nature, so it buys priority, never trust.
        const URGENT      = 0b0000_0001;
        /// Sender wants an acknowledgement from the channel.
        const WANT_ACK    = 0b0000_0010;
        /// This frame has already been held by at least one carrier, i.e. it
        /// travelled in a pocket rather than over a live link.
        const WAS_CARRIED = 0b0000_0100;
    }
}

/// A 16-byte random per-message identifier used solely for duplicate
/// suppression.
///
/// It is unlinkable to a device or a person: fresh randomness per message, never
/// derived from identity. It must be random rather than a content hash, because
/// a content hash would let an observer confirm a guessed plaintext.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct MsgId(pub [u8; 16]);

/// An 8-byte rotating channel tag.
///
/// Computed by the crypto layer as a MAC over the current epoch under the
/// channel key. A relay matches tags to decide whether it holds a frame for a
/// channel it knows, without learning which channel a tag denotes, and without
/// being able to correlate the same channel across epochs.
///
/// This replaces the cleartext sender/receiver pair that gave Bridgefy's
/// observers a social graph for free.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ChanTag(pub [u8; 8]);

impl fmt::Debug for ChanTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChanTag({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

/// The cleartext part of a frame, exactly [`HEADER_LEN`] bytes on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    pub ver: u8,
    pub kind: Kind,
    pub flags: Flags,
    /// Mutable in flight. Deliberately excluded from the authenticated data, so
    /// a relay can decrement it without invalidating the author's signature.
    pub ttl: u8,
    /// Index into [`BUCKETS`].
    pub bucket: u8,
    pub msg_id: MsgId,
    pub tag: ChanTag,
}

impl Header {
    pub fn body_len(&self) -> Result<usize, WireError> {
        BUCKETS
            .get(self.bucket as usize)
            .map(|b| *b as usize)
            .ok_or(WireError::BadBucket(self.bucket))
    }

    /// The bytes a signature and an AEAD cover.
    ///
    /// `ttl` is zeroed so that hop-by-hop mutation does not break end-to-end
    /// authentication, and `bucket` is included so an attacker cannot relabel a
    /// frame into a different size class.
    pub fn aad(&self) -> [u8; HEADER_LEN] {
        let mut out = self.encode();
        out[3] = 0;
        out
    }

    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0] = self.ver;
        out[1] = self.kind as u8;
        out[2] = self.flags.bits();
        out[3] = self.ttl;
        out[4] = self.bucket;
        out[5..21].copy_from_slice(&self.msg_id.0);
        out[21..29].copy_from_slice(&self.tag.0);
        // out[29..32] reserved, must be zero on the wire so it cannot be used
        // as a covert channel by a modified client.
        out
    }

    pub fn decode(src: &[u8]) -> Result<Self, WireError> {
        if src.len() < HEADER_LEN {
            return Err(WireError::Truncated {
                need: HEADER_LEN,
                got: src.len(),
            });
        }
        if src[0] != WIRE_VERSION {
            return Err(WireError::BadVersion(src[0]));
        }
        if src[29..32] != [0, 0, 0] {
            return Err(WireError::ReservedNotZero);
        }
        let ttl = src[3];
        if ttl > MAX_TTL {
            return Err(WireError::TtlTooHigh(ttl));
        }
        let bucket = src[4];
        if bucket as usize >= BUCKETS.len() {
            return Err(WireError::BadBucket(bucket));
        }
        let mut msg_id = [0u8; 16];
        msg_id.copy_from_slice(&src[5..21]);
        let mut tag = [0u8; 8];
        tag.copy_from_slice(&src[21..29]);
        Ok(Header {
            ver: src[0],
            kind: Kind::from_u8(src[1])?,
            flags: Flags::from_bits_truncate(src[2]),
            ttl,
            bucket,
            msg_id: MsgId(msg_id),
            tag: ChanTag(tag),
        })
    }
}

/// Pick the smallest bucket that fits `n` bytes of ciphertext.
pub fn bucket_for(n: usize) -> Result<u8, WireError> {
    BUCKETS
        .iter()
        .position(|b| (*b as usize) >= n)
        .map(|i| i as u8)
        .ok_or(WireError::TooLarge(n))
}

/// A complete frame: cleartext header plus an exactly-bucket-sized body.
///
/// The invariant that `body.len()` equals the bucket size is upheld at
/// construction, so no code path can emit a content-length-revealing frame.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Frame {
    pub hdr: Header,
    body: Vec<u8>,
}

impl Frame {
    /// Build a frame, padding `ciphertext` up to its bucket with `filler`.
    ///
    /// `filler` must come from a CSPRNG. Zero padding would be visible as such
    /// to anyone who later recovers a key, and would make a compression oracle
    /// possible again if any future layer compressed a frame.
    pub fn new(
        kind: Kind,
        flags: Flags,
        ttl: u8,
        msg_id: MsgId,
        tag: ChanTag,
        ciphertext: &[u8],
        filler: &mut dyn FnMut(&mut [u8]),
    ) -> Result<Self, WireError> {
        if ttl > MAX_TTL {
            return Err(WireError::TtlTooHigh(ttl));
        }
        let bucket = bucket_for(ciphertext.len())?;
        let want = BUCKETS[bucket as usize] as usize;
        let mut body = vec![0u8; want];
        body[..ciphertext.len()].copy_from_slice(ciphertext);
        filler(&mut body[ciphertext.len()..]);
        Ok(Frame {
            hdr: Header {
                ver: WIRE_VERSION,
                kind,
                flags,
                ttl,
                bucket,
                msg_id,
                tag,
            },
            body,
        })
    }

    pub fn body(&self) -> &[u8] {
        &self.body
    }

    pub fn wire_len(&self) -> usize {
        HEADER_LEN + self.body.len()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.wire_len());
        out.extend_from_slice(&self.hdr.encode());
        out.extend_from_slice(&self.body);
        out
    }

    pub fn decode(src: &[u8]) -> Result<Self, WireError> {
        let hdr = Header::decode(src)?;
        let want = hdr.body_len()?;
        let total = HEADER_LEN + want;
        // Exact length, not "at least". A frame carrying trailing bytes is
        // either a bug or someone probing for a parser seam.
        if src.len() != total {
            return Err(WireError::LengthMismatch {
                declared: total,
                got: src.len(),
            });
        }
        Ok(Frame {
            hdr,
            body: src[HEADER_LEN..].to_vec(),
        })
    }

    /// Decrement the hop counter for forwarding.
    ///
    /// Returns `None` when the frame has reached the end of its life, so the
    /// caller cannot accidentally forward a dead frame by ignoring a bool.
    pub fn forwarded(&self) -> Option<Frame> {
        if !self.hdr.kind.is_relayable() || self.hdr.ttl == 0 {
            return None;
        }
        let mut next = self.clone();
        next.hdr.ttl -= 1;
        if next.hdr.ttl == 0 {
            return None;
        }
        Some(next)
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    #[error("truncated: need {need} bytes, got {got}")]
    Truncated { need: usize, got: usize },
    #[error("declared length {declared} but got {got}")]
    LengthMismatch { declared: usize, got: usize },
    #[error("unsupported wire version {0}")]
    BadVersion(u8),
    #[error("unknown frame kind {0}")]
    UnknownKind(u8),
    #[error("invalid bucket index {0}")]
    BadBucket(u8),
    #[error("ttl {0} exceeds the ceiling")]
    TtlTooHigh(u8),
    #[error("reserved header bytes must be zero")]
    ReservedNotZero,
    #[error("{0} bytes exceeds the largest bucket")]
    TooLarge(usize),
}

/// A three-line stand-in for the `bitflags` crate, so that `gdc-wire` stays
/// dependency-free apart from `thiserror`. Everything else in the workspace
/// depends on this crate, so its dependency surface is everyone's.
#[macro_export]
macro_rules! bitflags_lite {
    (
        $(#[$m:meta])* pub struct $name:ident : $t:ty {
            $( $(#[$fm:meta])* const $f:ident = $v:expr; )*
        }
    ) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
        pub struct $name($t);
        impl $name {
            $( $(#[$fm])* pub const $f: $name = $name($v); )*
            pub const fn empty() -> Self { $name(0) }
            pub const fn bits(self) -> $t { self.0 }
            pub const fn from_bits_truncate(b: $t) -> Self {
                $name(b & ( 0 $( | $v )* ))
            }
            pub const fn contains(self, o: Self) -> bool { self.0 & o.0 == o.0 }
            pub const fn union(self, o: Self) -> Self { $name(self.0 | o.0) }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn zero_fill(b: &mut [u8]) {
        b.fill(0)
    }

    fn hdr(ttl: u8) -> Header {
        Header {
            ver: WIRE_VERSION,
            kind: Kind::ChannelMsg,
            flags: Flags::empty(),
            ttl,
            bucket: 0,
            msg_id: MsgId([7u8; 16]),
            tag: ChanTag([9u8; 8]),
        }
    }

    #[test]
    fn header_roundtrips() {
        let h = hdr(5);
        assert_eq!(Header::decode(&h.encode()).unwrap(), h);
    }

    #[test]
    fn aad_ignores_ttl_but_not_bucket() {
        let a = hdr(5);
        let mut b = a;
        b.ttl = 2;
        assert_eq!(a.aad(), b.aad(), "ttl must not be authenticated");
        let mut c = a;
        c.bucket = 1;
        assert_ne!(a.aad(), c.aad(), "bucket must be authenticated");
    }

    #[test]
    fn length_never_reveals_payload_length() {
        // The whole point of the bucket ladder: two payloads of very different
        // sizes inside one bucket are indistinguishable on the wire.
        let short = Frame::new(
            Kind::ChannelMsg, Flags::empty(), 7, MsgId([1; 16]), ChanTag([2; 8]),
            &[0xAA; 1], &mut zero_fill,
        ).unwrap();
        let long = Frame::new(
            Kind::ChannelMsg, Flags::empty(), 7, MsgId([1; 16]), ChanTag([2; 8]),
            &[0xAA; 64], &mut zero_fill,
        ).unwrap();
        assert_eq!(short.wire_len(), long.wire_len());
        assert_eq!(short.wire_len(), HEADER_LEN + 64);
    }

    #[test]
    fn every_bucket_is_reachable_and_exact() {
        for (i, b) in BUCKETS.iter().enumerate() {
            let f = Frame::new(
                Kind::ChannelMsg, Flags::empty(), 7, MsgId([0; 16]), ChanTag([0; 8]),
                &vec![1u8; *b as usize], &mut zero_fill,
            ).unwrap();
            assert_eq!(f.hdr.bucket, i as u8);
            assert_eq!(f.wire_len(), HEADER_LEN + *b as usize);
            assert_eq!(Frame::decode(&f.encode()).unwrap(), f);
        }
    }

    #[test]
    fn oversize_payload_is_refused() {
        let too_big = vec![0u8; *BUCKETS.last().unwrap() as usize + 1];
        assert!(matches!(
            Frame::new(Kind::ChannelMsg, Flags::empty(), 7, MsgId([0; 16]),
                       ChanTag([0; 8]), &too_big, &mut zero_fill),
            Err(WireError::TooLarge(_))
        ));
    }

    #[test]
    fn inflated_ttl_is_rejected_not_clamped() {
        let mut raw = hdr(0).encode();
        raw[3] = MAX_TTL + 1;
        assert_eq!(Header::decode(&raw), Err(WireError::TtlTooHigh(MAX_TTL + 1)));
    }

    #[test]
    fn reserved_bytes_cannot_carry_data() {
        let mut raw = hdr(3).encode();
        raw[30] = 0x01;
        assert_eq!(Header::decode(&raw), Err(WireError::ReservedNotZero));
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let f = Frame::new(
            Kind::ChannelMsg, Flags::empty(), 7, MsgId([0; 16]), ChanTag([0; 8]),
            &[0u8; 8], &mut zero_fill,
        ).unwrap();
        let mut raw = f.encode();
        raw.push(0);
        assert!(matches!(Frame::decode(&raw), Err(WireError::LengthMismatch { .. })));
    }

    #[test]
    fn forwarding_stops_at_zero_and_never_wraps() {
        let f = Frame::new(
            Kind::ChannelMsg, Flags::empty(), 2, MsgId([0; 16]), ChanTag([0; 8]),
            &[0u8; 4], &mut zero_fill,
        ).unwrap();
        let once = f.forwarded().expect("ttl 2 -> 1");
        assert_eq!(once.hdr.ttl, 1);
        assert!(once.forwarded().is_none(), "must not emit a ttl-0 frame");
    }

    #[test]
    fn handshakes_are_never_relayable() {
        let f = Frame::new(
            Kind::Handshake, Flags::empty(), 7, MsgId([0; 16]), ChanTag([0; 8]),
            &[0u8; 4], &mut zero_fill,
        ).unwrap();
        assert!(f.forwarded().is_none(), "a relay must not carry a handshake");
    }

    #[test]
    fn header_is_exactly_the_declared_size() {
        assert_eq!(hdr(1).encode().len(), HEADER_LEN);
    }
}
