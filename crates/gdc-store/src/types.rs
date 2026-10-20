//! Small shared types, the injected-time contract, and the injected randomness
//! contract.
//!
//! Time is the subject matter of this crate, so there is no call to a system
//! clock anywhere in it. Every entry point takes `now: Millis` from the caller.
//! That is a stronger guarantee than holding a `Clock` object, because it is
//! visible in every signature and a test cannot be fooled by a hidden default.

use crate::limits::{NOVELTY_BITS, NOVELTY_HASHES, SOURCE_CLASSES};

/// Milliseconds on a monotonic timeline whose origin is the session start.
///
/// Monotonic, not wall clock: a session cannot outlive a wipe, and the tag
/// epoch (which *is* wall-clock derived) enters this crate through
/// [`crate::tags::ChannelTags`] rather than through arithmetic here.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default, Hash)]
pub struct Millis(pub u64);

impl Millis {
    pub const ZERO: Millis = Millis(0);

    /// Saturating addition. A hostile or buggy caller offering `u64::MAX` must
    /// get a clamp, not a wrap into the past.
    #[must_use]
    pub fn plus(self, d: u64) -> Millis {
        Millis(self.0.saturating_add(d))
    }

    /// Elapsed time, floored at zero. Never panics on a clock that went
    /// backwards; the store additionally refuses to move its own clock back.
    #[must_use]
    pub fn since(self, earlier: Millis) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}

/// A clock, for the layers above that do have one.
///
/// This crate never constructs an implementation that reads ambient time; the
/// node assembly supplies one. [`TestClock`] exists so tests can drive it.
pub trait Clock {
    fn now(&self) -> Millis;
}

/// A settable clock for tests and for the deterministic harness.
#[derive(Clone, Debug, Default)]
pub struct TestClock {
    now: Millis,
}

impl TestClock {
    #[must_use]
    pub fn new(at: Millis) -> Self {
        TestClock { now: at }
    }
    pub fn set(&mut self, at: Millis) {
        self.now = at;
    }
    pub fn advance(&mut self, by: u64) {
        self.now = self.now.plus(by);
    }
}

impl Clock for TestClock {
    fn now(&self) -> Millis {
        self.now
    }
}

/// Randomness, injected.
///
/// In production this is wired to the crypto layer's CSPRNG. Nothing in this
/// crate uses randomness for a security decision — only for retry jitter and
/// for the local salts that keep stored metadata from being a readable record —
/// but it still must not come from an ambient source, because a test that
/// cannot pin the jitter cannot pin the schedule.
pub trait Rng {
    fn fill(&mut self, out: &mut [u8]);

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        u64::from_le_bytes(b)
    }

    /// Uniform-ish value in `0..n`. Modulo bias is irrelevant for jitter and
    /// this is never used to choose a key.
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }
}

/// A seeded generator so that every number this crate reports is reproducible.
#[derive(Clone, Debug)]
pub struct DetRng {
    state: u64,
}

impl DetRng {
    #[must_use]
    pub fn new(seed: u64) -> Self {
        // Any seed, including zero, must produce a usable stream.
        DetRng {
            state: seed ^ 0x9E37_79B9_7F4A_7C15,
        }
    }
}

impl Rng for DetRng {
    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let v = mix64(self.state).to_le_bytes();
            let n = chunk.len();
            chunk.copy_from_slice(&v[..n]);
        }
    }
}

/// SplitMix64 finalizer. Not a cryptographic hash and not used as one.
#[must_use]
pub fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// Keyed 64-bit hash over bytes.
///
/// Keyed with a per-session random salt wherever an adversary chooses the
/// input, so that neither the seen-log index nor the reconciliation filter can
/// be forced into a worst case or compared across devices offline.
#[must_use]
pub fn keyed_hash64(key: u64, bytes: &[u8]) -> u64 {
    let mut h = key ^ 0x517C_C1B7_2722_0A95;
    for chunk in bytes.chunks(8) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        h ^= u64::from_le_bytes(buf);
        h = mix64(h);
    }
    mix64(h ^ (bytes.len() as u64))
}

/// An ephemeral per-session peer identifier, as the crypto layer hands it over.
///
/// This crate never stores one. It converts to a [`SourceClass`] on the way in
/// and keeps only that.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct PeerId(pub [u8; 16]);

/// A six-bit fairness class derived from a peer id under a session-local salt.
///
/// Two properties matter. It is bounded by construction, so the eviction
/// bookkeeping is a fixed array that no peer set can grow. And it is almost no
/// information: a seized device shows that some envelope arrived in class 11,
/// not that it arrived from a named peer, and the salt dies with the session.
///
/// The cost is that roughly one peer in sixty-four shares a class with any
/// given peer, so a hostile peer can crowd one honest peer's share. That is a
/// deliberate trade and it is in the report.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub struct SourceClass(pub u8);

impl SourceClass {
    #[must_use]
    pub fn of(salt: u64, peer: PeerId) -> SourceClass {
        SourceClass((keyed_hash64(salt, &peer.0) % SOURCE_CLASSES as u64) as u8)
    }
    #[must_use]
    pub fn index(self) -> usize {
        (self.0 as usize) % SOURCE_CLASSES
    }
}

/// A fixed-size Bloom filter over salted peer ids, used only to answer "have I
/// met anyone like this before in this session".
///
/// Deliberately not a list of peers. When it saturates it starts answering
/// "yes" to everyone, which reads as *dense* — the direction in which a wrong
/// answer is safe, because dense means fewer copies and less of other people's
/// storage spent.
#[derive(Clone, Debug)]
pub struct NoveltyFilter {
    bits: Vec<u64>,
    salt: u64,
    inserted: u32,
}

impl NoveltyFilter {
    #[must_use]
    pub fn new(salt: u64) -> Self {
        NoveltyFilter {
            bits: vec![0u64; NOVELTY_BITS / 64],
            salt,
            inserted: 0,
        }
    }

    fn positions(&self, peer: PeerId) -> [usize; NOVELTY_HASHES] {
        let h1 = keyed_hash64(self.salt, &peer.0);
        let h2 = mix64(h1 | 1);
        let mut out = [0usize; NOVELTY_HASHES];
        for (i, slot) in out.iter_mut().enumerate() {
            let h = h1.wrapping_add((i as u64).wrapping_mul(h2));
            *slot = (h % NOVELTY_BITS as u64) as usize;
        }
        out
    }

    /// Record the peer and report whether it was new to this session.
    pub fn observe(&mut self, peer: PeerId) -> bool {
        let pos = self.positions(peer);
        let mut seen = true;
        for p in pos {
            let w = p / 64;
            let b = 1u64 << (p % 64);
            if self.bits[w] & b == 0 {
                seen = false;
                self.bits[w] |= b;
            }
        }
        if !seen {
            self.inserted = self.inserted.saturating_add(1);
        }
        !seen
    }

    #[must_use]
    pub fn distinct_seen(&self) -> u32 {
        self.inserted
    }

    /// Drop every record of who has been met. Called on panic wipe.
    pub fn wipe(&mut self) {
        self.bits.iter_mut().for_each(|w| *w = 0);
        self.inserted = 0;
    }
}
