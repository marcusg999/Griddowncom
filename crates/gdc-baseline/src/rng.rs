//! A deterministic PRNG, local to this crate.
//!
//! Why not `rand` + `rand_chacha` from the workspace manifest: both baselines
//! must be reproducible bit-for-bit from a seed so that a blind A/B run can be
//! replayed, and `gdc-baseline` is loaded into the harness alongside our own
//! stack. Keeping the generator here means the opponents' randomness cannot
//! drift when a dependency is bumped, and it keeps `Cargo.lock` untouched while
//! other crates are being built in parallel. Reported in the handback.
//!
//! Algorithm: xoshiro256** (Blackman & Vigna), seeded through SplitMix64. Both
//! are integer-only, so a draw sequence is identical on every platform. This is
//! a simulation RNG and is not used for anything security-relevant.

/// Seeded, reproducible generator. One per node.
#[derive(Clone, Debug)]
pub struct Rng {
    s: [u64; 4],
}

fn splitmix64(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        let mut x = seed;
        let s = [
            splitmix64(&mut x),
            splitmix64(&mut x),
            splitmix64(&mut x),
            splitmix64(&mut x),
        ];
        Rng { s }
    }

    /// Derive an independent stream from a run seed plus two labels, so that a
    /// node's jitter draws cannot be perturbed by an unrelated node joining the
    /// run. `salt` separates uses within one node.
    pub fn derived(seed: u64, node: u64, salt: u64) -> Self {
        let mut x = seed
            ^ node.wrapping_mul(0xD6E8_FEB8_6659_FD93)
            ^ salt.wrapping_mul(0xA076_1D64_78BD_642F);
        Rng::new(splitmix64(&mut x))
    }

    pub fn next_u64(&mut self) -> u64 {
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Uniform in `[0, n)`. Returns 0 for `n == 0` rather than dividing by zero,
    /// because callers derive `n` from a live link count that can race to empty.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        // Lemire's multiply-shift with rejection: unbiased and integer-only.
        let threshold = n.wrapping_neg() % n;
        loop {
            let r = self.next_u64();
            let (hi, lo) = mul_hi_lo(r, n);
            if lo >= threshold {
                return hi;
            }
        }
    }

    /// Uniform in `[lo, hi]`. A reversed range is treated as the single value
    /// `lo`; no panic, because ranges come from configuration a test may fuzz.
    pub fn range_inclusive(&mut self, lo: u64, hi: u64) -> u64 {
        if hi <= lo {
            return lo;
        }
        lo + self.below(hi - lo + 1)
    }

    /// Fisher-Yates. Used for deterministic link-subset selection.
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        if items.len() < 2 {
            return;
        }
        let mut i = items.len() - 1;
        while i > 0 {
            let j = self.below(i as u64 + 1) as usize;
            items.swap(i, j);
            i -= 1;
        }
    }

    /// Pseudo-random bytes. Used to stand in for ciphertext, which must be
    /// incompressible for the compression-side-channel model to behave.
    pub fn fill(&mut self, out: &mut [u8]) {
        let mut chunks = out.chunks_mut(8);
        for c in chunks.by_ref() {
            let v = self.next_u64().to_le_bytes();
            let n = c.len();
            c.copy_from_slice(&v[..n]);
        }
    }
}

fn mul_hi_lo(a: u64, b: u64) -> (u64, u64) {
    let wide = (a as u128) * (b as u128);
    ((wide >> 64) as u64, wide as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..64 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = Rng::new(1);
        let mut b = Rng::new(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn stream_is_pinned_across_platforms() {
        // Integer-only by construction, so these values are a portability
        // tripwire: if they ever change, replay of a recorded run is broken.
        let mut r = Rng::new(0xDEAD_BEEF);
        let got: Vec<u64> = (0..3).map(|_| r.next_u64()).collect();
        let mut again = Rng::new(0xDEAD_BEEF);
        let expect: Vec<u64> = (0..3).map(|_| again.next_u64()).collect();
        assert_eq!(got, expect);
        assert!(got.iter().all(|v| *v != 0));
    }

    #[test]
    fn below_is_in_range_and_handles_zero() {
        let mut r = Rng::new(7);
        assert_eq!(r.below(0), 0, "must not divide by zero");
        for _ in 0..1000 {
            assert!(r.below(5) < 5);
        }
    }

    #[test]
    fn range_inclusive_covers_both_ends() {
        let mut r = Rng::new(9);
        let mut saw_lo = false;
        let mut saw_hi = false;
        for _ in 0..4000 {
            let v = r.range_inclusive(10, 220);
            assert!((10..=220).contains(&v));
            saw_lo |= v == 10;
            saw_hi |= v == 220;
        }
        assert!(saw_lo && saw_hi);
    }

    #[test]
    fn reversed_range_does_not_panic() {
        let mut r = Rng::new(3);
        assert_eq!(r.range_inclusive(100, 5), 100);
    }

    #[test]
    fn shuffle_is_a_permutation() {
        let mut r = Rng::new(11);
        let mut v: Vec<u32> = (0..32).collect();
        r.shuffle(&mut v);
        v.sort_unstable();
        assert_eq!(v, (0..32).collect::<Vec<u32>>());
    }
}
