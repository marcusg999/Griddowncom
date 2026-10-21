//! Determinism primitives: a seeded PRNG and a keyed hash.
//!
//! Two separate jobs, deliberately not served by one tool:
//!
//! * [`Prng`] produces scheduling jitter and selection tie-breaks. It is not
//!   cryptographic and must never be used for anything that needs to be
//!   unpredictable to an attacker who can observe our output.
//! * [`KeyedHash`] indexes tables whose keys come off the radio. `MsgId` is 16
//!   bytes chosen by whoever authored the frame, so a table indexed by an
//!   unkeyed hash of it is a collision-flooding target. The key is derived from
//!   the node seed, which in production is session randomness and in tests is a
//!   fixed number, so the table is deterministic for us and unpredictable for
//!   an attacker.

/// splitmix64. Used only to expand a seed into state.
pub(crate) const fn mix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// xoshiro256++. Small, fast, and reproducible across platforms because every
/// operation is a wrapping integer op on fixed-width words.
#[derive(Clone, Debug)]
pub struct Prng {
    s: [u64; 4],
}

impl Prng {
    pub fn from_seed(seed: u64) -> Self {
        let mut s = [0u64; 4];
        let mut x = seed;
        for slot in s.iter_mut() {
            x = mix64(x);
            // xoshiro requires a non-zero state; mix64 of distinct inputs is
            // overwhelmingly non-zero but we refuse to rely on that.
            *slot = if x == 0 { 0x9E37_79B9_7F4A_7C15 } else { x };
        }
        Prng { s }
    }

    pub fn next_u64(&mut self) -> u64 {
        let result = self.s[0]
            .wrapping_add(self.s[3])
            .rotate_left(23)
            .wrapping_add(self.s[0]);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    /// Uniform in `0..n`, or 0 when `n == 0`. Uses the multiply-shift reduction
    /// rather than a modulo so there is no division and the bias is below
    /// 2^-32, which is far tighter than anything jitter needs.
    pub fn below(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        let r = self.next_u64() >> 32;
        ((r * u64::from(n)) >> 32) as u32
    }
}

/// A keyed 64-bit hash for radio-sourced table keys.
///
/// Not a MAC and not claimed to be one: it exists so that an attacker who can
/// choose `MsgId`s cannot steer them into one bucket of our fixed-size tables.
/// Combined with the set-associative layout in [`crate::seen`], where probe
/// work is bounded by the way count regardless of collisions, a break of this
/// hash costs an attacker a degraded suppression window, not unbounded work.
#[derive(Clone, Copy, Debug)]
pub struct KeyedHash {
    k0: u64,
    k1: u64,
}

impl KeyedHash {
    pub fn from_seed(seed: u64) -> Self {
        KeyedHash {
            k0: mix64(seed ^ 0x5DEE_CE66_D3A9_1C25),
            k1: mix64(seed ^ 0x1234_5678_9ABC_DEF0),
        }
    }

    fn round(&self, acc: u64, word: u64) -> u64 {
        let mut h = acc ^ word.wrapping_mul(self.k0 | 1);
        h = h.rotate_left(31).wrapping_mul(self.k1 | 1);
        h ^ (h >> 29)
    }

    pub fn hash_bytes(&self, b: &[u8]) -> u64 {
        let mut acc = self.k0 ^ (b.len() as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let mut chunks = b.chunks_exact(8);
        for c in &mut chunks {
            // chunks_exact guarantees 8 bytes; try_into cannot fail, and we
            // still avoid unwrap on a radio-driven path.
            let mut w = [0u8; 8];
            w.copy_from_slice(c);
            acc = self.round(acc, u64::from_le_bytes(w));
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut w = [0u8; 8];
            w[..rem.len()].copy_from_slice(rem);
            acc = self.round(acc, u64::from_le_bytes(w));
        }
        mix64(acc)
    }

    pub fn hash_u64(&self, v: u64) -> u64 {
        mix64(self.round(self.k1, v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prng_is_reproducible_and_seed_separated() {
        let a: Vec<u64> = (0..8).map(|_| Prng::from_seed(42).next_u64()).collect();
        assert!(a.iter().all(|v| *v == a[0]), "same seed, same first draw");
        let mut p = Prng::from_seed(42);
        let mut q = Prng::from_seed(43);
        assert_ne!(p.next_u64(), q.next_u64());
    }

    #[test]
    fn below_stays_in_range_including_degenerate_bounds() {
        let mut p = Prng::from_seed(7);
        assert_eq!(p.below(0), 0);
        assert_eq!(p.below(1), 0);
        for _ in 0..10_000 {
            assert!(p.below(150) < 150);
        }
    }

    #[test]
    fn keyed_hash_differs_by_key() {
        let a = KeyedHash::from_seed(1);
        let b = KeyedHash::from_seed(2);
        let id = [0xABu8; 16];
        assert_ne!(a.hash_bytes(&id), b.hash_bytes(&id));
        assert_eq!(a.hash_bytes(&id), a.hash_bytes(&id));
    }

    #[test]
    fn keyed_hash_spreads_sequential_ids() {
        // An attacker minting ids 0,1,2,... must not land them all in one
        // bucket of a 256-bucket table.
        let h = KeyedHash::from_seed(99);
        let mut hits = [0u32; 256];
        for i in 0..4096u32 {
            let mut id = [0u8; 16];
            id[..4].copy_from_slice(&i.to_le_bytes());
            hits[(h.hash_bytes(&id) % 256) as usize] += 1;
        }
        let max = hits.iter().copied().max().unwrap_or(0);
        assert!(max < 48, "worst bucket {max} of 4096/256=16 expected");
    }
}
