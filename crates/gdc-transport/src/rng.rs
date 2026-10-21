//! Randomness, injected.
//!
//! Transport needs randomness for three things: reconnect backoff jitter,
//! role-election tie-breaks, and the per-transfer fragment id. None of it is
//! security-critical — key material and BLE address rotation belong to
//! `gdc-crypto` and to the native shell respectively — but all of it has to be
//! reproducible so that a simulator run with a given seed is replayable and a
//! test can assert on an exact backoff ladder.
//!
//! This is deliberately not `rand`: the trait is two lines, so the simulator,
//! the native shell and the tests can each plug in their own source without the
//! whole workspace inheriting a dependency.

/// A source of reproducible randomness.
pub trait RandSource {
    fn next_u64(&mut self) -> u64;

    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// Uniform-ish value in `0..n`. Returns 0 for `n == 0` rather than dividing
    /// by zero, because `n` can be derived from a peer-supplied count.
    fn below(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        // Modulo bias is irrelevant for jitter and tie-breaks; being branch-free
        // and total matters more.
        (self.next_u64() % u64::from(n)) as u32
    }

    /// Uniform value in `[0.0, 1.0)`.
    fn unit(&mut self) -> f32 {
        // 24 bits is the full mantissa of an f32, so this is exact.
        (self.next_u64() >> 40) as f32 / (1u32 << 24) as f32
    }
}

/// SplitMix64. Small, fast, fully specified, and identical on every platform,
/// which is what makes a seeded simulator run reproducible across machines.
#[derive(Clone, Debug)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }
}

impl RandSource for SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let mut a = SplitMix64::new(42);
        let mut b = SplitMix64::new(42);
        for _ in 0..64 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn below_zero_does_not_divide_by_zero() {
        let mut r = SplitMix64::new(1);
        assert_eq!(r.below(0), 0);
    }

    #[test]
    fn unit_stays_in_range() {
        let mut r = SplitMix64::new(7);
        for _ in 0..1000 {
            let u = r.unit();
            assert!((0.0..1.0).contains(&u), "{u}");
        }
    }
}
