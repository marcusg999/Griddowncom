//! Deterministic randomness.
//!
//! Two kinds are needed and they must not be confused.
//!
//! * A **sequential** stream for per-event draws (which advertising channel a
//!   packet lands on, whether a packet survives fading, when the next app
//!   message is generated). Two different stacks consume this at different
//!   rates, which is fine: the realisation of the *world* must match, not the
//!   realisation of the protocol's own coin flips.
//! * A **counter-addressed** stream for the world itself — the shadowing field
//!   and the mobility trace. These are queried by coordinate, not in order, so
//!   the value for a given (pair, time block) is identical no matter when or
//!   whether anything asks for it. That is what makes the A/B rig's claim of a
//!   byte-identical world true rather than aspirational.

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Mix a 64-bit value. SplitMix64 finalizer; used only to spread seeds over the
/// ChaCha key space, never as a source of randomness in its own right.
pub fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Derive a 32-byte ChaCha key from a run seed and a domain label.
///
/// Domain separation means adding a new consumer of randomness never shifts the
/// draws an existing consumer sees, so a scenario's numbers do not move when an
/// unrelated feature is added.
pub fn derive_key(seed: u64, domain: &str) -> [u8; 32] {
    let mut acc = splitmix64(seed ^ 0x6772_6964_646F_776E);
    for (i, b) in domain.as_bytes().iter().enumerate() {
        acc = splitmix64(acc ^ ((*b as u64) << (i % 8 * 8)) ^ (i as u64));
    }
    let mut key = [0u8; 32];
    for (chunk, k) in key.chunks_mut(8).enumerate() {
        acc = splitmix64(acc ^ (chunk as u64).wrapping_mul(0x1000_0000_0000_01B3));
        k.copy_from_slice(&acc.to_le_bytes());
    }
    key
}

/// A sequential, domain-separated stream.
pub fn sequential(seed: u64, domain: &str) -> ChaCha20Rng {
    ChaCha20Rng::from_seed(derive_key(seed, domain))
}

/// A stream addressed by coordinate rather than by call order.
///
/// `draw_*` is a pure function of `(seed, domain, coords)`. Two runs that ask
/// in different orders, or ask for different subsets, still agree on every
/// value they both look up.
#[derive(Clone, Debug)]
pub struct CounterRng {
    key: [u8; 32],
}

impl CounterRng {
    pub fn new(seed: u64, domain: &str) -> Self {
        CounterRng {
            key: derive_key(seed, domain),
        }
    }

    fn at(&self, a: u64, b: u64, c: u64) -> ChaCha20Rng {
        let mut rng = ChaCha20Rng::from_seed(self.key);
        // 64 bits of stream and 64 bits of word position give 2^128 addressable
        // slots; the coordinate mix below is injective enough for our index
        // ranges (node ids and time blocks), and a collision would only reuse a
        // shadowing sample, never corrupt state.
        rng.set_stream(splitmix64(a.wrapping_mul(0x9E37_79B9).wrapping_add(b)));
        rng.set_word_pos((splitmix64(c) as u128) << 4);
        rng
    }

    /// Standard normal, Box-Muller. Used for log-normal shadowing in dB.
    pub fn normal(&self, a: u64, b: u64, c: u64) -> f64 {
        let mut rng = self.at(a, b, c);
        let u1: f64 = rng.gen_range(f64::MIN_POSITIVE..1.0);
        let u2: f64 = rng.gen_range(0.0..1.0);
        (-2.0 * u1.ln()).sqrt() * (core::f64::consts::TAU * u2).cos()
    }

    /// Uniform in `[0, 1)`.
    pub fn uniform(&self, a: u64, b: u64, c: u64) -> f64 {
        self.at(a, b, c).gen_range(0.0..1.0)
    }

    pub fn u64_at(&self, a: u64, b: u64, c: u64) -> u64 {
        self.at(a, b, c).gen()
    }
}

/// Exponential draw with the given mean, for Poisson arrival processes.
pub fn exponential(rng: &mut ChaCha20Rng, mean: f64) -> f64 {
    if !(mean > 0.0) {
        return 0.0;
    }
    let u: f64 = rng.gen_range(f64::MIN_POSITIVE..1.0);
    -mean * u.ln()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_rng_is_order_independent() {
        let r = CounterRng::new(42, "shadow");
        let forward: Vec<f64> = (0..8).map(|i| r.normal(1, 2, i)).collect();
        let backward: Vec<f64> = (0..8).rev().map(|i| r.normal(1, 2, i)).collect();
        for (i, v) in forward.iter().enumerate() {
            assert_eq!(*v, backward[7 - i]);
        }
    }

    #[test]
    fn domains_do_not_alias() {
        assert_ne!(derive_key(7, "phy"), derive_key(7, "mobility"));
        assert_ne!(derive_key(7, "phy"), derive_key(8, "phy"));
    }

    #[test]
    fn sequential_is_reproducible() {
        let a: Vec<u64> = (0..4).map(|_| sequential(9, "x").gen()).collect();
        let mut s = sequential(9, "x");
        let b: Vec<u64> = (0..4).map(|_| s.gen()).collect();
        // First draw matches; later draws differ because `a` restarts the stream.
        assert_eq!(a[0], b[0]);
    }

    #[test]
    fn exponential_rejects_nonsense_means() {
        let mut r = sequential(1, "t");
        assert_eq!(exponential(&mut r, 0.0), 0.0);
        assert_eq!(exponential(&mut r, f64::NAN), 0.0);
    }
}
