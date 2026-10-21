//! Injected randomness.
//!
//! The trait is object-safe and byte-oriented so that neither the OS source nor
//! the test source leaks into the logic. Tests pin every random value this crate
//! consumes: message ids, session seeds, Noise ephemerals.

use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// A cryptographically secure byte source.
pub trait Rng {
    /// Fill `out` with random bytes.
    fn fill(&mut self, out: &mut [u8]);
}

/// The operating system's CSPRNG. The only thing production should use.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRng;

impl Rng for OsRng {
    fn fill(&mut self, out: &mut [u8]) {
        // `getrandom` is the platform syscall on both of our targets. A failure
        // here is unrecoverable and not an input-driven path, so it panics
        // rather than returning a key derived from nothing.
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, out);
    }
}

/// A seeded ChaCha20 stream, for tests only.
///
/// Named so that its presence in non-test code is obvious in review.
#[derive(Debug)]
pub struct TestRng(ChaCha20Rng);

impl TestRng {
    /// Create a deterministic source from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        TestRng(ChaCha20Rng::from_seed(seed))
    }

    /// Create a deterministic source from a small integer seed.
    pub fn seeded(n: u64) -> Self {
        let mut seed = [0u8; 32];
        seed[..8].copy_from_slice(&n.to_le_bytes());
        TestRng::from_seed(seed)
    }
}

impl Rng for TestRng {
    fn fill(&mut self, out: &mut [u8]) {
        self.0.fill_bytes(out)
    }
}
