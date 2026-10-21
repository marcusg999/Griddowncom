//! Injected time.
//!
//! Epochs are absolute: `unix_secs / TAG_EPOCH_SECS`. There is no negotiated
//! anchor, because two phones that have been off-grid for an hour still have
//! working real-time clocks, and accepting the neighbouring epochs covers an
//! hour of skew in either direction. An anchor would have to be carried in the
//! QR and would still not survive a phone whose clock is simply wrong.

use std::sync::atomic::{AtomicU64, Ordering};

/// A source of wall-clock seconds since the Unix epoch.
pub trait Clock {
    /// Seconds since the Unix epoch.
    fn unix_secs(&self) -> u64;
}

/// The platform clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_secs(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// A clock a test drives by hand.
#[derive(Debug)]
pub struct FixedClock(AtomicU64);

impl FixedClock {
    /// Start at `t` seconds.
    pub fn at(t: u64) -> Self {
        FixedClock(AtomicU64::new(t))
    }

    /// Jump to `t` seconds.
    pub fn set(&self, t: u64) {
        self.0.store(t, Ordering::Relaxed)
    }

    /// Move forward by `d` seconds.
    pub fn advance(&self, d: u64) {
        self.0.fetch_add(d, Ordering::Relaxed);
    }
}

impl Clock for FixedClock {
    fn unix_secs(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}
