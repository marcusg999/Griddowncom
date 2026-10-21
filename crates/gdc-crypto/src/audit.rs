//! Making the wipe auditable.
//!
//! # What a test in this environment can and cannot prove
//!
//! It *can* prove that every secret buffer this crate still holds is all zero
//! after a wipe, byte for byte, because the buffers are wiped in place and the
//! structures are still there to be read.
//!
//! It *cannot* prove that a secret left no copy in freed heap memory, in a
//! register, in a stack frame, or in swap. Proving that would need either
//! `unsafe` memory scanning — forbidden in this workspace — or a sanitiser run,
//! which no test here is. What we do instead is structural: every secret in
//! this crate lives inside [`zeroize::Zeroizing`] or a type that wipes in
//! place, so drop-time scrubbing is delegated to a reviewed crate rather than
//! to our diligence, and no secret-bearing type is `Clone`, so there is no
//! quiet second copy for a wipe to miss.

/// How many secret bytes a value holds, and how many of them are still nonzero.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Audit {
    /// Total secret bytes reachable from the value.
    pub total: usize,
    /// How many of those are nonzero.
    pub nonzero: usize,
}

impl Audit {
    /// Audit a set of secret byte ranges.
    pub fn of(parts: &[&[u8]]) -> Audit {
        let mut a = Audit::default();
        for p in parts {
            a.total += p.len();
            a.nonzero += p.iter().filter(|b| **b != 0).count();
        }
        a
    }

    /// Combine two audits.
    pub fn plus(self, other: Audit) -> Audit {
        Audit {
            total: self.total + other.total,
            nonzero: self.nonzero + other.nonzero,
        }
    }

    /// Whether every secret byte held is zero.
    pub fn is_clean(&self) -> bool {
        self.nonzero == 0
    }
}

/// A value whose secret bytes can be counted.
pub trait SecretAudit {
    /// Count the secret bytes still held, and how many are nonzero.
    fn audit(&self) -> Audit;
}
