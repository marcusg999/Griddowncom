//! Live presence inside a channel.
//!
//! Not an address book. An entry is a [`SessionKey`] plus the nickname that key
//! has claimed, the last time we saw it, and whether a human has confirmed it.
//! Entries are per channel, because presence is a channel property.
//!
//! Every entry is keyed on a [`SessionKey`] that has already authenticated:
//! either an Ed25519 key whose signature verified over a record we decrypted,
//! or a remote static that Noise authenticated during a join. There is no path
//! into this map from a claimed identifier or a Bluetooth address. That is rule
//! 10, and the reason it is a rule is that Bridgefy's session lookup was keyed
//! on a `userId` in an address field, which let session state be swapped between
//! the check and the use.

use std::collections::HashMap;

use crate::channel::ChannelId;
use crate::handshake::Session;
use crate::identity::{Nickname, SessionKey};

/// Hard cap on roster size, across all channels.
///
/// Entries are only created by an authenticated frame, so this is not an
/// attacker-reachable allocation; the cap is here because "bounded by
/// construction" should not depend on that argument holding forever.
pub const MAX_ROSTER: usize = 256;

/// Whether a human has confirmed this key in person.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verification {
    /// Seen and cryptographically authenticated as a channel member, but no
    /// human has compared a short authentication string with its holder. The
    /// UI must not imply this is a known person.
    Unverified,
    /// A join handshake completed with this key and the two humans confirmed
    /// the same short authentication string.
    Verified,
}

/// One roster row.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RosterEntry {
    /// The channel this presence was seen in.
    pub channel: ChannelId,
    /// The authenticated session key.
    pub key: SessionKey,
    /// The nickname this key claims.
    pub nick: Nickname,
    /// Whether a human has confirmed it.
    pub verification: Verification,
    /// Unix seconds of the last authenticated frame from this key.
    pub last_seen: u64,
}

/// Live presence, per channel.
#[derive(Default, Debug)]
pub struct Roster {
    entries: HashMap<(ChannelId, SessionKey), RosterEntry>,
}

impl Roster {
    /// An empty roster.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an authenticated sighting.
    ///
    /// `key` must be a key that has already verified. A `Verified` row is never
    /// downgraded by a later sighting, and a nickname change does not clear
    /// verification, because what was verified was the key.
    pub(crate) fn observe(
        &mut self,
        channel: ChannelId,
        key: SessionKey,
        nick: Option<Nickname>,
        now: u64,
    ) {
        match self.entries.get_mut(&(channel, key)) {
            Some(e) => {
                if let Some(n) = nick {
                    e.nick = n;
                }
                e.last_seen = now;
            }
            None => {
                if self.entries.len() >= MAX_ROSTER {
                    return;
                }
                self.entries.insert(
                    (channel, key),
                    RosterEntry {
                        channel,
                        key,
                        nick: nick.unwrap_or(
                            Nickname::new("?").expect("single printable char is a valid nickname"),
                        ),
                        verification: Verification::Unverified,
                        last_seen: now,
                    },
                );
            }
        }
    }

    /// Promote a row to [`Verification::Verified`].
    ///
    /// Takes the completed [`Session`] rather than a key, so the key can only
    /// come from a handshake this device ran to completion and whose short
    /// authentication string the user confirmed. There is no public setter that
    /// takes a bare key.
    pub fn mark_verified(&mut self, session: &Session) -> bool {
        if !session.sas_confirmed() {
            return false;
        }
        let k = (session.channel(), session.remote());
        match self.entries.get_mut(&k) {
            Some(e) => {
                e.verification = Verification::Verified;
                true
            }
            None => {
                if self.entries.len() >= MAX_ROSTER {
                    return false;
                }
                self.entries.insert(
                    k,
                    RosterEntry {
                        channel: session.channel(),
                        key: session.remote(),
                        nick: Nickname::new("?").expect("valid"),
                        verification: Verification::Verified,
                        last_seen: 0,
                    },
                );
                true
            }
        }
    }

    /// Look a row up.
    pub fn get(&self, channel: ChannelId, key: SessionKey) -> Option<&RosterEntry> {
        self.entries.get(&(channel, key))
    }

    /// Every row in a channel.
    pub fn members(&self, channel: ChannelId) -> Vec<RosterEntry> {
        let mut v: Vec<RosterEntry> = self
            .entries
            .values()
            .filter(|e| e.channel == channel)
            .copied()
            .collect();
        v.sort_by_key(|e| e.key);
        v
    }

    /// Number of rows.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the roster is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop every row. Called by both new-identity and panic wipe: a roster is
    /// session state, and a session that ends takes it with it.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}
