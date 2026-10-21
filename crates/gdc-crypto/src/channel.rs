//! Channel keys, and the one place the QR root is allowed to exist.
//!
//! # What is kept and what is destroyed
//!
//! Installing a channel derives four things from the root and then **drops the
//! root**:
//!
//! * `tag_key` — rotating channel tags. Must live for the channel's whole life.
//! * `psk` — the Noise pre-shared key for the join handshake. Same.
//! * `bind` — a prologue binding value mixed into the Noise transcript.
//! * `msg_root` for the current epoch, plus its neighbours.
//!
//! The message root is a hash ratchet: `msg_root(e+1) = HKDF(msg_root(e))`, and
//! roots below `e-1` are dropped. Because the QR root is gone, a device seized
//! at epoch `e` cannot derive `msg_root(e-2)` and cannot read traffic it
//! captured from before then. That is the forward secrecy this crate provides,
//! and its granularity is one tag epoch — see `message` for why it is not
//! per-message.
//!
//! It is not forward secrecy against the *QR*. Anyone holding the invite can
//! recompute every message root from epoch zero. That is inherent to a channel
//! whose membership credential is a picture, and it is why `lifetime_hours`
//! exists: the credential has an expiry and the keys delete themselves.

use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::invite::ChannelInvite;
use crate::kdf::{derive, L_CHAN_BIND, L_CHAN_ID, L_CHAN_PSK, L_MSG_ROOT0, L_MSG_ROOT_STEP, L_TAG_KEY};
use crate::tag::tag_for_epoch;

/// A local handle for a channel. Derived from the root, never on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChannelId(pub(crate) [u8; 8]);

impl ChannelId {
    /// The handle's bytes. Safe to show a user; useless to an observer, because
    /// it never appears in a frame.
    pub fn as_bytes(&self) -> &[u8; 8] {
        &self.0
    }
}

impl core::fmt::Debug for ChannelId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ChannelId({:02x}{:02x}..)", self.0[0], self.0[1])
    }
}

/// Everything a device keeps for one channel.
pub struct ChannelKeys {
    id: ChannelId,
    tag_key: Zeroizing<[u8; 32]>,
    psk: Zeroizing<[u8; 32]>,
    bind: [u8; 16],
    created_epoch: u64,
    lifetime_hours: u16,
    /// Ascending by epoch, at most three entries: `e-1`, `e`, `e+1`.
    roots: Vec<(u64, Zeroizing<[u8; 32]>)>,
}

impl core::fmt::Debug for ChannelKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ChannelKeys")
            .field("id", &self.id)
            .field("created_epoch", &self.created_epoch)
            .field("lifetime_hours", &self.lifetime_hours)
            .field("epochs_held", &self.roots.len())
            .field("secrets", &"<redacted>")
            .finish()
    }
}

impl ChannelKeys {
    /// Install a channel from an invite, at tag epoch `now_epoch`.
    ///
    /// The invite is consumed, so the root is dropped — and, being
    /// [`Zeroizing`], scrubbed — before this function returns.
    pub fn install(invite: ChannelInvite, now_epoch: u64) -> Result<Self, CryptoError> {
        let created = invite.created_epoch();
        let lifetime = invite.lifetime_hours();
        if now_epoch > created.saturating_add(lifetime as u64) {
            return Err(CryptoError::ChannelExpired);
        }
        let root = invite.root();
        let mut keys = ChannelKeys {
            id: ChannelId(*derive::<8>(root, L_CHAN_ID)),
            tag_key: derive::<32>(root, L_TAG_KEY),
            psk: derive::<32>(root, L_CHAN_PSK),
            bind: *derive::<16>(root, L_CHAN_BIND),
            created_epoch: created,
            lifetime_hours: lifetime,
            roots: vec![(created, derive::<32>(root, L_MSG_ROOT0))],
        };
        drop(invite);
        keys.advance_to(now_epoch)?;
        Ok(keys)
    }

    /// The local handle.
    pub fn id(&self) -> ChannelId {
        self.id
    }

    /// Tag epoch the channel was created in.
    pub fn created_epoch(&self) -> u64 {
        self.created_epoch
    }

    /// Validity window in tag epochs.
    pub fn lifetime_hours(&self) -> u16 {
        self.lifetime_hours
    }

    /// Whether the channel's validity window has closed by `epoch`.
    pub fn expired(&self, epoch: u64) -> bool {
        epoch > self.created_epoch.saturating_add(self.lifetime_hours as u64)
    }

    pub(crate) fn psk(&self) -> &[u8; 32] {
        &self.psk
    }

    pub(crate) fn bind(&self) -> &[u8; 16] {
        &self.bind
    }

    /// The channel tag for `epoch`.
    pub fn tag_for(&self, epoch: u64) -> gdc_wire::ChanTag {
        tag_for_epoch(&self.tag_key, epoch)
    }

    /// The message root for `epoch`, if it is one of the epochs still held.
    pub(crate) fn msg_root(&self, epoch: u64) -> Option<&[u8; 32]> {
        self.roots
            .iter()
            .find(|(e, _)| *e == epoch)
            .map(|(_, r)| &**r)
    }

    /// The epochs whose message roots are currently held.
    pub fn epochs_held(&self) -> Vec<u64> {
        self.roots.iter().map(|(e, _)| *e).collect()
    }

    /// Ratchet to `epoch`, keeping `epoch-1 ..= epoch+1` and destroying the rest.
    ///
    /// Work is bounded by `lifetime_hours + 2` HKDF steps, and `epoch` comes
    /// from the local clock, never from a frame.
    pub fn advance_to(&mut self, epoch: u64) -> Result<(), CryptoError> {
        if self.expired(epoch) {
            self.wipe();
            return Err(CryptoError::ChannelExpired);
        }
        let ceiling = self.created_epoch.saturating_add(self.lifetime_hours as u64);
        self.extend_to(epoch.saturating_add(1).min(ceiling))?;
        let floor = epoch.saturating_sub(1);
        self.roots.retain(|(e, _)| *e >= floor);
        if self.roots.is_empty() {
            return Err(CryptoError::ChannelExpired);
        }
        Ok(())
    }

    fn extend_to(&mut self, target: u64) -> Result<(), CryptoError> {
        let Some(&(last, _)) = self.roots.last() else {
            return Err(CryptoError::ChannelExpired);
        };
        if target <= last {
            return Ok(());
        }
        if target - last > self.lifetime_hours as u64 + 2 {
            // Cannot happen from a frame; this is the belt for a clock that
            // jumped years, and it keeps the step count a stated constant.
            self.wipe();
            return Err(CryptoError::ChannelExpired);
        }
        let mut cur = self.roots.last().expect("checked above").1.clone();
        for e in (last + 1)..=target {
            cur = derive::<32>(&cur[..], L_MSG_ROOT_STEP);
            self.roots.push((e, cur.clone()));
        }
        Ok(())
    }

    /// Zeroize every secret in place, leaving the structure allocated so that a
    /// test can prove the bytes are gone rather than merely dropped.
    pub fn wipe(&mut self) {
        use zeroize::Zeroize;
        self.tag_key.zeroize();
        self.psk.zeroize();
        self.bind.zeroize();
        for (_, r) in self.roots.iter_mut() {
            r.zeroize();
        }
    }
}

impl crate::audit::SecretAudit for ChannelKeys {
    fn audit(&self) -> crate::audit::Audit {
        let mut parts: Vec<&[u8]> = vec![&self.tag_key[..], &self.psk[..], &self.bind[..]];
        for (_, r) in &self.roots {
            parts.push(&r[..]);
        }
        crate::audit::Audit::of(&parts)
    }
}
