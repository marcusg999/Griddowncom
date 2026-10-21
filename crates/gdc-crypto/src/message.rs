//! AEAD message protection for a channel, and the record layout.
//!
//! # Layout
//!
//! A frame body is *exactly* a bucket from [`gdc_wire::BUCKETS`] and is
//! *entirely* one ChaCha20-Poly1305 ciphertext. There is no cleartext length,
//! no cleartext sender, no cleartext counter and no cleartext padding marker.
//!
//! ```text
//! body  = ChaCha20Poly1305(k, n, inner, aad = header.aad())      // bucket bytes
//! inner = rt(1) | plen(2) | ctr(2) | sender_pub(32) | sig(64) | payload | pad
//! k, n  = HKDF(msg_root(epoch), "gdc/v1/msg/key-nonce", msg_id)
//! sig   = Ed25519(sender, "gdc/v1/record-sig" | aad | rt | plen | ctr | payload)
//! ```
//!
//! The nonce comes from the KDF keyed on the header's 16-byte random `msg_id`,
//! so a nonce is never reused and no counter has to be published to make that
//! true. `msg_id` is in the AAD, so it cannot be swapped for another frame's.
//!
//! # Why the padding is inside the AEAD, and why that kills a whole bug class
//!
//! `pad` fills the bucket from the end of the payload and is **never read**.
//! The true length is `plen`, which is inside the ciphertext and covered by both
//! the AEAD tag and the signature. So:
//!
//! * there is no padding check, therefore no padding oracle. Bridgefy's C-1 was
//!   a Bleichenbacher variant driven by delivery receipts distinguishing a
//!   padding failure from a MAC failure. Here a "padding failure" is not a
//!   representable event.
//! * on-wire length is a function of `payload.len()` only, through
//!   [`smallest_bucket_for`]. Nothing about *content* reaches the wire length.
//!   That is the structural kill for C-2, and the length-correlation test is
//!   what holds it.
//!
//! # Sender authentication
//!
//! Every record carries the sender's 32-byte Ed25519 public key and a 64-byte
//! signature, inside the AEAD. 96 bytes is a lot on a 500-byte-ceiling
//! messenger, and it is the price of the one property a shared-key group cannot
//! have otherwise: every member holds every symmetric key the channel has, so
//! symmetric authentication would mean any member can forge any other member —
//! which is finding A-3 with a smaller blast radius, not a fix for it. With a
//! signature, a member can only ever speak as itself.
//!
//! Carrying the key rather than a short selector is what makes a frame
//! self-contained. A frame that spent forty minutes in someone's pocket and
//! arrives in a cluster that has never seen its author is still verifiable
//! there, with no roster, no presence history and no round trip. That is the
//! product's whole premise, so it wins over the 28 bytes a selector would save.
//!
//! # Forward secrecy, precisely
//!
//! The ratchet is on the channel's message root, one step per tag epoch, with
//! the QR root destroyed at install and roots below `e-1` dropped (see
//! `channel`). A device seized in epoch `e` cannot read captured traffic from
//! epoch `e-2` or earlier. Granularity is therefore one epoch (3600 s), not one
//! message.
//!
//! Per-message forward secrecy would need a per-sender chain, which the
//! receiver must select *before* decrypting, which needs a sender selector in
//! the cleartext — and a receiver that has never seen the sender cannot match
//! one, so carried frames from unknown authors would become undeliverable. The
//! trade is: an hour of forward secrecy, or store-and-forward from strangers.
//! For this product the second is not optional.
//!
//! # Replay
//!
//! `ctr` is a per-sender, per-epoch counter inside the record. A
//! [`ReplayWindow`] of [`REPLAY_WINDOW`] messages is kept per
//! `(epoch, sender)`: 20 bytes each, at most [`MAX_SENDERS_PER_EPOCH`] senders
//! per epoch and three epochs held, so under 2 KiB per channel, and the window
//! is only ever created *after* a signature has verified. An attacker cannot
//! make this crate allocate.

use std::collections::HashMap;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use gdc_wire::{Flags, Frame, Header, Kind, MsgId, BUCKETS, MAX_BODY_LEN};

use crate::channel::{ChannelId, ChannelKeys};
use crate::error::SealError;
use crate::identity::{SessionIdentity, SessionKey};
use crate::kdf::{derive_ctx, L_MSG_KEY, SIG_DOMAIN};
use crate::rng::Rng;

const AEAD_TAG_LEN: usize = 16;
const RT_LEN: usize = 1;
const PLEN_LEN: usize = 2;
const CTR_LEN: usize = 2;
const EDPUB_LEN: usize = 32;
const SIG_LEN: usize = 64;

/// Fixed part of the inner record, before payload and padding.
const INNER_FIXED: usize = RT_LEN + PLEN_LEN + CTR_LEN + EDPUB_LEN + SIG_LEN; // 101

/// Non-payload bytes inside a frame body.
pub const BODY_OVERHEAD: usize = AEAD_TAG_LEN + INNER_FIXED; // 117

/// Non-payload bytes on the wire, including the `gdc-wire` header.
pub const WIRE_OVERHEAD: usize = gdc_wire::HEADER_LEN + BODY_OVERHEAD; // 149

/// Replay window width, in messages.
pub const REPLAY_WINDOW: u32 = 128;

/// Senders tracked per channel per epoch.
///
/// Reaching the cap means a later sender's first message in that epoch is
/// dropped until the epoch rolls. It is a liveness ceiling that exists so the
/// memory bound is a number rather than an argument.
pub const MAX_SENDERS_PER_EPOCH: usize = 32;

/// Record kinds. One byte, inside the AEAD, so it is not metadata.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum RecordType {
    /// Free text, UTF-8, up to [`gdc_wire::MAX_BODY_LEN`].
    Text = 0,
    /// An index into the canned-message pad.
    Canned = 1,
    /// A compact location pin.
    Pin = 2,
    /// An acknowledgement of a message id.
    Ack = 3,
    /// A liveness beacon carrying a nickname.
    Presence = 4,
}

impl RecordType {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => RecordType::Text,
            1 => RecordType::Canned,
            2 => RecordType::Pin,
            3 => RecordType::Ack,
            4 => RecordType::Presence,
            _ => return None,
        })
    }
}

/// A decrypted, signature-verified record.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Record {
    /// What kind of record this is.
    pub rtype: RecordType,
    /// Its payload, exactly as the author wrote it.
    pub payload: Vec<u8>,
}

/// The result of opening a frame.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Opened {
    /// Which channel it belongs to.
    pub channel: ChannelId,
    /// Which tag epoch it was sealed in.
    pub epoch: u64,
    /// The author's session key, after its signature verified.
    pub sender: SessionKey,
    /// The record.
    pub record: Record,
}

/// Largest payload that fits a body of `bucket_size` bytes.
pub fn max_payload(bucket_size: usize) -> Option<usize> {
    bucket_size.checked_sub(BODY_OVERHEAD)
}

/// Smallest `(bucket index, bucket size)` that holds `payload_len` bytes.
///
/// The *only* input is the payload length. This function is the single place
/// where on-wire size is decided, which is what makes "length carries no
/// information about content" checkable rather than hoped for.
pub fn smallest_bucket_for(payload_len: usize) -> Result<(u8, usize), SealError> {
    if payload_len > MAX_BODY_LEN {
        return Err(SealError::PayloadTooLarge);
    }
    for (i, b) in BUCKETS.iter().enumerate() {
        let b = *b as usize;
        if max_payload(b).is_some_and(|m| payload_len <= m) {
            return Ok((i as u8, b));
        }
    }
    Err(SealError::NoBucket)
}

/// A sliding replay window over a sender's per-epoch counter.
#[derive(Clone, Copy, Debug, Default)]
pub struct ReplayWindow {
    highest: u32,
    bits: u128,
}

impl ReplayWindow {
    /// Admit `ctr` if it has not been seen and is inside the window.
    pub fn admit(&mut self, ctr: u32) -> bool {
        if ctr > self.highest {
            let shift = ctr - self.highest;
            self.bits = if shift >= REPLAY_WINDOW {
                0
            } else {
                self.bits << shift
            };
            self.bits |= 1;
            self.highest = ctr;
            true
        } else {
            let back = self.highest - ctr;
            if back >= REPLAY_WINDOW {
                return false;
            }
            let mask = 1u128 << back;
            if self.bits & mask != 0 {
                return false;
            }
            self.bits |= mask;
            true
        }
    }
}

/// Everything a device keeps for one channel: its keys, its own send counters,
/// and one replay window per authenticated sender per epoch.
pub(crate) struct ChannelSlot {
    pub keys: ChannelKeys,
    send_ctr: HashMap<u64, u32>,
    replay: HashMap<(u64, SessionKey), ReplayWindow>,
}

impl ChannelSlot {
    pub fn new(keys: ChannelKeys) -> Self {
        ChannelSlot {
            keys,
            send_ctr: HashMap::new(),
            replay: HashMap::new(),
        }
    }

    /// Drop per-epoch state for epochs the channel no longer holds roots for.
    pub fn prune(&mut self, epoch: u64) {
        let floor = epoch.saturating_sub(1);
        self.send_ctr.retain(|e, _| *e >= floor);
        self.replay.retain(|(e, _), _| *e >= floor);
    }

    /// Forget every sender and every counter. Used by new-identity: a new
    /// session must not inherit the old one's view of anything.
    pub fn reset_session_state(&mut self) {
        self.send_ctr.clear();
        self.replay.clear();
    }

    fn next_ctr(&mut self, epoch: u64) -> Result<u16, SealError> {
        let c = self.send_ctr.entry(epoch).or_insert(0);
        if *c > u16::MAX as u32 {
            return Err(SealError::CounterExhausted);
        }
        let out = *c as u16;
        *c += 1;
        Ok(out)
    }

    fn admit(&mut self, epoch: u64, sender: SessionKey, ctr: u16) -> bool {
        if !self.replay.contains_key(&(epoch, sender)) {
            let in_epoch = self.replay.keys().filter(|(e, _)| *e == epoch).count();
            if in_epoch >= MAX_SENDERS_PER_EPOCH {
                return false;
            }
        }
        self.replay
            .entry((epoch, sender))
            .or_default()
            .admit(ctr as u32)
    }
}

fn key_nonce(msg_root: &[u8; 32], msg_id: &MsgId) -> ([u8; 32], [u8; 12]) {
    let kn = derive_ctx::<44>(&msg_root[..], L_MSG_KEY, &msg_id.0);
    let mut k = [0u8; 32];
    let mut n = [0u8; 12];
    k.copy_from_slice(&kn[..32]);
    n.copy_from_slice(&kn[32..44]);
    (k, n)
}

fn signed_bytes(aad: &[u8], rt: u8, plen: u16, ctr: u16, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(aad.len() + 5 + payload.len());
    b.extend_from_slice(aad);
    b.push(rt);
    b.extend_from_slice(&plen.to_be_bytes());
    b.extend_from_slice(&ctr.to_be_bytes());
    b.extend_from_slice(payload);
    b
}

/// Seal a record into a frame.
#[allow(clippy::too_many_arguments)]
pub(crate) fn seal(
    slot: &mut ChannelSlot,
    identity: &SessionIdentity,
    epoch: u64,
    kind: Kind,
    flags: Flags,
    ttl: u8,
    rtype: RecordType,
    payload: &[u8],
    rng: &mut impl Rng,
) -> Result<Frame, SealError> {
    let (bucket, bucket_size) = smallest_bucket_for(payload.len())?;
    let msg_root = *slot
        .keys
        .msg_root(epoch)
        .ok_or(SealError::ChannelExpired)?;
    let ctr = slot.next_ctr(epoch)?;

    let mut id = [0u8; 16];
    rng.fill(&mut id);
    let msg_id = MsgId(id);
    let tag = slot.keys.tag_for(epoch);

    let hdr = Header {
        ver: gdc_wire::WIRE_VERSION,
        kind,
        flags,
        ttl,
        bucket,
        msg_id,
        tag,
    };
    let aad = hdr.aad();

    let plen = payload.len() as u16;
    let sig = identity.sign(
        SIG_DOMAIN,
        &signed_bytes(&aad, rtype as u8, plen, ctr, payload),
    );

    // The inner plaintext is always exactly `bucket - 16` bytes, so the
    // ciphertext is always exactly the bucket. Padding is written last and is
    // random, which costs nothing and leaves no recognisable filler behind if a
    // key is ever recovered.
    let inner_len = bucket_size - AEAD_TAG_LEN;
    let mut inner = vec![0u8; inner_len];
    inner[0] = rtype as u8;
    inner[1..3].copy_from_slice(&plen.to_be_bytes());
    inner[3..5].copy_from_slice(&ctr.to_be_bytes());
    inner[5..37].copy_from_slice(&identity.session_key().0);
    inner[37..101].copy_from_slice(&sig);
    inner[INNER_FIXED..INNER_FIXED + payload.len()].copy_from_slice(payload);
    rng.fill(&mut inner[INNER_FIXED + payload.len()..]);

    let (k, n) = key_nonce(&msg_root, &msg_id);
    let ct = ChaCha20Poly1305::new((&k).into())
        .encrypt(
            (&n).into(),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| SealError::NoBucket)?;
    debug_assert_eq!(ct.len(), bucket_size);

    let frame = Frame::new(kind, flags, ttl, msg_id, tag, &ct, &mut |b: &mut [u8]| {
        rng.fill(b)
    })?;
    debug_assert_eq!(frame.hdr.bucket, bucket);
    Ok(frame)
}

struct Fields {
    rt: u8,
    ctr: u16,
    edpub: [u8; 32],
    sig: [u8; 64],
    plen: usize,
}

fn parse(pt: &[u8]) -> Option<Fields> {
    if pt.len() < INNER_FIXED {
        return None;
    }
    let plen = u16::from_be_bytes([pt[1], pt[2]]) as usize;
    if plen > MAX_BODY_LEN || INNER_FIXED + plen > pt.len() {
        return None;
    }
    let mut edpub = [0u8; 32];
    edpub.copy_from_slice(&pt[5..37]);
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&pt[37..101]);
    Some(Fields {
        rt: pt[0],
        ctr: u16::from_be_bytes([pt[3], pt[4]]),
        edpub,
        sig,
        plen,
    })
}

/// A plaintext that parses and whose key is a real curve point, used so that a
/// failed decrypt still costs one parse and one signature verification. Without
/// it, "unknown tag" would return before the expensive part and the latency
/// difference would be the oracle.
fn dummy_plaintext() -> Vec<u8> {
    let mut pt = vec![0u8; INNER_FIXED];
    let vk = ed25519_dalek::SigningKey::from_bytes(&[0x42u8; 32])
        .verifying_key()
        .to_bytes();
    pt[5..37].copy_from_slice(&vk);
    pt
}

/// One open attempt against one `(channel, epoch)` candidate.
///
/// `slot = None` is a *dummy* attempt: it does the same work against a fixed
/// key and discards the result. The caller always runs
/// [`crate::MAX_TAG_CANDIDATES`] attempts, so the work an `open` does is a
/// constant — independent of how many channels matched the tag, of whether the
/// AEAD succeeded, of whether the signature verified and of whether the counter
/// replayed.
pub(crate) fn try_open(
    slot: Option<&mut ChannelSlot>,
    epoch: u64,
    hdr: &Header,
    body: &[u8],
) -> Option<Opened> {
    const DUMMY_ROOT: [u8; 32] = [0x5a; 32];

    let channel = slot.as_ref().map(|s| s.keys.id());
    let msg_root = slot
        .as_ref()
        .and_then(|s| s.keys.msg_root(epoch))
        .copied()
        .unwrap_or(DUMMY_ROOT);

    let aad = hdr.aad();
    let (k, n) = key_nonce(&msg_root, &hdr.msg_id);
    let real = ChaCha20Poly1305::new((&k).into())
        .decrypt((&n).into(), Payload { msg: body, aad: &aad })
        .ok();

    let dummy = dummy_plaintext();
    let mut ok = real.is_some();
    let pt: &[u8] = real.as_deref().unwrap_or(&dummy);

    let f = match parse(pt) {
        Some(f) => f,
        None => {
            ok = false;
            parse(&dummy).expect("the dummy plaintext parses by construction")
        }
    };
    let payload: &[u8] = if ok && INNER_FIXED + f.plen <= pt.len() {
        &pt[INNER_FIXED..INNER_FIXED + f.plen]
    } else {
        &[]
    };

    // Always run exactly one verification, on real or dummy material.
    let sig_ok = crate::identity::verify(
        &f.edpub,
        SIG_DOMAIN,
        &signed_bytes(&aad, f.rt, f.plen as u16, f.ctr, payload),
        &f.sig,
    );
    ok &= sig_ok;

    let rtype = RecordType::from_u8(f.rt);
    ok &= rtype.is_some();

    if !ok {
        return None;
    }
    let channel = channel?;
    let slot = slot?;
    let sender = SessionKey(f.edpub);
    if !slot.admit(epoch, sender, f.ctr) {
        return None;
    }
    Some(Opened {
        channel,
        epoch,
        sender,
        record: Record {
            rtype: rtype?,
            payload: payload.to_vec(),
        },
    })
}
