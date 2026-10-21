//! HKDF-SHA256 and HMAC-SHA256 with one domain-separation scheme.
//!
//! Every derived secret in this crate comes through [`derive`] with a label from
//! the table below, so the set of things any one secret can be used for is
//! visible in one screen. Labels are fully qualified (`gdc/v1/<area>/<use>`) so
//! that a future wire version cannot collide with this one.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// HKDF salt. Fixed, not secret; it separates GridDown from any other protocol
/// that might one day be handed the same root bytes.
const SALT: &[u8] = b"GridDown/v1/hkdf";

// --- channel root (the QR secret) -------------------------------------------
/// Tag key: the only thing that survives untouched for the channel's life.
pub const L_TAG_KEY: &[u8] = b"gdc/v1/chan/tag-key";
/// Noise PSK for the join handshake.
pub const L_CHAN_PSK: &[u8] = b"gdc/v1/chan/noise-psk";
/// Epoch-zero message root. Ratcheted forward per epoch; see `channel`.
pub const L_MSG_ROOT0: &[u8] = b"gdc/v1/chan/msg-root-0";
/// Local channel handle. Never on the wire.
pub const L_CHAN_ID: &[u8] = b"gdc/v1/chan/local-id";
/// Prologue binding value mixed into the Noise transcript.
pub const L_CHAN_BIND: &[u8] = b"gdc/v1/chan/prologue-bind";
/// Invite integrity check digits.
pub const L_INVITE_CHECK: &[u8] = b"gdc/v1/invite/check";

// --- per-epoch ---------------------------------------------------------------
/// Message root ratchet step.
pub const L_MSG_ROOT_STEP: &[u8] = b"gdc/v1/chan/msg-root-step";
/// Per-sender chain start, keyed by the sender's identity key.
pub const L_SENDER_CHAIN: &[u8] = b"gdc/v1/chan/sender-chain";
/// Per-sender chain step.
pub const L_CHAIN_STEP: &[u8] = b"gdc/v1/chan/chain-step";
/// Message key and nonce, from a chain element.
pub const L_MSG_KEY: &[u8] = b"gdc/v1/msg/key-nonce";

// --- per-session -------------------------------------------------------------
/// X25519 handshake static, from the session seed.
pub const L_SESSION_X: &[u8] = b"gdc/v1/sess/x25519";
/// Ed25519 identity key, from the session seed.
pub const L_SESSION_ED: &[u8] = b"gdc/v1/sess/ed25519";
/// Short authentication string, from the Noise handshake hash.
pub const L_SAS: &[u8] = b"gdc/v1/join/sas";

// --- MAC domains (HMAC, not HKDF) -------------------------------------------
/// Channel tag for an epoch.
pub const M_TAG: &[u8] = b"gdc/v1/tag";
/// Blinded sender selector for a known sender.
pub const M_SID: &[u8] = b"gdc/v1/sid";
/// Record signature domain.
pub const SIG_DOMAIN: &[u8] = b"gdc/v1/record-sig";

/// Expand `ikm` into `N` bytes under `label`.
pub fn derive<const N: usize>(ikm: &[u8], label: &[u8]) -> Zeroizing<[u8; N]> {
    let hk = Hkdf::<Sha256>::new(Some(SALT), ikm);
    let mut out = Zeroizing::new([0u8; N]);
    // The only failure mode is N > 255*32, and N is always a literal here.
    hk.expand(label, &mut out[..])
        .expect("HKDF output length is a compile-time constant under the limit");
    out
}

/// Expand `ikm` into `N` bytes under `label` with extra context appended to the
/// HKDF `info` field.
pub fn derive_ctx<const N: usize>(ikm: &[u8], label: &[u8], ctx: &[u8]) -> Zeroizing<[u8; N]> {
    let hk = Hkdf::<Sha256>::new(Some(SALT), ikm);
    let mut info = Vec::with_capacity(label.len() + 1 + ctx.len());
    info.extend_from_slice(label);
    info.push(0x00);
    info.extend_from_slice(ctx);
    let mut out = Zeroizing::new([0u8; N]);
    hk.expand(&info, &mut out[..])
        .expect("HKDF output length is a compile-time constant under the limit");
    out
}

/// HMAC-SHA256 truncated to `N` bytes.
///
/// Truncation is a deliberate size/strength trade; see `tag` for the collision
/// arithmetic at N = 8.
pub fn mac<const N: usize>(key: &[u8; 32], domain: &[u8], msg: &[u8]) -> [u8; N] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts any key length");
    m.update(domain);
    m.update(&[0x00]);
    m.update(msg);
    let full = m.finalize().into_bytes();
    let mut out = [0u8; N];
    out.copy_from_slice(&full[..N]);
    out
}
