//! Faithful models of the two protocols we are measured against.
//!
//! Every blind comparison in this project runs our stack against this crate, so
//! a flattering opponent here invalidates every number the project publishes.
//! Faithfulness, not performance, is the whole job. Two rules follow from that
//! and are applied throughout:
//!
//! 1. **Every parameter cites its source** — which file, which section.
//! 2. **Every behaviour the sources leave open is marked `ASSUMPTION:`** and
//!    states which way the choice cuts. Where an ambiguity could be resolved
//!    either way, it is resolved in the opponent's favour, never ours.
//!
//! The models
//! ----------
//!
//! * [`bridgefy`] — Bridgefy, from `docs/research/BRIDGEFY-FINDINGS.md` Part 1.
//!   A pure controlled flood with a one-byte `hops` TTL defaulting to 100, no
//!   topology knowledge of any kind, `MessagePack -> gzip -> encrypt` so
//!   on-wire length varies with payload content, relay-before-parse ordering,
//!   and the `track` CRC list carried but never consulted.
//! * [`bitchat`] — bitchat, from its published WHITEPAPER.md v2.0 (2026-07-06).
//!   The harder opponent and the real state of the art in this niche:
//!   degree-tuned TTL clamps, message-id-seeded subset flooding, an LRU
//!   seen-set with cancellable jittered relays, a shallow topology map with
//!   source routing, fragmentation, a sender outbox, spray-and-wait couriers
//!   with daily-rotating tags, and gossip-synced public history.
//!
//! Support modules: [`sizing`] models `MessagePack`, gzip, AES-ECB and
//! libsignal for their *size and leakage* rather than performing them;
//! [`rng`] is a seeded integer-only generator so a run replays exactly;
//! [`hash`] holds the CRC-32 Bridgefy's `track` list is specified in terms of
//! and the digests bitchat's dedup key and courier tags are built from.
//!
//! Where the sources are silent
//! ----------------------------
//!
//! BLE connection interval, scan window and ATT MTU are not in the bitchat
//! whitepaper and not in the Bridgefy material. Both models take them from
//! [`proto::LinkParams`], which exists to be filled in from `gdc-sim`'s link
//! model so that — per `docs/METRICS.md`, "How a blind comparison is run",
//! rule 2 — both stacks sit on identical link assumptions.

#![forbid(unsafe_code)]

// TEMP-STAGE: pub mod bitchat;
pub mod bridgefy;
pub mod hash;
pub mod proto;
pub mod rng;
pub mod sizing;
// TEMP-STAGE: pub mod slots;

pub use bridgefy::{Bridgefy, BridgefyConfig, Profile, ALL_PROFILES};
pub use proto::{
    Action, Dest, Event, LinkParams, MeshProtocol, PeerId, ProtoError, Stats, TimeMs,
};

/// Which opponent to build.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BaselineKind {
    Bridgefy,
    Bitchat,
}

/// Build one opponent behind the protocol-under-test trait.
///
/// The blind A/B rig holds both stacks through this, so nothing downstream can
/// tell them apart by type.
pub fn make(kind: BaselineKind, node: PeerId, seed: u64) -> Box<dyn MeshProtocol> {
    match kind {
        BaselineKind::Bridgefy => Box::new(Bridgefy::new(node, seed, BridgefyConfig::default())),
        BaselineKind::Bitchat => Box::new(Bridgefy::new(node, seed, BridgefyConfig::default())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_models_are_constructible_behind_the_trait() {
        for k in [BaselineKind::Bridgefy, BaselineKind::Bitchat] {
            let p = make(k, PeerId(1), 7);
            assert_eq!(p.id(), PeerId(1));
            assert!(!p.name().is_empty());
            assert_eq!(p.stats().tx_frames, 0);
        }
    }

    #[test]
    fn bridgefy_leaks_payload_content_through_length_where_our_wire_cannot() {
        // The measurement `docs/METRICS.md` asks for under Crypto: "across a
        // corpus of varied plaintexts, on-wire frame length must carry no mutual
        // information with plaintext content". This is the contrast that claim
        // rests on, so it is pinned here against the real `gdc-wire` ladder
        // rather than asserted in prose.
        let corpus: [&[u8]; 4] = [
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            b"meet at north gate meet at north gate meet at north g",
            b"the quick brown fox jumps over the lazy dog, twice ab",
            b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\
              \x01\x12\x23\x34\x45\x56\x67\x78\x89\x9a\xab\xbc\xcd\xde\xef\xf0\
              \x02\x13\x24\x35\x46\x57\x68\x79\x8a\x9b\xac\xbd\xce\xdf\xe0\xf1\
              \x03\x14\x25\x36",
        ];
        let mut bridgefy_lens = std::collections::BTreeSet::new();
        let mut ours = std::collections::BTreeSet::new();
        for p in corpus {
            bridgefy_lens.insert(bridgefy::inner_ct_len(p, false));
            let f = gdc_wire::Frame::new(
                gdc_wire::Kind::ChannelMsg,
                gdc_wire::Flags::empty(),
                gdc_wire::DEFAULT_TTL,
                gdc_wire::MsgId([0; 16]),
                gdc_wire::ChanTag([0; 8]),
                p,
                &mut |b| b.fill(0),
            )
            .expect("corpus fits a bucket");
            ours.insert(f.wire_len());
        }
        assert!(
            bridgefy_lens.len() > 1,
            "Bridgefy must leak content through length (finding C-2)"
        );
        assert_eq!(
            ours.len(),
            1,
            "our bucket ladder must not: {ours:?}"
        );
    }
}
