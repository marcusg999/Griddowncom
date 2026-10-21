//! Model 1 — Bridgefy.
//!
//! Specification: `docs/research/BRIDGEFY-FINDINGS.md`, **Part 1**, plus the
//! behaviour implied by Part 2's findings. Every parameter below cites the
//! section it came from. Nothing here is tuned; where the sources do not pin a
//! behaviour down the choice is marked `ASSUMPTION:` and states which way it
//! cuts.
//!
//! What this model reproduces
//! --------------------------
//!
//! * **Pure controlled flood.** Part 1, Routing: "No neighbour tables, no
//!   topology map, no source routes, no link quality. A multi-hop packet is
//!   flooded until it happens to reach the addressed `receiver`." There is
//!   therefore no neighbour table, no degree awareness, no link-quality input
//!   and no subsetting anywhere in this file. `Event::LinkUp`'s `rssi_dbm` is
//!   accepted and discarded, deliberately.
//! * **The `hops` TTL**, one byte, decremented per forward, discarded at zero.
//!   Part 1, Packet structure and Routing. Default profile TTL 100.
//! * **The full propagation-profile table** as selectable configs. Part 1,
//!   Propagation profiles.
//! * **`track` carried but not used.** See [`ForwardPacket::track`] and the
//!   loud comment there. This is the single most important faithfulness claim
//!   in the file and the one a critic should attack first.
//! * **Relay before parse.** Part 1, Processing order: "Receive -> assemble ->
//!   relay to network -> decompress and decrypt -> process."
//! * **`MessagePack -> gzip -> encrypt`,** so on-wire length varies with
//!   payload content. Part 1, Encoding pipeline, and finding C-2.
//! * **Direct-link-only handshake, 4 messages, trust on first use.** Part 1,
//!   Crypto placement.
//!
//! What this model does not reproduce, and why
//! -------------------------------------------
//!
//! No real cryptography: AES-ECB, libsignal and gzip are modelled for their
//! size and their information leakage, not performed (see [`crate::sizing`]).
//! The attacks in Part 2 are not implemented as attacks; the *properties* they
//! exploit are present and measurable, which is what a comparison needs.

use std::collections::{BTreeMap, HashMap, VecDeque};

use crate::hash::crc32;
use crate::proto::{Action, Dest, Event, LinkParams, MeshProtocol, PeerId, ProtoError, Stats, TimeMs};
use crate::sizing::{self, MsgPack};

/// A Bridgefy userId. Part 1, Packet structure: `sender`/`receiver` are UUIDs.
///
/// Note that it is **static for the lifetime of the install**, which is finding
/// P-1 (static identifiers in `ADV_IND`, no resolvable private addresses) and
/// P-2 (plaintext social graph). Deriving it from the node index rather than
/// rotating it is the faithful choice, not a shortcut.
pub type Uuid = [u8; 16];

/// Deterministic userId for a simulated node.
pub fn uuid_of(node: PeerId) -> Uuid {
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&node.0.to_le_bytes());
    out[8..].copy_from_slice(&0xB7_1D_6E_F4_u32.to_le_bytes().repeat(2));
    out
}

// ---------------------------------------------------------------------------
// Propagation profiles
// ---------------------------------------------------------------------------

/// One row of the propagation-profile table.
///
/// Source: `docs/research/BRIDGEFY-FINDINGS.md`, Part 1, "Propagation profiles".
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Profile {
    pub name: &'static str,
    /// `Hops` column. The initial value of the one-byte `hops` field.
    pub hops: u8,
    /// `TTL (s)` column: how long the message itself remains alive.
    pub ttl_secs: u64,
    /// `Sharing time` column, milliseconds.
    pub sharing_time_ms: u64,
    /// `Max propagation` column. See [`BridgefyConfig::max_propagation_is_per_message`].
    pub max_propagation: u32,
    /// `Tracklist` column: how many CRC-32 entries `track` carries.
    pub tracklist: usize,
    /// The `profile` field's on-wire value. ASSUMPTION: the table gives names,
    /// not enum values. The number is one MessagePack byte either way, so the
    /// choice is behaviourally inert; it is listed so no reviewer wonders.
    pub wire_id: u8,
}

/// Standard. The default profile: **TTL 100**.
///
/// Part 1: "A default TTL of **100 hops** in a flood with no degree awareness
/// is the performance target we intend to destroy." Also `gdc-wire`'s
/// `DEFAULT_TTL` comment. 100 fits one byte, consistent with the one-byte
/// `hops` field; so does Long Reach's 250.
pub const STANDARD: Profile = Profile {
    name: "Standard",
    hops: 100,
    ttl_secs: 86_400,
    sharing_time_ms: 15_000,
    max_propagation: 200,
    tracklist: 50,
    wire_id: 0,
};

/// High Density. Part 1, Propagation profiles.
pub const HIGH_DENSITY: Profile = Profile {
    name: "HighDensity",
    hops: 50,
    ttl_secs: 3_600,
    sharing_time_ms: 10_000,
    max_propagation: 50,
    tracklist: 50,
    wire_id: 1,
};

/// Sparse. Part 1, Propagation profiles.
pub const SPARSE: Profile = Profile {
    name: "Sparse",
    hops: 100,
    ttl_secs: 302_400,
    sharing_time_ms: 10_000,
    max_propagation: 250,
    tracklist: 50,
    wire_id: 2,
};

/// Long Reach. Part 1, Propagation profiles. The 250-hop profile.
pub const LONG_REACH: Profile = Profile {
    name: "LongReach",
    hops: 250,
    ttl_secs: 604_800,
    sharing_time_ms: 15_000,
    max_propagation: 1_000,
    tracklist: 50,
    wire_id: 3,
};

/// Short Reach. Part 1, Propagation profiles.
pub const SHORT_REACH: Profile = Profile {
    name: "ShortReach",
    hops: 50,
    ttl_secs: 1_800,
    sharing_time_ms: 10_000,
    max_propagation: 50,
    tracklist: 50,
    wire_id: 4,
};

/// Every profile in the published table, in table order.
pub const ALL_PROFILES: [Profile; 5] = [STANDARD, HIGH_DENSITY, SPARSE, LONG_REACH, SHORT_REACH];

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Behaviours the sources do not pin down, collected in one place so a critic
/// can see the whole set of judgement calls at a glance and flip any of them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BridgefyConfig {
    pub profile: Profile,

    /// Whether a relay excludes the link a packet arrived on.
    ///
    /// ASSUMPTION. Part 1 describes a flood with `track` unused and says
    /// nothing about split horizon. **Default `true`, which favours Bridgefy**:
    /// excluding the ingress link strictly lowers its transmissions per
    /// delivered message, the `docs/METRICS.md` Routing figure we are trying to
    /// beat. Set `false` for the literal "flood to every connection" reading.
    pub split_horizon: bool,

    /// Whether the node keeps a seen-set and refuses to relay a repeat.
    ///
    /// **Default `false`, which is what the source describes**: Part 1, Routing
    /// says loop control is "the `hops` TTL plus the (apparently unused) `track`
    /// CRC list", and Part 1, Packet structure records that `track` "appears
    /// unused otherwise". Setting this `true` gives Bridgefy duplicate
    /// suppression it is not documented to have; it is offered only so the
    /// harness can run the charitable variant and report both numbers. Doing so
    /// improves Bridgefy's flood efficiency by a large factor, so the default
    /// must stay `false` or we are reporting a comparison against a protocol
    /// nobody published.
    pub dedup_seen: bool,

    /// Whether the addressed receiver stops relaying a packet it has consumed.
    ///
    /// ASSUMPTION. **Default `true`, which favours Bridgefy** by saving
    /// transmissions. The literal reading of the Part 1 processing order
    /// (relay happens before the payload is even looked at) argues for `false`;
    /// the routing text's "flooded until it happens to reach the addressed
    /// `receiver`" argues for `true`. Note that other nodes keep flooding
    /// regardless, because nothing tells them the packet arrived.
    pub receiver_stops_relay: bool,

    /// Whether UUID fields serialise as 36-character strings.
    ///
    /// ASSUMPTION. Part 1 shows `payload: Map<String,Object>`, so keys are
    /// strings, but does not say how a UUID value is encoded. A Java/Android
    /// MessagePack mapping of `java.util.UUID` commonly goes via its string
    /// form (38 wire bytes) rather than 16 raw bytes (18 wire bytes).
    /// **Default `false` (binary), which favours Bridgefy** by about 20 bytes
    /// per UUID field, i.e. ~60 bytes per `ForwardPacket`, understating its
    /// airtime.
    pub uuid_as_string: bool,

    /// Whether `max_propagation` is read as a per-node, per-message cap on
    /// relay transmissions.
    ///
    /// ASSUMPTION, and the one that makes an unsuppressed flood simulable at
    /// all. The profile table's `Max propagation` column (200 for Standard) is
    /// unexplained in the source. A per-node-per-message cap is the only
    /// reading a node can enforce locally. It cuts **both** ways: it lowers
    /// Bridgefy's transmission count, which flatters its efficiency number,
    /// and it bounds its reach, which costs it delivery. At 200 against the
    /// node degrees in our scenarios it rarely binds; where it does, the
    /// harness should report that it bound.
    pub max_propagation_is_per_message: bool,

    /// Ceiling on a single application payload. House style: "every allocation
    /// driven by remote input has an explicit ceiling" (`docs/BRIEF.md`).
    ///
    /// ASSUMPTION: the sources give no Bridgefy payload limit. 2048 is set well
    /// above our own product's 500-byte body (`gdc-wire::MAX_BODY_LEN`), which
    /// favours Bridgefy — it is allowed to carry messages our stack would
    /// refuse.
    pub max_app_payload: usize,

    /// How many recent packets stay available for re-offer during `sharing_time`.
    /// ASSUMPTION on the depth only; the window itself is the profile's
    /// `Sharing time` column. A deeper buffer favours Bridgefy.
    pub sharing_buffer: usize,

    /// Ceiling on the per-message propagation-counter table. Bounded because it
    /// is driven by remote input. Eviction makes a node forget a message it has
    /// already relayed to exhaustion, so it may relay more: that favours
    /// Bridgefy's delivery and costs it airtime.
    pub propagation_table_cap: usize,

    /// Link parameters. Owned by `gdc-sim`; see [`LinkParams`].
    pub link: LinkParams,
}

impl Default for BridgefyConfig {
    fn default() -> Self {
        BridgefyConfig {
            profile: STANDARD,
            split_horizon: true,
            dedup_seen: false,
            receiver_stops_relay: true,
            uuid_as_string: false,
            max_propagation_is_per_message: true,
            max_app_payload: 2048,
            sharing_buffer: 128,
            propagation_table_cap: 4096,
            link: LinkParams::PLACEHOLDER,
        }
    }
}

// ---------------------------------------------------------------------------
// Packet types — the field set from Part 1, Packet structure
// ---------------------------------------------------------------------------

/// `BleEntity<T>.et`. ASSUMPTION on the numbering: Part 1 gives `et: int` and
/// the three content types but no values. One MessagePack byte either way.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum EntityType {
    /// `BleHandshake`. AES-ECB on metadata and payload both.
    Handshake = 0,
    /// `BleEntityContent`: direct one-to-one, carries no routing fields.
    EntityContent = 1,
    /// `ForwardTransaction`: the mesh type.
    ForwardTransaction = 2,
}

impl EntityType {
    fn from_u8(v: u8) -> Result<Self, ProtoError> {
        Ok(match v {
            0 => EntityType::Handshake,
            1 => EntityType::EntityContent,
            2 => EntityType::ForwardTransaction,
            other => return Err(ProtoError::UnknownType(other)),
        })
    }
}

/// `receiver_type`: Part 1, Packet structure — "1 = broadcast, 0 = multi-hop".
pub const RECEIVER_TYPE_BROADCAST: u8 = 1;
pub const RECEIVER_TYPE_MULTIHOP: u8 = 0;

/// `ForwardPacket`, exactly the field set in Part 1, Packet structure.
///
/// The field set is reproduced in full — including fields this model never
/// reads — because per-packet overhead has to be realistic rather than guessed.
/// `creation`/`expiration`/`profile` cost bytes on every hop whether or not a
/// relay consults them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ForwardPacket {
    pub id: Uuid,
    /// The message, under key `"ct"` of `payload: Map<String,Object>`, after
    /// `MessagePack -> gzip -> encrypt`. Held here as the modelled ciphertext
    /// length plus the plaintext the simulator needs to deliver.
    pub payload: Payload,
    /// Original author. Travels in clear; finding P-2.
    pub sender: Uuid,
    /// Empty for broadcast.
    pub receiver: Option<Uuid>,
    pub creation: u64,
    pub expiration: u64,
    pub receiver_type: u8,
    /// The TTL. One byte, decremented per forward, discarded at zero.
    pub hops: u8,
    pub profile: u8,
    /// CRC-32 of the last n relay userIds.
    ///
    /// ==================== BEHAVIOURAL CLAIM, READ THIS ====================
    /// This list is **carried and never consulted**. It costs bytes on every
    /// hop and prevents nothing.
    ///
    /// Source: `docs/research/BRIDGEFY-FINDINGS.md`, Part 1, Packet structure:
    /// 'The paper notes `track` "appears unused otherwise" — i.e. it is carried
    /// but not actually relied on for loop suppression.' And Part 1, Routing:
    /// "Loop control is the `hops` TTL plus the (apparently unused) `track` CRC
    /// list."
    ///
    /// A critic auditing this crate for a weakened opponent should check that
    /// this is still true, because *using* `track` is the single cheapest way to
    /// make Bridgefy look better than it was published to be, and it would be
    /// invisible in a benchmark. [`Bridgefy::stats`]'s `loops_forwarded`
    /// counter exists so the loops this omission causes can be counted rather
    /// than argued about: it increments every time a node forwards a packet
    /// whose `track` already contains that node's own CRC-32.
    ///
    /// The charitable variant is [`BridgefyConfig::dedup_seen`], which is a
    /// *stronger* suppression than `track` would give and is available to the
    /// harness. The default is the published behaviour.
    /// ======================================================================
    pub track: Vec<u32>,
}

/// The inner payload after the modelled `MessagePack -> gzip -> encrypt`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Payload {
    /// Plaintext, carried so the simulator can deliver a message. The baselines
    /// model crypto rather than performing it; nothing in the protocol logic
    /// reads this before the modelled decrypt step.
    pub plain: Vec<u8>,
    /// Modelled ciphertext length in bytes. Content-dependent, because gzip
    /// runs before encryption (finding C-2).
    pub ct_len: usize,
    /// Set on a crafted packet whose payload cannot be parsed after
    /// decompression: the shape of finding D-1's decompression bomb. The
    /// envelope still parses, so the relay still happens first.
    pub malformed: bool,
}

/// `ForwardTransaction { dump: bool, sender: UUID }` plus its `ForwardPacket 1..*`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ForwardTransaction {
    pub dump: bool,
    /// **Last relay**, not the author. Part 1, Packet structure.
    pub sender: Uuid,
    pub packets: Vec<ForwardPacket>,
}

/// `BleEntity<T> { id: UUID, et: int, ct: T }`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BleEntity {
    pub id: Uuid,
    pub et: EntityType,
    pub ct: EntityBody,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum EntityBody {
    /// 4-message handshake, direct link only. Part 1, Crypto placement.
    Handshake(HandshakeMsg),
    /// `BleEntityContent { id: UUID, payload: Map<String,Object> }` — direct,
    /// no routing fields.
    Content { id: Uuid, payload: Payload },
    Forward(ForwardTransaction),
}

/// The four handshake messages, in order. Part 1, Crypto placement:
///
/// ```text
/// A -> B : ResponseTypeGeneral(userIdA)      // plaintext userId
/// B -> A : ResponseTypeGeneral(userIdB)
/// A -> B : ResponseTypeKey(PKBA)
/// B -> A : ResponseTypeKey(PKBB)
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandshakeMsg {
    /// Step 1 or 2: a userId, in plaintext. Finding A-1: userId is treated as
    /// identity and is never authenticated.
    General { user_id: Uuid },
    /// Step 3 or 4: a public key bundle, trusted on first use. Finding A-2:
    /// survived the libsignal migration because PKBs are trusted on first use
    /// with no verification path, and Part 1: "No key verification exists
    /// anywhere in the UI."
    Key { user_id: Uuid, pkb: [u8; 32] },
}

// ---------------------------------------------------------------------------
// Sizing: MessagePack -> gzip -> encrypt
// ---------------------------------------------------------------------------

/// Modelled length of the inner message after `MessagePack -> gzip -> encrypt`.
///
/// Part 1, Encoding pipeline. The order is the whole point: gzip sees the
/// plaintext, so the ciphertext length — and therefore the on-wire frame length
/// — carries information about plaintext *content*, not merely its length. That
/// is finding C-2, and it is what `gdc-wire`'s fixed bucket ladder exists to
/// kill.
///
/// `libsignal` is applied for one-to-one and multi-hop payloads and the
/// network-wide AES-ECB key for broadcast (Part 1, Crypto placement), but both
/// sit *after* gzip, so both inherit the leak. The published attack was
/// demonstrated on broadcast; the pipeline as stated applies uniformly, and
/// this model applies it uniformly rather than picking the reading that makes
/// Bridgefy look better or worse.
pub fn inner_ct_len(plain: &[u8], libsignal: bool) -> usize {
    // The message object: `payload: Map<String,Object>` with the message under
    // key "ct". ASSUMPTION: a single-key inner map. A richer inner object would
    // add bytes, so the minimal one favours Bridgefy.
    let mut m = MsgPack::new();
    m.map_header(1).str("ct").bin(plain);
    let packed = m.into_bytes();
    let gz = sizing::gzip_len(&packed);
    if libsignal {
        gz + sizing::LIBSIGNAL_OVERHEAD
    } else {
        sizing::aes_ecb_len(gz)
    }
}

fn uuid_field(m: &mut MsgPack, u: &Uuid, as_string: bool) {
    if as_string {
        // 36 characters, 8-4-4-4-12.
        let mut s = String::with_capacity(36);
        for (i, b) in u.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                s.push('-');
            }
            s.push_str(&format!("{b:02x}"));
        }
        m.str(&s);
    } else {
        m.bin(u);
    }
}

/// Modelled on-wire octets of one `BleEntity`, after MessagePack and the
/// AES-ECB metadata layer.
///
/// Part 1, Crypto placement: metadata is AES-ECB under a single network-wide
/// key compiled into the app (finding C-4), so every field below is readable by
/// any participant and by anyone who pulled the key out of the binary. AES-ECB
/// is length-preserving apart from PKCS#7 padding, so the content-dependent
/// inner length survives to the wire at 16-byte granularity.
pub fn entity_wire_len(e: &BleEntity, cfg: &BridgefyConfig) -> usize {
    let mut m = MsgPack::new();
    m.map_header(3).str("id");
    uuid_field(&mut m, &e.id, cfg.uuid_as_string);
    m.str("et").uint(e.et as u64).str("ct");
    match &e.ct {
        EntityBody::Handshake(h) => match h {
            HandshakeMsg::General { user_id } => {
                m.map_header(1).str("userId");
                uuid_field(&mut m, user_id, cfg.uuid_as_string);
            }
            HandshakeMsg::Key { user_id, pkb } => {
                m.map_header(2).str("userId");
                uuid_field(&mut m, user_id, cfg.uuid_as_string);
                m.str("pkb").bin(pkb);
            }
        },
        EntityBody::Content { id, payload } => {
            m.map_header(2).str("id");
            uuid_field(&mut m, id, cfg.uuid_as_string);
            m.str("payload").map_header(1).str("ct");
            // Only the length matters; MessagePack's bin header width depends on
            // it, so write a correctly-sized placeholder.
            m.bin(&vec![0u8; payload.ct_len]);
        }
        EntityBody::Forward(ft) => {
            m.map_header(3).str("dump").boolean(ft.dump).str("sender");
            uuid_field(&mut m, &ft.sender, cfg.uuid_as_string);
            m.str("packets").array_header(ft.packets.len());
            for p in &ft.packets {
                m.map_header(10).str("id");
                uuid_field(&mut m, &p.id, cfg.uuid_as_string);
                m.str("payload").map_header(1).str("ct");
                m.bin(&vec![0u8; p.payload.ct_len]);
                m.str("sender");
                uuid_field(&mut m, &p.sender, cfg.uuid_as_string);
                m.str("receiver");
                match &p.receiver {
                    Some(r) => uuid_field(&mut m, r, cfg.uuid_as_string),
                    // "empty for broadcast".
                    None => {
                        m.str("");
                    }
                }
                m.str("creation").uint(p.creation);
                m.str("expiration").uint(p.expiration);
                m.str("receiver_type").uint(p.receiver_type as u64);
                m.str("hops").uint(p.hops as u64);
                m.str("profile").uint(p.profile as u64);
                m.str("track").array_header(p.track.len());
                for t in &p.track {
                    m.uint(*t as u64);
                }
            }
        }
    }
    sizing::aes_ecb_len(m.len())
}

// ---------------------------------------------------------------------------
// Internal frame encoding
// ---------------------------------------------------------------------------
//
// Not the modelled wire format. This is a plain, bounds-checked byte layout so
// one simulated node can parse what another emitted; the modelled on-air octet
// count travels in its first four bytes and is what the harness charges for.
// Stated in `Action::Tx`'s documentation as well, because a critic must be able
// to see that `wire_len` comes from the documented pipeline and not from
// `frame.len()`.

const F_HANDSHAKE_GENERAL: u8 = 0;
const F_HANDSHAKE_KEY: u8 = 1;
const F_CONTENT: u8 = 2;
const F_FORWARD: u8 = 3;

/// Reader that cannot panic: every read is length-checked.
struct Rd<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Rd<'a> {
    fn new(b: &'a [u8]) -> Self {
        Rd { b, i: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        let end = self.i.checked_add(n).ok_or(ProtoError::BadField("overflow"))?;
        let s = self.b.get(self.i..end).ok_or(ProtoError::Truncated {
            need: end,
            got: self.b.len(),
        })?;
        self.i = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, ProtoError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, ProtoError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, ProtoError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, ProtoError> {
        let s = self.take(8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        Ok(u64::from_le_bytes(a))
    }
    fn uuid(&mut self) -> Result<Uuid, ProtoError> {
        let s = self.take(16)?;
        let mut a = [0u8; 16];
        a.copy_from_slice(s);
        Ok(a)
    }
}

fn put_u16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}

fn encode_frame(e: &BleEntity, wire_len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(&(wire_len.min(u32::MAX as usize) as u32).to_le_bytes());
    v.extend_from_slice(&e.id);
    match &e.ct {
        EntityBody::Handshake(HandshakeMsg::General { user_id }) => {
            v.push(F_HANDSHAKE_GENERAL);
            v.extend_from_slice(user_id);
        }
        EntityBody::Handshake(HandshakeMsg::Key { user_id, pkb }) => {
            v.push(F_HANDSHAKE_KEY);
            v.extend_from_slice(user_id);
            v.extend_from_slice(pkb);
        }
        EntityBody::Content { id, payload } => {
            v.push(F_CONTENT);
            v.extend_from_slice(id);
            encode_payload(&mut v, payload);
        }
        EntityBody::Forward(ft) => {
            v.push(F_FORWARD);
            v.push(u8::from(ft.dump));
            v.extend_from_slice(&ft.sender);
            v.push(ft.packets.len().min(u8::MAX as usize) as u8);
            for p in ft.packets.iter().take(u8::MAX as usize) {
                v.extend_from_slice(&p.id);
                v.extend_from_slice(&p.sender);
                match &p.receiver {
                    Some(r) => {
                        v.push(1);
                        v.extend_from_slice(r);
                    }
                    None => v.push(0),
                }
                v.extend_from_slice(&p.creation.to_le_bytes());
                v.extend_from_slice(&p.expiration.to_le_bytes());
                v.push(p.receiver_type);
                v.push(p.hops);
                v.push(p.profile);
                v.push(p.track.len().min(u8::MAX as usize) as u8);
                for t in p.track.iter().take(u8::MAX as usize) {
                    v.extend_from_slice(&t.to_le_bytes());
                }
                encode_payload(&mut v, &p.payload);
            }
        }
    }
    v
}

fn encode_payload(v: &mut Vec<u8>, p: &Payload) {
    put_u16(v, p.ct_len.min(u16::MAX as usize) as u16);
    v.push(u8::from(p.malformed));
    put_u16(v, p.plain.len().min(u16::MAX as usize) as u16);
    v.extend_from_slice(&p.plain);
}

/// Hard ceiling on a decoded plaintext, independent of configuration, so a
/// crafted frame cannot drive an unbounded allocation in the harness.
const DECODE_PLAIN_CEILING: usize = 16 * 1024;

fn decode_payload(r: &mut Rd<'_>) -> Result<Payload, ProtoError> {
    let ct_len = r.u16()? as usize;
    let malformed = r.u8()? != 0;
    let n = r.u16()? as usize;
    if n > DECODE_PLAIN_CEILING {
        return Err(ProtoError::PayloadTooLarge {
            got: n,
            max: DECODE_PLAIN_CEILING,
        });
    }
    let plain = r.take(n)?.to_vec();
    Ok(Payload {
        plain,
        ct_len,
        malformed,
    })
}

/// Parse an internal frame. Never panics; every malformed shape is an error.
pub fn decode_frame(bytes: &[u8]) -> Result<(usize, BleEntity), ProtoError> {
    let mut r = Rd::new(bytes);
    let wire_len = r.u32()? as usize;
    let id = r.uuid()?;
    let tag = r.u8()?;
    let (et, ct) = match tag {
        F_HANDSHAKE_GENERAL => (
            EntityType::Handshake,
            EntityBody::Handshake(HandshakeMsg::General { user_id: r.uuid()? }),
        ),
        F_HANDSHAKE_KEY => {
            let user_id = r.uuid()?;
            let s = r.take(32)?;
            let mut pkb = [0u8; 32];
            pkb.copy_from_slice(s);
            (
                EntityType::Handshake,
                EntityBody::Handshake(HandshakeMsg::Key { user_id, pkb }),
            )
        }
        F_CONTENT => {
            let cid = r.uuid()?;
            let payload = decode_payload(&mut r)?;
            (
                EntityType::EntityContent,
                EntityBody::Content { id: cid, payload },
            )
        }
        F_FORWARD => {
            let dump = r.u8()? != 0;
            let sender = r.uuid()?;
            let n = r.u8()? as usize;
            let mut packets = Vec::with_capacity(n.min(16));
            for _ in 0..n {
                let pid = r.uuid()?;
                let psender = r.uuid()?;
                let receiver = if r.u8()? != 0 { Some(r.uuid()?) } else { None };
                let creation = r.u64()?;
                let expiration = r.u64()?;
                let receiver_type = r.u8()?;
                let hops = r.u8()?;
                let profile = r.u8()?;
                let tn = r.u8()? as usize;
                let mut track = Vec::with_capacity(tn);
                for _ in 0..tn {
                    track.push(r.u32()?);
                }
                let payload = decode_payload(&mut r)?;
                packets.push(ForwardPacket {
                    id: pid,
                    payload,
                    sender: psender,
                    receiver,
                    creation,
                    expiration,
                    receiver_type,
                    hops,
                    profile,
                    track,
                });
            }
            (
                EntityType::ForwardTransaction,
                EntityBody::Forward(ForwardTransaction {
                    dump,
                    sender,
                    packets,
                }),
            )
        }
        other => return Err(ProtoError::UnknownType(other)),
    };
    let _ = EntityType::from_u8(et as u8)?;
    Ok((wire_len, BleEntity { id, et, ct }))
}

// ---------------------------------------------------------------------------
// The model
// ---------------------------------------------------------------------------

/// Handshake progress on one direct link. Part 1, Crypto placement: four
/// messages, direct link only, never over the mesh.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
struct LinkState {
    sent_general: bool,
    got_general: bool,
    sent_key: bool,
    got_key: bool,
}

impl LinkState {
    fn complete(&self) -> bool {
        self.sent_key && self.got_key
    }
}

/// A trust-on-first-use contact record. There is no verification path anywhere
/// (Part 1: "No key verification exists anywhere in the UI"), so a later key
/// for a known userId simply replaces the old one — findings A-1 and A-2. The
/// replacement is counted rather than refused, because refusing it would be a
/// security property Bridgefy does not have.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Contact {
    pub pkb: [u8; 32],
    pub rebindings: u32,
}

struct Stored {
    entity: BleEntity,
    created: TimeMs,
}

pub struct Bridgefy {
    me: PeerId,
    user_id: Uuid,
    cfg: BridgefyConfig,
    rng: crate::rng::Rng,
    seq: u64,

    /// Live links. This is a *connection* list, not a neighbour table: nothing
    /// in this file reads anything from it but the peer id, because Part 1,
    /// Routing says there is no topology knowledge and no link quality.
    links: BTreeMap<PeerId, LinkState>,
    contacts: BTreeMap<Uuid, Contact>,

    /// Per-message relay counter, for the `max_propagation` cap. Bounded.
    propagations: HashMap<Uuid, u32>,
    propagation_order: VecDeque<Uuid>,

    /// Only populated when [`BridgefyConfig::dedup_seen`] is on, i.e. never by
    /// default.
    seen: HashMap<Uuid, ()>,
    seen_order: VecDeque<Uuid>,

    /// Message ids already handed to the application, so a delivery is counted
    /// once however many copies the flood brings.
    delivered: HashMap<Uuid, ()>,
    delivered_order: VecDeque<Uuid>,

    /// Packets still inside their profile's `Sharing time`, re-offered to a peer
    /// that has just connected.
    sharing: VecDeque<Stored>,

    stats: Stats,
}

impl Bridgefy {
    pub fn new(me: PeerId, seed: u64, cfg: BridgefyConfig) -> Self {
        Bridgefy {
            me,
            user_id: uuid_of(me),
            cfg,
            rng: crate::rng::Rng::derived(seed, me.0, 0xB_1D6E),
            seq: 0,
            links: BTreeMap::new(),
            contacts: BTreeMap::new(),
            propagations: HashMap::new(),
            propagation_order: VecDeque::new(),
            seen: HashMap::new(),
            seen_order: VecDeque::new(),
            delivered: HashMap::new(),
            delivered_order: VecDeque::new(),
            sharing: VecDeque::new(),
            stats: Stats::default(),
        }
    }

    pub fn config(&self) -> &BridgefyConfig {
        &self.cfg
    }

    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    pub fn contact(&self, user: &Uuid) -> Option<Contact> {
        self.contacts.get(user).copied()
    }

    pub fn degree(&self) -> usize {
        self.links.len()
    }

    fn fresh_uuid(&mut self) -> Uuid {
        self.seq = self.seq.wrapping_add(1);
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.rng.next_u64().to_le_bytes());
        out[8..].copy_from_slice(&self.seq.to_le_bytes());
        out
    }

    fn tx(&mut self, peer: PeerId, e: &BleEntity, out: &mut Vec<Action>, is_relay: bool) {
        let wire_len = entity_wire_len(e, &self.cfg);
        self.stats.tx_frames += 1;
        self.stats.tx_bytes += wire_len as u64;
        if is_relay {
            self.stats.relayed += 1;
        }
        out.push(Action::Tx {
            peer,
            wire_len,
            frame: encode_frame(e, wire_len),
        });
    }

    /// Every link, optionally minus the one a packet arrived on.
    ///
    /// No degree awareness, no subsetting, no ordering by quality: Part 1,
    /// Routing. The sort is only so a replay is deterministic.
    fn flood_targets(&self, ingress: Option<PeerId>) -> Vec<PeerId> {
        self.links
            .keys()
            .copied()
            .filter(|p| !(self.cfg.split_horizon && Some(*p) == ingress))
            .collect()
    }

    fn note_bounded(map: &mut HashMap<Uuid, ()>, order: &mut VecDeque<Uuid>, k: Uuid, cap: usize) {
        if map.insert(k, ()).is_none() {
            order.push_back(k);
            while order.len() > cap {
                if let Some(old) = order.pop_front() {
                    map.remove(&old);
                }
            }
        }
    }

    /// Relay budget check against the profile's `Max propagation`.
    fn may_propagate(&mut self, id: Uuid) -> bool {
        if !self.cfg.max_propagation_is_per_message {
            return true;
        }
        let cap = self.cfg.profile.max_propagation;
        let n = self.propagations.entry(id).or_insert_with(|| {
            // Insertion order is tracked separately so the table stays bounded.
            0
        });
        if *n >= cap {
            return false;
        }
        *n += 1;
        if *n == 1 {
            self.propagation_order.push_back(id);
            while self.propagation_order.len() > self.cfg.propagation_table_cap {
                if let Some(old) = self.propagation_order.pop_front() {
                    self.propagations.remove(&old);
                }
            }
        }
        true
    }

    fn originate(
        &mut self,
        now: TimeMs,
        dest: Dest,
        payload: &[u8],
        out: &mut Vec<Action>,
    ) -> Result<(), ProtoError> {
        if payload.len() > self.cfg.max_app_payload {
            return Err(ProtoError::PayloadTooLarge {
                got: payload.len(),
                max: self.cfg.max_app_payload,
            });
        }
        let (receiver, receiver_type, libsignal) = match dest {
            Dest::Broadcast => (None, RECEIVER_TYPE_BROADCAST, false),
            // Part 1, Crypto placement: libsignal covers the payload of
            // one-to-one and multi-hop packets. Finding A-2 shows the app will
            // fetch or refresh a public key for an *out-of-range* peer, which
            // is why a multi-hop packet to a peer we have never met directly is
            // modelled as sendable at all. Refusing it would turn Bridgefy into
            // a strawman on the `docs/METRICS.md` M2 chain test.
            Dest::Peer(p) => (Some(uuid_of(p)), RECEIVER_TYPE_MULTIHOP, true),
        };
        let id = self.fresh_uuid();
        let pkt = ForwardPacket {
            id,
            payload: Payload {
                plain: payload.to_vec(),
                ct_len: inner_ct_len(payload, libsignal),
                malformed: false,
            },
            sender: self.user_id,
            receiver,
            creation: now.0,
            expiration: now.0.saturating_add(self.cfg.profile.ttl_secs.saturating_mul(1000)),
            receiver_type,
            hops: self.cfg.profile.hops,
            profile: self.cfg.profile.wire_id,
            // The author seeds `track` with its own CRC-32. It will be appended
            // to at every relay and consulted by nobody.
            track: vec![crc32(&self.user_id)],
        };
        let entity = BleEntity {
            id: self.fresh_uuid(),
            et: EntityType::ForwardTransaction,
            ct: EntityBody::Forward(ForwardTransaction {
                dump: false,
                sender: self.user_id,
                packets: vec![pkt],
            }),
        };
        for peer in self.flood_targets(None) {
            self.tx(peer, &entity, out, false);
        }
        self.remember_for_sharing(now, entity);
        Ok(())
    }

    fn remember_for_sharing(&mut self, now: TimeMs, entity: BleEntity) {
        self.sharing.push_back(Stored {
            entity,
            created: now,
        });
        while self.sharing.len() > self.cfg.sharing_buffer {
            self.sharing.pop_front();
        }
    }

    /// Re-offer everything still inside the profile's `Sharing time` to a peer
    /// that has just connected.
    ///
    /// Source: the `Sharing time` column of Part 1's propagation-profile table
    /// (15 000 ms on Standard). The column exists, so the behaviour has to:
    /// without it Bridgefy would have no store-and-forward at all and would
    /// lose the `docs/METRICS.md` M2 carrier regime by construction, which
    /// would be a strawman. `dump` is set on these transactions. ASSUMPTION on
    /// that last detail only — Part 1 gives `dump: bool` without semantics, and
    /// it is one byte.
    fn share_on_connect(&mut self, now: TimeMs, peer: PeerId, out: &mut Vec<Action>) {
        let window = self.cfg.profile.sharing_time_ms;
        let due: Vec<BleEntity> = self
            .sharing
            .iter()
            .filter(|s| now.elapsed_since(s.created) <= window)
            .map(|s| {
                let mut e = s.entity.clone();
                if let EntityBody::Forward(ft) = &mut e.ct {
                    ft.dump = true;
                    ft.sender = self.user_id;
                }
                e
            })
            .collect();
        for e in due {
            self.tx(peer, &e, out, true);
        }
    }

    /// The Part 1 processing order, in order.
    fn on_forward_transaction(
        &mut self,
        now: TimeMs,
        from: PeerId,
        ft: ForwardTransaction,
        out: &mut Vec<Action>,
    ) -> Result<(), ProtoError> {
        let mut first_err = None;
        for pkt in ft.packets {
            // -- relay to network -------------------------------------------
            // Before decompressing, before decrypting, before parsing the
            // payload. Part 1, Processing order. This is the mechanism that
            // turned finding D-1's single malformed message into a
            // network-wide outage, so the ordering is the behaviour, not an
            // implementation detail.
            let relayed_now = self.relay(now, from, &pkt, out);

            // -- decompress and decrypt, then process -----------------------
            if pkt.payload.malformed {
                // The payload never parses. The relay above already happened.
                self.stats.dropped_malformed += 1;
                if relayed_now > 0 {
                    self.stats.relayed_before_parse += relayed_now as u64;
                }
                if first_err.is_none() {
                    first_err = Some(ProtoError::BadField("payload failed to decompress"));
                }
                continue;
            }
            if relayed_now > 0 {
                self.stats.relayed_before_parse += relayed_now as u64;
            }
            self.process(now, from, &pkt, out);
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Returns how many transmissions the relay produced.
    fn relay(
        &mut self,
        now: TimeMs,
        from: PeerId,
        pkt: &ForwardPacket,
        out: &mut Vec<Action>,
    ) -> usize {
        // The one-byte TTL. Decremented per forward, discarded at zero.
        if pkt.hops == 0 {
            self.stats.dropped_ttl += 1;
            return 0;
        }
        if now.0 >= pkt.expiration {
            self.stats.dropped_ttl += 1;
            return 0;
        }
        if self.cfg.dedup_seen {
            // Off by default; see BridgefyConfig::dedup_seen.
            if self.seen.contains_key(&pkt.id) {
                self.stats.dup_rx += 1;
                return 0;
            }
            Self::note_bounded(
                &mut self.seen,
                &mut self.seen_order,
                pkt.id,
                self.cfg.propagation_table_cap,
            );
        }
        if self.cfg.receiver_stops_relay && pkt.receiver == Some(self.user_id) {
            return 0;
        }
        if !self.may_propagate(pkt.id) {
            self.stats.dropped_full += 1;
            return 0;
        }

        let mine = crc32(&self.user_id);
        if pkt.track.contains(&mine) {
            // We have already carried this packet and we are about to carry it
            // again, because `track` is not consulted. Counted so the loop is a
            // number in the report instead of an argument.
            self.stats.loops_forwarded += 1;
        }

        let mut next = pkt.clone();
        next.hops -= 1;
        if next.hops == 0 {
            self.stats.dropped_ttl += 1;
            return 0;
        }
        // Append our CRC-32 and keep the list to the profile's Tracklist length.
        next.track.push(mine);
        let keep = self.cfg.profile.tracklist;
        if next.track.len() > keep {
            let drop = next.track.len() - keep;
            next.track.drain(..drop);
        }

        let entity = BleEntity {
            id: self.fresh_uuid(),
            et: EntityType::ForwardTransaction,
            ct: EntityBody::Forward(ForwardTransaction {
                // `sender` on the transaction is the *last relay*: us.
                dump: false,
                sender: self.user_id,
                packets: vec![next],
            }),
        };
        let targets = self.flood_targets(Some(from));
        for peer in &targets {
            self.tx(*peer, &entity, out, true);
        }
        self.remember_for_sharing(now, entity);
        targets.len()
    }

    fn process(&mut self, _now: TimeMs, from: PeerId, pkt: &ForwardPacket, out: &mut Vec<Action>) {
        let for_me = match pkt.receiver_type {
            RECEIVER_TYPE_BROADCAST => true,
            _ => pkt.receiver == Some(self.user_id),
        };
        if !for_me {
            return;
        }
        if self.delivered.contains_key(&pkt.id) {
            self.stats.dup_rx += 1;
            return;
        }
        Self::note_bounded(
            &mut self.delivered,
            &mut self.delivered_order,
            pkt.id,
            self.cfg.propagation_table_cap,
        );
        self.stats.app_delivered += 1;
        out.push(Action::Deliver {
            via: Some(from),
            dest: match pkt.receiver_type {
                RECEIVER_TYPE_BROADCAST => Dest::Broadcast,
                _ => Dest::Peer(self.me),
            },
            payload: pkt.payload.plain.clone(),
        });
    }

    // -- handshake ----------------------------------------------------------

    fn pkb_of(&self, user: &Uuid) -> [u8; 32] {
        // Modelled public key: deterministic from the userId. Not crypto.
        let mut out = [0u8; 32];
        let a = crate::hash::digest64(user);
        for (i, c) in out.chunks_mut(8).enumerate() {
            c.copy_from_slice(&crate::hash::mix64(a, i as u64).to_le_bytes());
        }
        out
    }

    fn start_handshake(&mut self, peer: PeerId, out: &mut Vec<Action>) {
        let st = self.links.entry(peer).or_default();
        if st.sent_general {
            return;
        }
        st.sent_general = true;
        let e = BleEntity {
            id: self.fresh_uuid(),
            et: EntityType::Handshake,
            ct: EntityBody::Handshake(HandshakeMsg::General {
                user_id: self.user_id,
            }),
        };
        self.tx(peer, &e, out, false);
    }

    fn on_handshake(&mut self, peer: PeerId, msg: HandshakeMsg, out: &mut Vec<Action>) {
        // Handshake frames are accepted on a direct link only and are never
        // relayed. Part 1, Crypto placement: "Handshake, over a direct link
        // only, never over the mesh". `gdc-wire::Kind::is_relayable` encodes the
        // same rule structurally for our own stack.
        if !self.links.contains_key(&peer) {
            return;
        }
        match msg {
            HandshakeMsg::General { user_id } => {
                {
                    let st = self.links.entry(peer).or_default();
                    st.got_general = true;
                }
                // Reply with our own userId if we have not already.
                let need_general = !self.links.get(&peer).map(|s| s.sent_general).unwrap_or(false);
                if need_general {
                    self.start_handshake(peer, out);
                }
                // Then step 3: our public key bundle.
                let already = self.links.get(&peer).map(|s| s.sent_key).unwrap_or(false);
                if !already {
                    if let Some(st) = self.links.get_mut(&peer) {
                        st.sent_key = true;
                    }
                    let e = BleEntity {
                        id: self.fresh_uuid(),
                        et: EntityType::Handshake,
                        ct: EntityBody::Handshake(HandshakeMsg::Key {
                            user_id: self.user_id,
                            pkb: self.pkb_of(&self.user_id),
                        }),
                    };
                    self.tx(peer, &e, out, false);
                }
                let _ = user_id;
            }
            HandshakeMsg::Key { user_id, pkb } => {
                if let Some(st) = self.links.get_mut(&peer) {
                    st.got_key = true;
                }
                // Trust on first use, and trust on every subsequent use too:
                // there is no verification path, so a fresh key for a known
                // userId replaces the old binding. Findings A-1 and A-2. We
                // count the rebinding instead of refusing it, because refusing
                // it is a property Bridgefy does not have and giving it one
                // here would be exactly the kind of quiet improvement this
                // crate exists not to make.
                match self.contacts.get_mut(&user_id) {
                    Some(c) => {
                        if c.pkb != pkb {
                            c.pkb = pkb;
                            c.rebindings += 1;
                        }
                    }
                    None => {
                        self.contacts.insert(user_id, Contact { pkb, rebindings: 0 });
                    }
                }
                // Step 4: answer with ours if we have not sent it.
                let already = self.links.get(&peer).map(|s| s.sent_key).unwrap_or(false);
                if !already {
                    if let Some(st) = self.links.get_mut(&peer) {
                        st.sent_key = true;
                    }
                    let e = BleEntity {
                        id: self.fresh_uuid(),
                        et: EntityType::Handshake,
                        ct: EntityBody::Handshake(HandshakeMsg::Key {
                            user_id: self.user_id,
                            pkb: self.pkb_of(&self.user_id),
                        }),
                    };
                    self.tx(peer, &e, out, false);
                }
            }
        }
    }

    /// Whether the 4-message handshake has completed on a link.
    pub fn handshake_complete(&self, peer: PeerId) -> bool {
        self.links.get(&peer).map(|s| s.complete()).unwrap_or(false)
    }

    /// Build a crafted broadcast whose envelope parses and whose payload does
    /// not: the shape of finding D-1's decompression bomb.
    ///
    /// Exposed so the harness can measure the amplification that the
    /// relay-before-parse ordering gives it, rather than taking it on trust.
    pub fn craft_malformed_broadcast(&mut self, now: TimeMs, declared_ct_len: usize) -> Vec<u8> {
        let pkt = ForwardPacket {
            id: self.fresh_uuid(),
            payload: Payload {
                plain: Vec::new(),
                ct_len: declared_ct_len,
                malformed: true,
            },
            sender: self.user_id,
            receiver: None,
            creation: now.0,
            expiration: now.0.saturating_add(self.cfg.profile.ttl_secs.saturating_mul(1000)),
            receiver_type: RECEIVER_TYPE_BROADCAST,
            hops: self.cfg.profile.hops,
            profile: self.cfg.profile.wire_id,
            track: vec![crc32(&self.user_id)],
        };
        let e = BleEntity {
            id: self.fresh_uuid(),
            et: EntityType::ForwardTransaction,
            ct: EntityBody::Forward(ForwardTransaction {
                dump: false,
                sender: self.user_id,
                packets: vec![pkt],
            }),
        };
        let wl = entity_wire_len(&e, &self.cfg);
        encode_frame(&e, wl)
    }
}

impl MeshProtocol for Bridgefy {
    fn name(&self) -> &'static str {
        "bridgefy"
    }

    fn id(&self) -> PeerId {
        self.me
    }

    fn on_event(
        &mut self,
        now: TimeMs,
        ev: Event<'_>,
        out: &mut Vec<Action>,
    ) -> Result<(), ProtoError> {
        match ev {
            // `rssi_dbm` is accepted and dropped on the floor. Part 1, Routing:
            // no link quality awareness. Keeping the parameter unused here is
            // the faithful behaviour.
            Event::LinkUp { peer, rssi_dbm: _ } => {
                self.links.entry(peer).or_default();
                self.start_handshake(peer, out);
                self.share_on_connect(now, peer, out);
                Ok(())
            }
            Event::LinkDown { peer } => {
                self.links.remove(&peer);
                Ok(())
            }
            Event::Rx { peer, bytes } => {
                let (wire_len, entity) = match decode_frame(bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        self.stats.rx_frames += 1;
                        self.stats.dropped_malformed += 1;
                        return Err(e);
                    }
                };
                self.stats.rx_frames += 1;
                self.stats.rx_bytes += wire_len as u64;
                match entity.ct {
                    EntityBody::Handshake(h) => {
                        self.on_handshake(peer, h, out);
                        Ok(())
                    }
                    EntityBody::Content { payload, .. } => {
                        // `BleEntityContent`: direct, no routing fields, never
                        // relayed. Part 1, Packet structure.
                        if payload.malformed {
                            self.stats.dropped_malformed += 1;
                            return Err(ProtoError::BadField("direct payload failed to parse"));
                        }
                        self.stats.app_delivered += 1;
                        out.push(Action::Deliver {
                            via: Some(peer),
                            dest: Dest::Peer(self.me),
                            payload: payload.plain,
                        });
                        Ok(())
                    }
                    EntityBody::Forward(ft) => self.on_forward_transaction(now, peer, ft, out),
                }
            }
            Event::AppSend {
                dest,
                payload,
                want_ack: _,
            } => {
                // Bridgefy has three delivery receipts per message (finding
                // P-3). They are not modelled as frames here: see the handback.
                self.originate(now, dest, payload, out)
            }
        }
    }

    fn on_timer(&mut self, now: TimeMs, _out: &mut Vec<Action>) {
        // No jitter, no scheduled relays, no beacons: a Bridgefy relay goes out
        // on reception. The only time-driven work is expiring the sharing
        // buffer, so there is nothing for the simulator to wake us for.
        let window = self.cfg.profile.sharing_time_ms;
        while let Some(front) = self.sharing.front() {
            if now.elapsed_since(front.created) > window {
                self.sharing.pop_front();
            } else {
                break;
            }
        }
    }

    fn next_timer(&self) -> Option<TimeMs> {
        self.sharing
            .front()
            .map(|s| s.created.saturating_add_ms(self.cfg.profile.sharing_time_ms))
    }

    fn stats(&self) -> Stats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(n: u64) -> Bridgefy {
        Bridgefy::new(PeerId(n), 1, BridgefyConfig::default())
    }

    fn link_up(b: &mut Bridgefy, peer: u64, out: &mut Vec<Action>) {
        b.on_event(
            TimeMs(0),
            Event::LinkUp {
                peer: PeerId(peer),
                rssi_dbm: -70,
            },
            out,
        )
        .unwrap();
    }

    #[test]
    fn profile_table_matches_the_research_file() {
        // docs/research/BRIDGEFY-FINDINGS.md Part 1, Propagation profiles.
        let rows = [
            ("Standard", 100u8, 86_400u64, 15_000u64, 200u32, 50usize),
            ("HighDensity", 50, 3_600, 10_000, 50, 50),
            ("Sparse", 100, 302_400, 10_000, 250, 50),
            ("LongReach", 250, 604_800, 15_000, 1_000, 50),
            ("ShortReach", 50, 1_800, 10_000, 50, 50),
        ];
        for (p, want) in ALL_PROFILES.iter().zip(rows.iter()) {
            assert_eq!(p.name, want.0);
            assert_eq!(p.hops, want.1, "{} hops", p.name);
            assert_eq!(p.ttl_secs, want.2, "{} ttl", p.name);
            assert_eq!(p.sharing_time_ms, want.3, "{} sharing", p.name);
            assert_eq!(p.max_propagation, want.4, "{} maxprop", p.name);
            assert_eq!(p.tracklist, want.5, "{} tracklist", p.name);
        }
        assert_eq!(STANDARD.hops, 100, "the default TTL is the thing to beat");
        // Every profile's hop count fits the one-byte `hops` field.
        assert!(ALL_PROFILES.iter().all(|p| p.hops as u64 <= u8::MAX as u64));
    }

    #[test]
    fn ttl_decrements_once_per_forward_and_dies_at_zero() {
        let mut b = node(1);
        let mut out = Vec::new();
        link_up(&mut b, 2, &mut out);
        out.clear();

        let mut src = node(9);
        let mut tmp = Vec::new();
        link_up(&mut src, 1, &mut tmp);
        tmp.clear();
        src.on_event(
            TimeMs(0),
            Event::AppSend {
                dest: Dest::Broadcast,
                payload: b"x",
                want_ack: false,
            },
            &mut tmp,
        )
        .unwrap();
        let frame = match &tmp[0] {
            Action::Tx { frame, .. } => frame.clone(),
            _ => panic!("expected a transmission"),
        };
        let (_, e) = decode_frame(&frame).unwrap();
        let sent_hops = match &e.ct {
            EntityBody::Forward(ft) => ft.packets[0].hops,
            _ => unreachable!(),
        };
        assert_eq!(sent_hops, 100);

        b.on_event(
            TimeMs(0),
            Event::Rx {
                peer: PeerId(9),
                bytes: &frame,
            },
            &mut out,
        )
        .unwrap();
        let relayed = out
            .iter()
            .find_map(|a| match a {
                Action::Tx { frame, .. } => Some(frame.clone()),
                _ => None,
            })
            .expect("must relay");
        let (_, e2) = decode_frame(&relayed).unwrap();
        match &e2.ct {
            EntityBody::Forward(ft) => assert_eq!(ft.packets[0].hops, 99),
            _ => unreachable!(),
        }
    }

    #[test]
    fn a_hops_one_packet_is_not_forwarded() {
        let mut b = node(1);
        let mut out = Vec::new();
        link_up(&mut b, 2, &mut out);
        link_up(&mut b, 3, &mut out);
        out.clear();
        let frame = hand_built(1, |p| p.hops = 1);
        b.on_event(
            TimeMs(0),
            Event::Rx {
                peer: PeerId(9),
                bytes: &frame,
            },
            &mut out,
        )
        .unwrap();
        assert!(
            !out.iter().any(|a| matches!(a, Action::Tx { .. })),
            "hops 1 decrements to 0 and must not go out"
        );
        assert_eq!(b.stats().dropped_ttl, 1);
    }

    /// Build a ForwardTransaction frame from node 9 with a tweak applied.
    fn hand_built(_to: u64, tweak: impl FnOnce(&mut ForwardPacket)) -> Vec<u8> {
        let cfg = BridgefyConfig::default();
        let mut pkt = ForwardPacket {
            id: [5u8; 16],
            payload: Payload {
                plain: b"hello".to_vec(),
                ct_len: inner_ct_len(b"hello", false),
                malformed: false,
            },
            sender: uuid_of(PeerId(9)),
            receiver: None,
            creation: 0,
            expiration: u64::MAX,
            receiver_type: RECEIVER_TYPE_BROADCAST,
            hops: cfg.profile.hops,
            profile: cfg.profile.wire_id,
            track: vec![crc32(&uuid_of(PeerId(9)))],
        };
        tweak(&mut pkt);
        let e = BleEntity {
            id: [6u8; 16],
            et: EntityType::ForwardTransaction,
            ct: EntityBody::Forward(ForwardTransaction {
                dump: false,
                sender: uuid_of(PeerId(9)),
                packets: vec![pkt],
            }),
        };
        let wl = entity_wire_len(&e, &cfg);
        encode_frame(&e, wl)
    }

    #[test]
    fn track_is_carried_and_never_prevents_a_loop() {
        // The behavioural claim from Part 1. A packet arrives already carrying
        // this node's own CRC-32; a protocol that used `track` would drop it.
        // Bridgefy forwards it, and we count the loop.
        let mut b = node(1);
        let mut out = Vec::new();
        link_up(&mut b, 2, &mut out);
        link_up(&mut b, 3, &mut out);
        out.clear();

        let mine = crc32(&uuid_of(PeerId(1)));
        let frame = hand_built(1, |p| p.track = vec![mine, 0xDEAD_BEEF]);
        b.on_event(
            TimeMs(0),
            Event::Rx {
                peer: PeerId(9),
                bytes: &frame,
            },
            &mut out,
        )
        .unwrap();
        let txs = out.iter().filter(|a| matches!(a, Action::Tx { .. })).count();
        assert_eq!(txs, 2, "must forward to both links despite being in `track`");
        assert_eq!(b.stats().loops_forwarded, 1, "and the loop must be counted");

        // And the list keeps growing, costing bytes on every hop.
        let relayed = out
            .iter()
            .find_map(|a| match a {
                Action::Tx { frame, .. } => Some(frame.clone()),
                _ => None,
            })
            .unwrap();
        let (_, e) = decode_frame(&relayed).unwrap();
        match &e.ct {
            EntityBody::Forward(ft) => {
                assert_eq!(ft.packets[0].track.len(), 3);
                assert!(ft.packets[0].track.contains(&mine));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn track_costs_bytes_on_the_wire() {
        // A full 50-entry tracklist against an empty one, same payload.
        let cfg = BridgefyConfig::default();
        let mk = |n: usize| {
            let e = BleEntity {
                id: [1u8; 16],
                et: EntityType::ForwardTransaction,
                ct: EntityBody::Forward(ForwardTransaction {
                    dump: false,
                    sender: [2u8; 16],
                    packets: vec![ForwardPacket {
                        id: [3u8; 16],
                        payload: Payload {
                            plain: vec![],
                            ct_len: 64,
                            malformed: false,
                        },
                        sender: [4u8; 16],
                        receiver: None,
                        creation: 1,
                        expiration: 2,
                        receiver_type: RECEIVER_TYPE_BROADCAST,
                        hops: 100,
                        profile: 0,
                        track: (0..n).map(|i| 0x8000_0000 + i as u32).collect(),
                    }],
                }),
            };
            entity_wire_len(&e, &cfg)
        };
        let empty = mk(0);
        let full = mk(STANDARD.tracklist);
        // 50 CRC-32s as MessagePack uint32 are 5 bytes each.
        assert!(
            full >= empty + 5 * STANDARD.tracklist - 16,
            "a full tracklist must cost ~250 bytes: {empty} -> {full}"
        );
    }

    #[test]
    fn tracklist_is_capped_at_the_profile_length() {
        let mut b = node(1);
        let mut out = Vec::new();
        link_up(&mut b, 2, &mut out);
        out.clear();
        let frame = hand_built(1, |p| {
            p.track = (0..STANDARD.tracklist as u32).collect();
        });
        b.on_event(
            TimeMs(0),
            Event::Rx {
                peer: PeerId(9),
                bytes: &frame,
            },
            &mut out,
        )
        .unwrap();
        let relayed = out
            .iter()
            .find_map(|a| match a {
                Action::Tx { frame, .. } => Some(frame.clone()),
                _ => None,
            })
            .unwrap();
        let (_, e) = decode_frame(&relayed).unwrap();
        match &e.ct {
            EntityBody::Forward(ft) => {
                assert_eq!(ft.packets[0].track.len(), STANDARD.tracklist);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn on_wire_length_varies_with_payload_content() {
        // Finding C-2's enabling property, and the thing gdc-wire's bucket
        // ladder exists to remove. Two broadcasts of identical plaintext
        // length, different content.
        let a = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mut varied = vec![0u8; a.len()];
        crate::rng::Rng::new(5).fill(&mut varied);
        let la = inner_ct_len(a, false);
        let lb = inner_ct_len(&varied, false);
        assert_ne!(la, lb, "gzip-before-encrypt must leak content: {la} vs {lb}");

        // And the leak survives to the frame.
        let cfg = BridgefyConfig::default();
        let mk = |ct_len: usize| {
            let e = BleEntity {
                id: [1u8; 16],
                et: EntityType::ForwardTransaction,
                ct: EntityBody::Forward(ForwardTransaction {
                    dump: false,
                    sender: [2u8; 16],
                    packets: vec![ForwardPacket {
                        id: [3u8; 16],
                        payload: Payload {
                            plain: vec![],
                            ct_len,
                            malformed: false,
                        },
                        sender: [4u8; 16],
                        receiver: None,
                        creation: 1,
                        expiration: 2,
                        receiver_type: RECEIVER_TYPE_BROADCAST,
                        hops: 100,
                        profile: 0,
                        track: vec![],
                    }],
                }),
            };
            entity_wire_len(&e, &cfg)
        };
        assert_ne!(mk(la), mk(lb));
    }

    #[test]
    fn multihop_length_also_tracks_content_because_gzip_precedes_libsignal() {
        let a = b"north gate north gate north gate north gate north gate north gat";
        let mut varied = vec![0u8; a.len()];
        crate::rng::Rng::new(6).fill(&mut varied);
        assert_ne!(inner_ct_len(a, true), inner_ct_len(&varied, true));
    }

    #[test]
    fn relay_happens_before_the_payload_is_parsed() {
        // Finding D-1's amplification: a payload that never decompresses has
        // already been handed to every other link.
        let mut b = node(1);
        let mut out = Vec::new();
        for p in [2u64, 3, 4] {
            link_up(&mut b, p, &mut out);
        }
        out.clear();
        let mut attacker = node(9);
        let bomb = attacker.craft_malformed_broadcast(TimeMs(0), 10_000);
        let r = b.on_event(
            TimeMs(0),
            Event::Rx {
                peer: PeerId(9),
                bytes: &bomb,
            },
            &mut out,
        );
        assert!(r.is_err(), "the payload must fail to parse");
        let txs = out.iter().filter(|a| matches!(a, Action::Tx { .. })).count();
        assert_eq!(txs, 3, "and it must already have been relayed");
        assert_eq!(b.stats().relayed_before_parse, 3);
        assert_eq!(b.stats().dropped_malformed, 1);
    }

    #[test]
    fn malformed_radio_input_never_panics() {
        let mut b = node(1);
        let mut out = Vec::new();
        link_up(&mut b, 2, &mut out);
        for case in [
            vec![],
            vec![0u8; 1],
            vec![0xFFu8; 8],
            vec![0u8; 21],
            {
                let mut v = vec![0u8; 21];
                v[20] = 3; // F_FORWARD with nothing after it
                v
            },
            {
                let mut v = vec![0u8; 20];
                v.push(99); // unknown tag
                v
            },
        ] {
            let _ = b.on_event(
                TimeMs(0),
                Event::Rx {
                    peer: PeerId(2),
                    bytes: &case,
                },
                &mut out,
            );
        }
    }

    #[test]
    fn a_declared_plaintext_cannot_drive_an_unbounded_allocation() {
        let mut v = vec![0u8; 4];
        v.extend_from_slice(&[1u8; 16]);
        v.push(F_CONTENT);
        v.extend_from_slice(&[2u8; 16]);
        put_u16(&mut v, 64); // ct_len
        v.push(0); // not malformed
        put_u16(&mut v, u16::MAX); // declared plaintext length, with no bytes behind it
        let e = decode_frame(&v).unwrap_err();
        assert!(
            matches!(e, ProtoError::PayloadTooLarge { .. } | ProtoError::Truncated { .. }),
            "got {e:?}"
        );
    }

    #[test]
    fn flood_has_no_degree_awareness() {
        // A node with 12 links transmits on all 12 minus the ingress. No
        // subsetting, no log2, no cap by degree.
        let mut b = node(1);
        let mut out = Vec::new();
        for p in 2u64..=13 {
            link_up(&mut b, p, &mut out);
        }
        out.clear();
        let frame = hand_built(1, |_| {});
        b.on_event(
            TimeMs(0),
            Event::Rx {
                peer: PeerId(2),
                bytes: &frame,
            },
            &mut out,
        )
        .unwrap();
        let txs = out.iter().filter(|a| matches!(a, Action::Tx { .. })).count();
        assert_eq!(txs, 11, "degree 12 minus the ingress link");
    }

    #[test]
    fn rssi_is_ignored() {
        let mut a = node(1);
        let mut b = node(1);
        let mut oa = Vec::new();
        let mut ob = Vec::new();
        a.on_event(
            TimeMs(0),
            Event::LinkUp {
                peer: PeerId(2),
                rssi_dbm: -40,
            },
            &mut oa,
        )
        .unwrap();
        b.on_event(
            TimeMs(0),
            Event::LinkUp {
                peer: PeerId(2),
                rssi_dbm: -95,
            },
            &mut ob,
        )
        .unwrap();
        assert_eq!(oa, ob, "no link-quality awareness (Part 1, Routing)");
    }

    #[test]
    fn handshake_is_four_messages_on_a_direct_link() {
        let mut a = Bridgefy::new(PeerId(1), 1, BridgefyConfig::default());
        let mut b = Bridgefy::new(PeerId(2), 2, BridgefyConfig::default());
        let mut oa = Vec::new();
        let mut ob = Vec::new();
        link_up(&mut a, 2, &mut oa);
        link_up(&mut b, 1, &mut ob);
        // Both opened with a General; drive them to completion.
        let mut count = 0;
        let mut pending: Vec<(bool, Vec<u8>)> = Vec::new();
        for act in oa.drain(..) {
            if let Action::Tx { frame, .. } = act {
                pending.push((true, frame));
            }
        }
        for act in ob.drain(..) {
            if let Action::Tx { frame, .. } = act {
                pending.push((false, frame));
            }
        }
        for _ in 0..10 {
            let batch = std::mem::take(&mut pending);
            if batch.is_empty() {
                break;
            }
            for (from_a, frame) in batch {
                count += 1;
                let mut o = Vec::new();
                if from_a {
                    b.on_event(
                        TimeMs(0),
                        Event::Rx {
                            peer: PeerId(1),
                            bytes: &frame,
                        },
                        &mut o,
                    )
                    .unwrap();
                } else {
                    a.on_event(
                        TimeMs(0),
                        Event::Rx {
                            peer: PeerId(2),
                            bytes: &frame,
                        },
                        &mut o,
                    )
                    .unwrap();
                }
                for act in o {
                    if let Action::Tx { frame, .. } = act {
                        pending.push((!from_a, frame));
                    }
                }
            }
        }
        assert!(a.handshake_complete(PeerId(2)));
        assert!(b.handshake_complete(PeerId(1)));
        assert!(
            (4..=6).contains(&count),
            "four handshake messages plus at most the symmetric opening: {count}"
        );
    }

    #[test]
    fn handshake_is_refused_without_a_direct_link() {
        // "over a direct link only, never over the mesh".
        let mut b = node(1);
        let mut out = Vec::new();
        let e = BleEntity {
            id: [1u8; 16],
            et: EntityType::Handshake,
            ct: EntityBody::Handshake(HandshakeMsg::Key {
                user_id: uuid_of(PeerId(7)),
                pkb: [9u8; 32],
            }),
        };
        let wl = entity_wire_len(&e, &BridgefyConfig::default());
        let frame = encode_frame(&e, wl);
        b.on_event(
            TimeMs(0),
            Event::Rx {
                peer: PeerId(7),
                bytes: &frame,
            },
            &mut out,
        )
        .unwrap();
        assert!(b.contact(&uuid_of(PeerId(7))).is_none());
    }

    #[test]
    fn keys_are_trusted_on_first_use_and_rebound_without_complaint() {
        // Findings A-1 / A-2. This test exists to prove we did not quietly give
        // Bridgefy a verification path it does not have.
        let mut b = node(1);
        let mut out = Vec::new();
        link_up(&mut b, 7, &mut out);
        let victim = uuid_of(PeerId(42));
        let send_key = |b: &mut Bridgefy, pkb: [u8; 32], out: &mut Vec<Action>| {
            let e = BleEntity {
                id: [1u8; 16],
                et: EntityType::Handshake,
                ct: EntityBody::Handshake(HandshakeMsg::Key {
                    user_id: victim,
                    pkb,
                }),
            };
            let wl = entity_wire_len(&e, &BridgefyConfig::default());
            let frame = encode_frame(&e, wl);
            b.on_event(
                TimeMs(0),
                Event::Rx {
                    peer: PeerId(7),
                    bytes: &frame,
                },
                out,
            )
            .unwrap();
        };
        send_key(&mut b, [1u8; 32], &mut out);
        assert_eq!(b.contact(&victim).unwrap().pkb, [1u8; 32]);
        send_key(&mut b, [2u8; 32], &mut out);
        let c = b.contact(&victim).unwrap();
        assert_eq!(c.pkb, [2u8; 32], "an attacker's key replaces the victim's");
        assert_eq!(c.rebindings, 1);
    }

    #[test]
    fn sharing_time_re_offers_recent_packets_to_a_new_peer() {
        // The `Sharing time` column, 15 000 ms on Standard.
        let mut b = node(1);
        let mut out = Vec::new();
        b.on_event(
            TimeMs(0),
            Event::AppSend {
                dest: Dest::Broadcast,
                payload: b"hello",
                want_ack: false,
            },
            &mut out,
        )
        .unwrap();
        out.clear();
        link_up(&mut b, 2, &mut out);
        assert!(
            out.iter().any(|a| matches!(a, Action::Tx { .. })),
            "a packet inside the sharing window must be re-offered"
        );

        let mut late = Vec::new();
        b.on_event(
            TimeMs(STANDARD.sharing_time_ms + 1),
            Event::LinkUp {
                peer: PeerId(3),
                rssi_dbm: -70,
            },
            &mut late,
        )
        .unwrap();
        let shares = late
            .iter()
            .filter(|a| matches!(a, Action::Tx { wire_len, .. } if *wire_len > 120))
            .count();
        assert_eq!(shares, 0, "outside the window nothing is re-offered");
    }

    #[test]
    fn oversized_app_payload_is_refused_not_truncated() {
        let mut b = node(1);
        let mut out = Vec::new();
        let big = vec![b'x'; BridgefyConfig::default().max_app_payload + 1];
        assert!(matches!(
            b.on_event(
                TimeMs(0),
                Event::AppSend {
                    dest: Dest::Broadcast,
                    payload: &big,
                    want_ack: false
                },
                &mut out
            ),
            Err(ProtoError::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn max_propagation_bounds_an_otherwise_unbounded_flood() {
        let mut cfg = BridgefyConfig::default();
        cfg.profile = HIGH_DENSITY; // max_propagation 50
        let mut b = Bridgefy::new(PeerId(1), 1, cfg);
        let mut out = Vec::new();
        link_up(&mut b, 2, &mut out);
        link_up(&mut b, 3, &mut out);
        out.clear();
        let frame = hand_built(1, |p| {
            p.hops = 50;
            p.id = [77u8; 16];
        });
        for _ in 0..80 {
            let _ = b.on_event(
                TimeMs(0),
                Event::Rx {
                    peer: PeerId(2),
                    bytes: &frame,
                },
                &mut out,
            );
        }
        let txs = out.iter().filter(|a| matches!(a, Action::Tx { .. })).count();
        assert_eq!(txs, HIGH_DENSITY.max_propagation as usize);
        assert!(b.stats().dropped_full > 0);
    }

    #[test]
    fn the_addressed_receiver_delivers_once_however_many_copies_arrive() {
        let mut b = node(1);
        let mut out = Vec::new();
        link_up(&mut b, 2, &mut out);
        out.clear();
        let frame = hand_built(1, |p| {
            p.receiver = Some(uuid_of(PeerId(1)));
            p.receiver_type = RECEIVER_TYPE_MULTIHOP;
        });
        for _ in 0..5 {
            b.on_event(
                TimeMs(0),
                Event::Rx {
                    peer: PeerId(2),
                    bytes: &frame,
                },
                &mut out,
            )
            .unwrap();
        }
        assert_eq!(b.stats().app_delivered, 1);
        assert_eq!(b.stats().dup_rx, 4);
        assert_eq!(
            out.iter().filter(|a| matches!(a, Action::Deliver { .. })).count(),
            1
        );
    }
}
