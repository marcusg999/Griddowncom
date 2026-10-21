# Bridgefy: published findings and protocol internals

Source material, read in full:

- Albrecht, Blasco, Jensen, Mareková. *Mesh Messaging in Large-scale Protests:
  Breaking Bridgefy.* CT-RSA 2021. eprint 2021/214. (2020 disclosure.)
- Albrecht, Eikenberg, Paterson. *Breaking Bridgefy, again: Adopting libsignal
  is not enough.* USENIX Security '22. Targets messenger 3.1.3 / SDK 2.0.2.
- Bridgefy SDK docs (iOS/Android usage + overview), propagation profile table.
- bitchat WHITEPAPER.md v2.0 (2026-07-06) — not the bar, but the real state of
  the art in this exact niche, and the design we must actually out-engineer.

This file is a **contract**. Every builder and every critic is handed it. Any
design that reintroduces a numbered item below is rejected on sight, regardless
of how it benchmarks.

---

## Part 1 — Bridgefy's protocol as reverse-engineered

Needed because our blind baseline must be a faithful implementation of the
*published* Bridgefy behaviour, not a strawman.

### Encoding pipeline

    MessagePack  ->  gzip  ->  encrypt

Compression **precedes** encryption. This single ordering decision is the root
of finding C-2 below.

### Packet structure

    BleEntity<T>            { id: UUID, et: int, ct: T }
      ForwardTransaction    { dump: bool, sender: UUID }      // sender = last relay
        ForwardPacket 1..*  { id: UUID,
                              payload: Map<String,Object>,    // message under key "ct"
                              sender: UUID,                   // original author
                              receiver: UUID,                 // empty for broadcast
                              creation: long,
                              expiration: long,
                              receiver_type: int,             // 1 = broadcast, 0 = multi-hop
                              hops: int,                      // TTL, 1 byte, decremented
                              profile: int,
                              track: List<long> }             // CRC-32 of last n relay userIds
      BleEntityContent      { id: UUID, payload: Map<String,Object> }  // direct, no routing

`BleEntityContent` is the direct one-to-one type and carries no routing fields.
The paper notes `track` "appears unused otherwise" — i.e. it is carried but not
actually relied on for loop suppression.

### Routing

Pure controlled flood. No neighbour tables, no topology map, no source routes,
no link quality. A multi-hop packet is flooded until it happens to reach the
addressed `receiver`. Loop control is the `hops` TTL plus the (apparently
unused) `track` CRC list.

Propagation profiles:

| Profile      | Hops | TTL (s) | Sharing time | Max propagation | Tracklist |
|--------------|------|---------|--------------|-----------------|-----------|
| Standard     | 100  | 86400   | 15000        | 200             | 50        |
| High Density | 50   | 3600    | 10000        | 50              | 50        |
| Sparse       | 100  | 302400  | 10000        | 250             | 50        |
| Long Reach   | 250  | 604800  | 15000        | 1000            | 50        |
| Short Reach  | 50   | 1800    | 10000        | 50              | 50        |

A default TTL of **100 hops** in a flood with no degree awareness is the
performance target we intend to destroy. Claimed per-link range ~100 m.

### Crypto placement

| Data category        | Metadata | Payload   |
|----------------------|----------|-----------|
| BleHandshake         | AES-ECB  | AES-ECB   |
| BleEntityContent     | AES-ECB  | libsignal |
| ForwardTransaction   | AES-ECB  | libsignal |

libsignal covers **only** the payload of one-to-one and multi-hop packets.
Broadcast packets in their entirety, and all metadata everywhere, are
**AES-ECB under a single network-wide key compiled into the public app**.

Handshake, over a direct link only, never over the mesh, 4 messages, TOFU:

    A -> B : ResponseTypeGeneral(userIdA)      // plaintext userId
    B -> A : ResponseTypeGeneral(userIdB)
    A -> B : ResponseTypeKey(PKBA)
    B -> A : ResponseTypeKey(PKBB)

No key verification exists anywhere in the UI.

### Processing order

Receive -> assemble -> **relay to network** -> decompress and decrypt -> process.

Forwarding happens *before* parsing. That is what turns a single malformed
message into a network-wide outage.

---

## Part 2 — The findings. Do not reproduce any of these.

### Privacy / metadata

- **P-1 Local user tracking.** Static identifiers in BLE `ADV_IND`; no use of
  resolvable private addresses. Passive observation tracks every user.
- **P-2 Plaintext social graph.** Sender and receiver userIds travel in clear
  in every mesh packet. A passive listener with physical presence reconstructs
  who talks to whom; the vendor's own server API resolved IDs to usernames.
- **P-3 Topology leak via receipt timing.** Three receipts per message, with
  distance-dependent delay, let an observer infer hop distance and build a live
  topology map.

### Authentication

- **A-1 Impersonation.** userId was treated as identity but was never
  authenticated. Replying to a handshake with a victim's userId caused the app
  to merge attacker and victim into one contact.
- **A-2 Active MITM.** Extends A-1. Forcing a public-key refresh for an
  out-of-range peer lets the attacker substitute its own key. Survived the
  libsignal migration because PKBs are trusted on first use with no
  verification path.
- **A-3 Broadcast impersonation.** Broadcast is authenticated only by the
  shared network key, which every installation holds, so any participant can
  forge any sender.

### Confidentiality

- **C-1 Padding oracle.** A Bleichenbacher variant against RSA PKCS#1 v1.5,
  using delivery receipts as the oracle. (Retired by the libsignal migration,
  listed so we never build a receipt-driven oracle of any kind.)
- **C-2 Compression side channel.** Because gzip runs before encryption,
  ciphertext length leaks plaintext content. The 2022 paper mounts a
  distinguishing attack and then full plaintext recovery on broadcast messages
  by maximum-likelihood estimation over lengths observed across several hops —
  **without** knowing the network key.
- **C-3 TOCTOU around libsignal.** `deviceId` pinned to 0 with `userId` in the
  address `name` field; session state can be swapped between check and use,
  side-stepping Signal's guarantees entirely and recovering one-to-one
  plaintext.
- **C-4 Network-wide shared key.** A single symmetric key shipped in a public
  binary, recoverable by dynamic instrumentation. Confidentiality against any
  insider is zero by construction.
- **C-5 AES-ECB.** Deterministic, unauthenticated, no integrity.
- **C-6 Attachments in plaintext.** Only text and coordinates were encrypted.

### Availability

- **D-1 Decompression bomb.** A ~10 KB crafted broadcast expands catastrophically,
  freezes and crashes every receiving client. Amplified to a network-wide
  outage by the relay-before-parse ordering. Still worked in 2022.

---

## Part 3 — The resulting hard rules for this codebase

A builder violating any of these is reverted. A critic that fails to check them
has not done its job.

1. **Encrypt before compress, or compress inside the AEAD.** No plaintext
   length may vary with plaintext content on the wire. Frames go out in
   fixed-size buckets. Kills C-2.
2. **No network-wide shared secret.** No key material in the binary. Channel
   keys come from the QR and nowhere else. Kills C-4, A-3.
3. **AEAD only.** No ECB, no unauthenticated mode, no encrypt-without-MAC
   anywhere. Kills C-5.
4. **Every relayed frame is authenticated before it is forwarded.** Parse and
   verify with a hard bounded work budget, then relay. Never relay unparsed
   bytes. Kills D-1 and its amplification.
5. **No unbounded decompression.** Explicit output ceiling, enforced by
   construction, checked by a fuzz target.
6. **No identifiers stable across sessions on the wire.** Rotating BLE
   identifiers and per-session keys. Kills P-1.
7. **No plaintext routing identifiers.** Addressing is by channel tag derived
   from the channel key, not by a cleartext sender/receiver pair. Kills P-2.
8. **No oracle of any kind from receipts, errors or timing.** Uniform response
   shape and timing on every failure path. Kills C-1 and P-3.
9. **No trust on first use without a verification path.** Session keys are
   authenticated against the channel key at join. Kills A-1, A-2.
10. **No session-state lookup keyed on anything an attacker supplies.** Bind
    sessions to the verified key, not to a claimed id or a Bluetooth address.
    Kills C-3.
