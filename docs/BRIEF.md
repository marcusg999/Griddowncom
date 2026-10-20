# GridDown — shared brief

Read this first. Every builder and every critic on this project is handed this
file, `docs/METRICS.md`, `docs/research/BRIDGEFY-FINDINGS.md`, and
`crates/gdc-wire/src/lib.rs`.

## What we are building

An off-grid emergency messenger for iOS and Android that works with no cell
towers, no internet, no Wi-Fi infrastructure and no satellite. Every radio it
uses is already in the phone. No hardware to buy, no spectrum licence.

Range comes from hop count and from carriers in motion, not from any single
link. A message crosses a city by multi-hop relay and by store-and-forward
through people who physically move.

Product surface: group channels joined by QR, a canned-message pad, a roster,
and an interface simple enough for a panicking stranger.

The bar is Bridgefy. We must beat it on per-hop distance in a built-up area and
on end-to-end delivery rate across three or more hops. See `docs/METRICS.md`.

## Decisions already made. Do not relitigate these.

**Stack.** Rust core, native shells. Mesh, routing, crypto, store-and-forward
and scheduling live in the Rust workspace and are testable off-device. Swift /
SwiftUI and Kotlin / Compose shells own the radios and the UI, over UniFFI.

**Transports.** BLE phone-to-phone is the floor and the only cross-platform
link. Infrastructure-free peer-to-peer Wi-Fi is an opportunistic accelerator
for backlog flush and sync between two close devices, and is **intra-platform
only**: Wi-Fi Aware / Wi-Fi Direct on Android, MultipeerConnectivity / AWDL on
iOS. iOS exposes no public Wi-Fi Direct or Wi-Fi Aware API, so there is no
infra-free high-throughput iOS-to-Android path. Design for that, do not wish it
away.

**The stack picks the best available link per peer, per moment.** Cheapest
sufficient radio wins: BLE for presence, control and most messages; a Wi-Fi
burst only when there is enough backlog to repay the cost of bringing the radio
up, and only when both ends can speak it.

**Payload.** Short free text up to 500 bytes, the canned-message pad, and a
compact location pin. No photos, no voice, no file transfer. This is why the
Wi-Fi burst is an accelerator and not a media pipe.

**Threat model: reach above all, with a hard cheap floor.** We spend nothing on
expensive privacy — no cover traffic, no timing jitter for unlinkability, no
mixnet behaviour, no sender anonymity. We spend everything on delivery. But the
cheap defences are non-negotiable, because shipping them broken would mean
reproducing the published Bridgefy findings. The floor is Part 3 of
`docs/research/BRIDGEFY-FINDINGS.md` and it is not a suggestion.

**Identity is ephemeral per session.** A session runs from launch until an
explicit new-identity or panic wipe. Nothing survives a wipe, there is no
account, and sessions are unlinkable to one another.

**Addressing is channel-first.** The primary address is a channel, keyed from
the QR, not a person. This is what lets store-and-forward survive ephemeral
identity: a frame carried in a pocket for forty minutes is deliverable to
anyone in that channel on arrival. Direct messages to an ephemeral session key
are secondary and best-effort; if the recipient wiped, the message expires
undelivered and the UI says so rather than faking delivery.

**The roster is live presence inside a channel**, nickname bound to a session
key, with a verified / unverified badge. Not a persistent address book.

**Battery.** One fixed balanced profile, about 5 %/hr on a 4000 mAh-class phone
while relaying with the screen off, biased toward delivery. Roughly a day of
relay duty from a full charge.

## Testing reality. Read this carefully.

The container this project is developed in has **no radios and no phones**. It
is a Linux box. Nobody here can run a BLE scan or install an APK on a handset.

Consequences:

- The Rust core, the simulator and the baselines are fully built and fully
  tested here. That is where the engineering lives.
- Android can be compiled here if the SDK is fetched. **iOS cannot be compiled
  here at all** — there is no Swift toolchain and no macOS. iOS code is written
  to be reviewed and compiled by the user, and must be marked as unverified
  wherever we report status.
- Field numbers come from the user, who has four to five mixed iOS and Android
  devices. We give them an instrumented build and a precise walk protocol; they
  give us CSVs; the simulator is recalibrated against them.
- **Never report a simulated number as a measurement.** Every figure we publish
  carries its provenance: `measured`, `simulated`, or `simulated, calibrated
  against round N`. A critic that lets an uncalibrated simulated number be
  presented as a field result has failed.

## Crate ownership

One owner per crate. Do not edit a crate you do not own; if you need a change
there, say so in your report instead.

| Crate            | Owns                                                      |
|------------------|-----------------------------------------------------------|
| `gdc-wire`       | On-wire contract. **Orchestrator owns it. Frozen.**        |
| `gdc-crypto`     | Channel keys, session keys, AEAD, tags, handshake, wipe    |
| `gdc-transport`  | Link abstraction, radio selection, MTU, fragmentation      |
| `gdc-routing`    | Relay decisions, dup suppression, density and churn        |
| `gdc-store`      | Store-and-forward, couriers, backlog sync, expiry          |
| `gdc-node`       | Assembles the above into one node state machine            |
| `gdc-sim`        | PHY, mobility, battery, harness, blind A/B rig             |
| `gdc-baseline`   | Faithful Bridgefy and bitchat models for comparison        |

If you need something from another crate that does not exist yet, define the
narrowest trait you need in your own crate and note the dependency in your
report. The orchestrator reconciles.

## House style

- `#![forbid(unsafe_code)]` in every crate.
- No panics on any input that can come off a radio. Return errors.
- Every allocation driven by remote input has an explicit ceiling.
- Deterministic where it can be: seeded RNG, injected clocks, no ambient time or
  randomness in logic that a test needs to pin down.
- Comments explain why, not what. Match the density of the surrounding code.
- Tests assert behaviour that matters, especially the hard rules. A test named
  after a finding in the research file is worth ten named `test_works`.
