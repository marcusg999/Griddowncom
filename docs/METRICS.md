# The judging contract

Every builder optimises against this file. Every critic judges against this
file. Nothing else counts as winning.

## The two headline numbers

These are the ones the project is graded on.

### M1 — Per-hop effective distance, built-up area

Median distance in metres at which a one-hop message succeeds on the first
attempt, outdoors in a built-up area, both devices held at waist height by
walking humans, screens off.

- Reported as median plus 10th/90th percentile over >= 30 trials per distance band.
- Bands: 10/20/30/50/75/100/150 m.
- Success = message delivered and acknowledged within 30 s.
- Must be reported per platform pair: iOS-iOS, Android-Android, iOS-Android.
  The mixed pair is the one that matters and the one everybody else is worst at.

Bridgefy's claimed figure is ~100 m per link. bitchat's reported figure is ~30 m.
We need the real measured number for all three, under identical conditions, on
the same walk, same hour, same street.

### M2 — End-to-end delivery rate across >= 3 hops

Fraction of messages that arrive at the far end of a chain of >= 4 devices
(3 hops) where no non-adjacent pair is in radio range.

- Reported at 3, 4 and 5 hops.
- Two regimes, reported separately:
  - **Static chain** — relays stationary, link exists throughout.
  - **Carrier regime** — the chain is broken and closed only by a human
    walking between clusters. This is the store-and-forward case and is where
    hop count stops being the limit.
- Success = delivered within the stated deadline. Report delivery rate at
  30 s / 5 min / 30 min / 2 h deadlines, because "eventually" is a real and
  different product than "now".
- Screens off, apps backgrounded, for at least one arm of every test. A
  foreground-only number is not a number.

## Per-piece metrics

Each piece is judged on its own, so it can be improved and compared alone.

### Transport
- Neighbour acquisition time from cold: p50/p90 seconds to first usable link.
- Goodput per link: bytes/second of application payload, BLE and Wi-Fi burst.
- Link survival: fraction of links still usable after 60 s of pedestrian motion.
- Reconnect time after a link drops.
- Background-vs-foreground delta on every one of the above, per platform.

### Routing
- Delivery rate vs hop count (feeds M2).
- **Transmissions per delivered message** — the flood-efficiency number.
  Bridgefy's default TTL of 100 with no degree awareness is the thing to beat;
  measure it, publish the ratio.
- Latency p50/p90 per hop.
- Behaviour under density: 5, 20, 50, 150 nodes in range. Delivery rate must
  not collapse as density rises.
- Behaviour under churn: nodes joining/leaving at a given rate.
- Duplicate suppression effectiveness: redundant receptions per delivery.

### Crypto
- Every rule in `docs/research/BRIDGEFY-FINDINGS.md` Part 3, each with a test
  that fails if the rule is broken.
- Wire overhead in bytes per message, and the padding-bucket histogram.
- Handshake round trips and wall-clock time to first encrypted message.
- Fuzz: zero panics, zero unbounded allocations, over a stated corpus and
  iteration count.
- A length-correlation test: across a corpus of varied plaintexts, on-wire
  frame length must carry no mutual information with plaintext content.

### Onboarding
- Time from app launch to joined-a-channel-and-sent-first-message, measured on
  someone who has never seen the app. Target: under 20 seconds.
- Number of taps, number of screens, number of words the user must read.
- Comprehension: can a first-time user state correctly, unprompted, whether
  their message has actually been delivered?
- Failure legibility: when nothing is in range, does the user understand that
  it is not their fault and that the message will go when someone arrives?

### Message screen
- Time to send a canned message from screen-on: target under 3 seconds.
- Delivery state must be honest and distinguishable: queued / carried /
  delivered-to-channel / read-by-someone / expired-undelivered.
- One-handed reachability of every primary action.
- Legibility in direct sunlight and at night without destroying dark adaptation.
- Usable by a panicking stranger: judged by scripted stress tasks, not opinion.

### Battery
- mAh per hour in each duty mode, idle-relay, screen off. Budget: ~5 %/hr on
  a 4000 mAh-class phone for the balanced default.
- mAh per delivered message, as a function of hop count.
- Projected hours of relay duty from 100 % to 20 %.
- Measured, not estimated, on real hardware for at least one Android device;
  modelled with a stated radio-event energy table everywhere else.

## How a blind comparison is run

The critic never sees which build is which.

1. The harness emits two result sets labelled only `A` and `B`, in randomised
   order per run, from a seed the critic does not hold.
2. For simulation rounds, both stacks run on the identical PHY trace, mobility
   trace, node count and offered load. Same seed, same world, different
   protocol. Any other comparison is void.
3. For UI rounds, the critic is given two builds with branding, colours and
   copy neutralised, and runs the same scripted tasks against both.
4. The critic must name a winner per metric, then an overall winner, then the
   single biggest remaining gap in the one it picked. "Both are fine" is not a
   permitted verdict.
5. The critic's verdict is written to `harness/verdicts/` with the label
   mapping sealed until after the verdict is recorded.

## Rules of evidence

- A number without the conditions it was measured under is not a number.
- Simulated results are always labelled simulated. They are never reported as
  field measurements.
- The simulator is only credible to the extent it is calibrated against real
  measurements. Every sim result cites the calibration round it rests on.
- Where we have no measurement and no calibration, we say so.
