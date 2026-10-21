# PHY profile: dense downtown canyon

The field site is a dense downtown street with tall buildings on both sides.
This file is the simulator's default PHY profile and the reasoning behind every
number in it.

**Everything here is modelled.** It is a link budget plus published propagation
behaviour, not a measurement. It exists so that pre-calibration numbers are
defensible rather than invented, and so that the first field round has
something specific to falsify. `gdc-sim` owns `phy.rs` and should load these as
its defaults.

## Link budget inputs

| Quantity | Value | Basis |
|---|---|---|
| TX power | +4 dBm | Typical phone BLE. Android commonly +1 to +4; some iPhones higher. Conservative middle. |
| RX sensitivity, 1M PHY | −95 dBm | Modern phone chipsets. BLE spec floor is −70 dBm; real silicon is −90 to −97. |
| RX sensitivity, Coded PHY S=8 | −107 dBm | +12 dB coding gain over 1M, at 1/4 the data rate. |
| Antenna efficiency loss | −3 dB per device | Phone antennas are small and detuned by a hand or a body. |
| Body loss, phone in trouser pocket | −10 dB per device | 2.4 GHz on-body attenuation. Literature spans 3–20 dB depending on which side of the body the far device is; 10 dB is the orientation average. |
| Body loss, handheld in front of face | −3 dB per device | Hand and head present but no torso in the path. |
| Shadowing sigma | 7 dB | Log-normal, urban canyon with pedestrians and vehicles. |
| Fade margin for 90 % success | 9 dB | 1.28σ at σ = 7 dB. |

Free-space path loss at 2.44 GHz: `PL(d) = 40.2 + 20·log10(d_m)` dB.

## Path loss exponent

The canyon geometry is the thing most models of this kind get wrong.

- **Along the street, line of sight: n = 1.9.** Below free space. Tall buildings
  on both sides act as a waveguide, reflecting energy forward instead of
  letting it spread spherically. This is a known urban-canyon effect and it
  works in our favour: a downtown street is a *better* BLE corridor than an
  open park at the same distance.
- **Around a corner, NLOS: n = 3.2, plus 20–30 dB corner loss.** Once the
  direct path is blocked by a building edge, propagation is diffraction and
  reflection only. Use 25 dB as the default corner loss.
- **Obstructed along-street (a bus, a crowd, a truck): n = 2.8.**

## Resulting ranges

Distance at which a single hop succeeds 90 % of the time.

| Condition | Budget | Range |
|---|---|---|
| 1M PHY, both phones pocketed, screens off | 64 dB | **≈ 18 m** |
| 1M PHY, both handheld, foreground | 78 dB | **≈ 97 m** |
| Coded PHY S=8, both pocketed | 76 dB | **≈ 76 m** |
| Coded PHY S=8, both handheld | 90 dB | **≈ 400 m** |
| 1M PHY, pocketed, around a corner | 39 dB after corner loss | **≈ 0 m** |
| Coded PHY S=8, pocketed, around a corner | 51 dB after corner loss | **≈ 4 m** |

## Three conclusions that should change the design

**1. Bridgefy's "up to 100 m" is a handheld line-of-sight number.** Our model
reproduces it almost exactly: 97 m for 1M PHY, both devices handheld in the
foreground, clear along-street path. The same link with both phones in pockets
is about 18 m. That is a five-fold gap between the marketing condition and the
condition the app is actually used in, and it is most of why multi-hop
messengers disappoint in the field. Our M1 measurement is specified pocketed
and backgrounded precisely to avoid flattering ourselves the same way.

**2. Coded PHY is the single biggest lever on per-hop distance.** Pocketed, it
turns 18 m into roughly 76 m — a 4× improvement on the headline metric, bought
with a coding gain rather than a protocol trick, at the cost of a quarter of
the data rate. Given the payload ceiling is 500 bytes, that data rate is
irrelevant to us and the range is everything. Nothing in the published
Bridgefy material suggests it uses Coded PHY.

  Caveat that needs checking before we claim this per platform:
  `UNVERIFIED:` Android exposes PHY selection (`setPreferredPhy`, LE Coded
  advertising sets). CoreBluetooth appears to expose **no** public PHY
  selection to apps, which would make Coded PHY an Android-only advantage and
  would mean the iOS-to-Android pair cannot use it at all. The transport
  builder must verify this against current CoreBluetooth documentation rather
  than take it from here.

**3. In a downtown grid, corners are walls, and that reshapes the routing
problem.** A pocketed 1M PHY link does not turn a corner at all; even Coded
PHY gets about 4 m past the building edge. So a city block is a set of
corridors joined only at intersections, and useful relays are at
intersections, not mid-block. Two consequences:

- Hop count alone does not describe reach. A 3-hop chain down one street
  covers one street. Crossing the city means getting through intersections,
  which means the store-and-forward carrier path is doing more of the work
  than hop count is. This strengthens the case for the channel-addressed
  courier design.
- Routing should prefer a neighbour at an intersection over a closer one
  mid-block, which is a different objective from "strongest signal".
  `gdc-routing` should treat this as a real lever.

## A favourable asymmetry worth stating

The field rounds will be run with the grid **up**. A dense downtown at 2.4 GHz
is one of the most congested RF environments there is: every Wi-Fi access
point, every hotspot, every Bluetooth device. In the scenario this app exists
for, nearly all of that is dead, and the noise floor is far lower.

So the field numbers will be **pessimistic relative to the real use case**.
That is the right direction for an error to run, and it should be said out loud
rather than used quietly as an excuse later. We report the measured
grid-up numbers as the headline, and note the grid-down margin separately
without claiming it.
