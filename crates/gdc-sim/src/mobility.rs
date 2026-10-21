//! Pedestrian mobility on a street grid.
//!
//! Three things have to be expressible, because `docs/METRICS.md` grades us on
//! all three:
//!
//! * **Static clusters.** The M2 static-chain regime.
//! * **Clusters with no radio path between them.** The world where hop count
//!   cannot help, because there is nothing to hop through.
//! * **Carriers.** Nodes that walk from one cluster to another. A carrier is
//!   the only thing that closes a broken chain, and the carrier regime is half
//!   of M2.
//!
//! The trace is precomputed from the world seed before any protocol runs. That
//! is deliberate: it is what lets the blind A/B rig claim both arms saw the
//! same world, rather than merely the same seed.

use crate::clock::SimTime;
use crate::rng::CounterRng;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

impl Point {
    pub fn new(x: f64, y: f64) -> Self {
        Point { x, y }
    }

    pub fn distance_to(&self, o: &Point) -> f64 {
        let dx = self.x - o.x;
        let dy = self.y - o.y;
        let d = (dx * dx + dy * dy).sqrt();
        if d.is_finite() {
            d
        } else {
            f64::INFINITY
        }
    }

    fn lerp(&self, o: &Point, f: f64) -> Point {
        let f = f.clamp(0.0, 1.0);
        Point {
            x: self.x + (o.x - self.x) * f,
            y: self.y + (o.y - self.y) * f,
        }
    }
}

/// A rectilinear street grid. Streets run along every multiple of `block_m` in
/// both axes; everything else is building interior.
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct StreetGrid {
    pub block_m: f64,
    pub street_width_m: f64,
    /// How many samples to take along a path when counting blocks crossed.
    /// More is slower and not more accurate past the point where a sample
    /// cannot skip a whole street.
    pub obstruction_samples: u32,
}

impl Default for StreetGrid {
    fn default() -> Self {
        StreetGrid {
            block_m: 80.0,
            street_width_m: 14.0,
            obstruction_samples: 48,
        }
    }
}

impl StreetGrid {
    fn on_street_axis(&self, v: f64) -> bool {
        if self.block_m <= 0.0 {
            return true;
        }
        let m = v.rem_euclid(self.block_m);
        let half = self.street_width_m.max(0.0) * 0.5;
        m <= half || m >= self.block_m - half
    }

    /// Is this point in the open (on a street) rather than inside a block.
    pub fn is_street(&self, p: Point) -> bool {
        if !p.x.is_finite() || !p.y.is_finite() {
            return false;
        }
        self.on_street_axis(p.x) || self.on_street_axis(p.y)
    }

    /// Number of building blocks the straight line `a -> b` passes through.
    ///
    /// Counted as maximal runs of in-block samples, so a 300 m diagonal across
    /// four blocks returns four, not one and not forty.
    pub fn blocks_between(&self, a: Point, b: Point) -> u32 {
        if self.block_m <= 0.0 {
            return 0;
        }
        let n = self.obstruction_samples.clamp(4, 512);
        let mut runs = 0u32;
        let mut inside = false;
        for i in 0..=n {
            let f = f64::from(i) / f64::from(n);
            let p = a.lerp(&b, f);
            let in_block = !self.is_street(p);
            if in_block && !inside {
                runs = runs.saturating_add(1);
            }
            inside = in_block;
        }
        runs
    }

    /// Is this point on a north-south street.
    pub fn on_vertical_street(&self, p: Point) -> bool {
        self.on_street_axis(p.x)
    }

    /// Snap a point to the nearest street intersection, so that a Manhattan
    /// walk between two snapped points stays on streets.
    pub fn snap_to_intersection(&self, p: Point) -> Point {
        if self.block_m <= 0.0 {
            return p;
        }
        Point {
            x: (p.x / self.block_m).round() * self.block_m,
            y: (p.y / self.block_m).round() * self.block_m,
        }
    }
}

/// A standing group of people.
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub struct ClusterSpec {
    pub centre: Point,
    /// Members wander inside this radius.
    pub radius_m: f64,
    /// Metres per second of pedestrian wander. Zero means a static cluster.
    pub speed_mps: f64,
    /// Mean pause between waypoints, seconds.
    pub pause_s: f64,
}

impl ClusterSpec {
    pub fn stationary(centre: Point, radius_m: f64) -> Self {
        ClusterSpec {
            centre,
            radius_m,
            speed_mps: 0.0,
            pause_s: 0.0,
        }
    }

    pub fn milling(centre: Point, radius_m: f64) -> Self {
        ClusterSpec {
            centre,
            radius_m,
            speed_mps: 1.3,
            pause_s: 20.0,
        }
    }
}

/// A node that walks between clusters. The only thing that closes a broken
/// chain.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct CarrierSpec {
    /// Index into the scenario's node list.
    pub node: usize,
    /// Cluster indices, visited in order and then repeated.
    pub route: Vec<usize>,
    pub speed_mps: f64,
    /// Seconds spent inside each cluster before setting off again. Long enough
    /// to actually exchange a backlog, or the carrier is useless.
    pub dwell_s: f64,
    /// Seconds before the carrier first sets off.
    pub start_delay_s: f64,
}

/// Everything needed to generate a world's motion.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct MobilitySpec {
    pub grid: StreetGrid,
    pub clusters: Vec<ClusterSpec>,
    /// Which cluster each node belongs to. Nodes beyond the end of this vector
    /// are assigned round-robin.
    pub assignment: Vec<usize>,
    pub carriers: Vec<CarrierSpec>,
    /// Trace sampling interval, seconds. One second is enough for 1.3 m/s
    /// pedestrians and keeps a two-hour 150-node world small.
    pub step_s: f64,
}

impl Default for MobilitySpec {
    fn default() -> Self {
        MobilitySpec {
            grid: StreetGrid::default(),
            clusters: vec![ClusterSpec::milling(Point::new(0.0, 0.0), 25.0)],
            assignment: Vec::new(),
            carriers: Vec::new(),
            step_s: 1.0,
        }
    }
}

/// A precomputed mobility trace: positions for every node at every step.
#[derive(Clone, PartialEq, Debug)]
pub struct Trace {
    step: SimTime,
    nodes: usize,
    /// `positions[step * nodes + node]`.
    positions: Vec<Point>,
    grid: StreetGrid,
    carrier_nodes: Vec<usize>,
}

impl Trace {
    pub fn grid(&self) -> StreetGrid {
        self.grid
    }

    pub fn nodes(&self) -> usize {
        self.nodes
    }

    pub fn step(&self) -> SimTime {
        self.step
    }

    pub fn steps(&self) -> usize {
        if self.nodes == 0 {
            0
        } else {
            self.positions.len() / self.nodes
        }
    }

    pub fn is_carrier(&self, node: usize) -> bool {
        self.carrier_nodes.contains(&node)
    }

    /// Position of `node` at `t`, clamped to the ends of the trace.
    pub fn position(&self, node: usize, t: SimTime) -> Point {
        if self.nodes == 0 || self.step.as_micros() == 0 {
            return Point::default();
        }
        let steps = self.steps();
        if steps == 0 {
            return Point::default();
        }
        let k = (t.as_micros() / self.step.as_micros()) as usize;
        let k = k.min(steps - 1);
        let idx = k * self.nodes + node;
        self.positions.get(idx).copied().unwrap_or_default()
    }

    /// A stable digest of the whole trace, so a test can assert that two runs
    /// really did see the same world rather than merely the same seed.
    pub fn digest(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for p in &self.positions {
            for b in p.x.to_bits().to_le_bytes().iter().chain(p.y.to_bits().to_le_bytes().iter()) {
                h ^= u64::from(*b);
                h = h.wrapping_mul(0x1000_0000_0000_01B3);
            }
        }
        h
    }
}

/// Build the trace for a world.
///
/// Pure in `(spec, nodes, duration, seed)`. No clock, no ambient randomness,
/// no dependence on anything a protocol does.
pub fn build_trace(spec: &MobilitySpec, nodes: usize, duration: SimTime, seed: u64) -> Trace {
    let step_s = if spec.step_s.is_finite() && spec.step_s > 0.01 {
        spec.step_s
    } else {
        1.0
    };
    let step = SimTime::from_secs_f64(step_s);
    let steps = (duration.as_micros() / step.as_micros().max(1)) as usize + 2;
    let steps = steps.clamp(2, 1_000_000);

    let clusters: Vec<ClusterSpec> = if spec.clusters.is_empty() {
        vec![ClusterSpec::milling(Point::new(0.0, 0.0), 25.0)]
    } else {
        spec.clusters.clone()
    };
    let home: Vec<usize> = (0..nodes)
        .map(|i| {
            spec.assignment
                .get(i)
                .copied()
                .unwrap_or(i % clusters.len())
                .min(clusters.len() - 1)
        })
        .collect();

    let rng = CounterRng::new(seed, "mobility");
    let mut positions = vec![Point::default(); steps.saturating_mul(nodes)];

    // Non-carrier nodes: random waypoint inside their cluster disc, snapped so
    // they sit on streets rather than inside buildings.
    let carrier_nodes: Vec<usize> = spec
        .carriers
        .iter()
        .map(|c| c.node)
        .filter(|n| *n < nodes)
        .collect();

    for node in 0..nodes {
        if carrier_nodes.contains(&node) {
            continue;
        }
        let c = clusters.get(home[node]).copied().unwrap_or(clusters[0]);
        let waypoints = waypoint_schedule(&rng, node as u64, &c, &spec.grid, duration, step_s);
        write_walk(&mut positions, nodes, steps, node, step_s, &waypoints);
    }

    for carrier in &spec.carriers {
        if carrier.node >= nodes {
            continue;
        }
        let waypoints = carrier_schedule(carrier, &clusters, &spec.grid, duration);
        write_walk(
            &mut positions,
            nodes,
            steps,
            carrier.node,
            step_s,
            &waypoints,
        );
    }

    Trace {
        step,
        nodes,
        positions,
        grid: spec.grid,
        carrier_nodes,
    }
}

/// A timed sequence of positions: `(time_s, point)`, interpolated linearly.
type Waypoints = Vec<(f64, Point)>;

/// Intermediate points that keep a walk from `a` to `b` on the street network.
///
/// A straight line between two street points cuts through buildings, which
/// would silently corrupt the obstruction count that the PHY model depends on.
/// Both endpoints lie on some street line, so turning at the grid lines nearest
/// `b` is always a legal route: at most two corners.
fn street_route(grid: &StreetGrid, a: Point, b: Point) -> Vec<Point> {
    if grid.block_m <= 0.0 {
        return vec![b];
    }
    let ib = grid.snap_to_intersection(b);
    let mut pts = Vec::with_capacity(3);
    let p1 = if grid.on_vertical_street(a) {
        Point::new(a.x, ib.y)
    } else {
        Point::new(ib.x, a.y)
    };
    pts.push(p1);
    let p2 = if grid.on_vertical_street(b) {
        Point::new(b.x, p1.y)
    } else {
        Point::new(p1.x, b.y)
    };
    pts.push(p2);
    pts.push(b);
    pts.dedup_by(|x, y| x.distance_to(y) < 1e-6);
    pts
}

fn waypoint_schedule(
    rng: &CounterRng,
    node: u64,
    c: &ClusterSpec,
    grid: &StreetGrid,
    duration: SimTime,
    step_s: f64,
) -> Waypoints {
    let total = duration.as_secs_f64() + step_s * 2.0;
    let mut out: Waypoints = Vec::new();
    let start = sample_in_cluster(rng, node, 0, c, grid);
    out.push((0.0, start));
    if !(c.speed_mps > 0.0) {
        out.push((total, start));
        return out;
    }
    let mut t = 0.0;
    let mut here = start;
    let mut k = 1u64;
    // Bounded: a two-hour trace at 1.3 m/s inside a 25 m disc is a few hundred
    // waypoints, and the cap stops a pathological config from allocating.
    while t < total && k < 20_000 {
        let next = sample_in_cluster(rng, node, k, c, grid);
        // Walk the street network rather than straight across a building.
        for leg_end in street_route(grid, here, next) {
            let leg = here.distance_to(&leg_end) / c.speed_mps.max(0.1);
            if leg.is_finite() {
                t += leg;
            }
            out.push((t, leg_end));
            here = leg_end;
        }
        let pause = c.pause_s.max(0.0) * rng.uniform(node, 0xC0FFEE, k);
        t += pause;
        out.push((t, here));
        k += 1;
    }
    out
}

fn sample_in_cluster(
    rng: &CounterRng,
    node: u64,
    k: u64,
    c: &ClusterSpec,
    grid: &StreetGrid,
) -> Point {
    let r = c.radius_m.max(0.0) * rng.uniform(node, 1, k).sqrt();
    let th = core::f64::consts::TAU * rng.uniform(node, 2, k);
    let raw = Point::new(c.centre.x + r * th.cos(), c.centre.y + r * th.sin());
    // Pull the point onto the nearest street line so pedestrians are not
    // standing inside buildings; keeps the obstruction count honest.
    nearest_street_point(grid, raw)
}

fn nearest_street_point(grid: &StreetGrid, p: Point) -> Point {
    if grid.block_m <= 0.0 {
        return p;
    }
    if grid.is_street(p) {
        return p;
    }
    let snap = |v: f64| (v / grid.block_m).round() * grid.block_m;
    let sx = snap(p.x);
    let sy = snap(p.y);
    if (p.x - sx).abs() <= (p.y - sy).abs() {
        Point::new(sx, p.y)
    } else {
        Point::new(p.x, sy)
    }
}

fn carrier_schedule(
    carrier: &CarrierSpec,
    clusters: &[ClusterSpec],
    grid: &StreetGrid,
    duration: SimTime,
) -> Waypoints {
    let total = duration.as_secs_f64() + 2.0;
    let route: Vec<usize> = carrier
        .route
        .iter()
        .copied()
        .filter(|i| *i < clusters.len())
        .collect();
    let mut out: Waypoints = Vec::new();
    if route.is_empty() {
        let p = clusters.first().map(|c| c.centre).unwrap_or_default();
        out.push((0.0, p));
        out.push((total, p));
        return out;
    }
    let speed = if carrier.speed_mps.is_finite() && carrier.speed_mps > 0.05 {
        carrier.speed_mps
    } else {
        1.3
    };
    let mut t = carrier.start_delay_s.max(0.0);
    let mut here = grid.snap_to_intersection(
        clusters
            .get(route[0])
            .map(|c| c.centre)
            .unwrap_or_default(),
    );
    out.push((0.0, here));
    out.push((t, here));
    let mut hop = 0usize;
    // Bounded loop: one iteration per cluster visit.
    while t < total && hop < 10_000 {
        let next_idx = route[(hop + 1) % route.len()];
        let dest = grid.snap_to_intersection(
            clusters
                .get(next_idx)
                .map(|c| c.centre)
                .unwrap_or_default(),
        );
        // Manhattan along streets: x first, then y. Both endpoints are snapped
        // to intersections, so both legs run down a street rather than through
        // a building.
        let corner = Point::new(dest.x, here.y);
        let leg1 = here.distance_to(&corner) / speed;
        t += leg1;
        out.push((t, corner));
        let leg2 = corner.distance_to(&dest) / speed;
        t += leg2;
        out.push((t, dest));
        t += carrier.dwell_s.max(0.0);
        out.push((t, dest));
        here = dest;
        hop += 1;
    }
    out
}

fn write_walk(
    positions: &mut [Point],
    nodes: usize,
    steps: usize,
    node: usize,
    step_s: f64,
    waypoints: &Waypoints,
) {
    if waypoints.is_empty() || nodes == 0 {
        return;
    }
    let mut wi = 0usize;
    for k in 0..steps {
        let t = k as f64 * step_s;
        while wi + 1 < waypoints.len() && waypoints[wi + 1].0 <= t {
            wi += 1;
        }
        let p = if wi + 1 >= waypoints.len() {
            waypoints[waypoints.len() - 1].1
        } else {
            let (t0, p0) = waypoints[wi];
            let (t1, p1) = waypoints[wi + 1];
            let span = t1 - t0;
            if span <= 1e-9 {
                p1
            } else {
                p0.lerp(&p1, (t - t0) / span)
            }
        };
        if let Some(slot) = positions.get_mut(k * nodes + node) {
            *slot = p;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_static_cluster_does_not_move() {
        let spec = MobilitySpec {
            clusters: vec![ClusterSpec::stationary(Point::new(0.0, 0.0), 10.0)],
            ..MobilitySpec::default()
        };
        let tr = build_trace(&spec, 4, SimTime::from_secs(60), 1);
        for n in 0..4 {
            let a = tr.position(n, SimTime::ZERO);
            let b = tr.position(n, SimTime::from_secs(59));
            assert!(a.distance_to(&b) < 1e-9);
        }
    }

    #[test]
    fn a_carrier_actually_arrives_at_the_far_cluster() {
        let spec = MobilitySpec {
            clusters: vec![
                ClusterSpec::stationary(Point::new(0.0, 0.0), 10.0),
                ClusterSpec::stationary(Point::new(480.0, 0.0), 10.0),
            ],
            assignment: vec![0, 1, 0],
            carriers: vec![CarrierSpec {
                node: 2,
                route: vec![0, 1],
                speed_mps: 1.4,
                dwell_s: 60.0,
                start_delay_s: 10.0,
            }],
            ..MobilitySpec::default()
        };
        let dur = SimTime::from_secs(1200);
        let tr = build_trace(&spec, 3, dur, 7);
        let start = tr.position(2, SimTime::ZERO);
        assert!(start.distance_to(&Point::new(0.0, 0.0)) < 1.0);
        // 480 m at 1.4 m/s is 343 s, plus a 10 s delay.
        let arrived = tr.position(2, SimTime::from_secs(400));
        assert!(
            arrived.distance_to(&Point::new(480.0, 0.0)) < 5.0,
            "carrier at {arrived:?} after 400 s"
        );
        // And it comes back: 10 s delay + 343 s out + 60 s dwell + 343 s back
        // puts it home from t=756 s until it sets off again at t=816 s.
        let returned = tr.position(2, SimTime::from_secs(790));
        assert!(
            returned.distance_to(&Point::new(0.0, 0.0)) < 5.0,
            "carrier at {returned:?} after 790 s"
        );
    }

    #[test]
    fn trace_is_byte_identical_for_the_same_seed() {
        let spec = MobilitySpec {
            clusters: vec![ClusterSpec::milling(Point::new(0.0, 0.0), 30.0)],
            ..MobilitySpec::default()
        };
        let a = build_trace(&spec, 12, SimTime::from_secs(300), 99);
        let b = build_trace(&spec, 12, SimTime::from_secs(300), 99);
        let c = build_trace(&spec, 12, SimTime::from_secs(300), 100);
        assert_eq!(a.digest(), b.digest());
        assert_ne!(a.digest(), c.digest());
    }

    #[test]
    fn walkers_stay_on_streets() {
        let grid = StreetGrid::default();
        let spec = MobilitySpec {
            clusters: vec![ClusterSpec::milling(Point::new(40.0, 40.0), 60.0)],
            grid,
            ..MobilitySpec::default()
        };
        let tr = build_trace(&spec, 20, SimTime::from_secs(120), 5);
        let mut off = 0;
        for n in 0..20 {
            for k in 0..120 {
                if !grid.is_street(tr.position(n, SimTime::from_secs(k))) {
                    off += 1;
                }
            }
        }
        // Linear interpolation between two street points can cut a corner, so a
        // few samples off-street are expected; most must be on-street.
        assert!(off < 20 * 120 / 4, "{off} off-street samples of 2400");
    }

    #[test]
    fn blocks_between_counts_building_interiors() {
        let grid = StreetGrid {
            block_m: 80.0,
            street_width_m: 14.0,
            obstruction_samples: 128,
        };
        // Straight down a street: nothing in the way.
        assert_eq!(
            grid.blocks_between(Point::new(0.0, 0.0), Point::new(240.0, 0.0)),
            0
        );
        // Diagonally across the grid: several blocks.
        let n = grid.blocks_between(Point::new(0.0, 0.0), Point::new(240.0, 240.0));
        assert!((2..=4).contains(&n), "diagonal crossed {n} blocks");
        // Round one corner.
        assert_eq!(
            grid.blocks_between(Point::new(10.0, 40.0), Point::new(70.0, 10.0)),
            1
        );
    }

    #[test]
    fn degenerate_specs_do_not_panic() {
        let spec = MobilitySpec {
            grid: StreetGrid {
                block_m: 0.0,
                street_width_m: -1.0,
                obstruction_samples: 0,
            },
            clusters: vec![],
            assignment: vec![99, 99],
            carriers: vec![CarrierSpec {
                node: 50,
                route: vec![42],
                speed_mps: f64::NAN,
                dwell_s: -1.0,
                start_delay_s: f64::INFINITY,
            }],
            step_s: 0.0,
        };
        let tr = build_trace(&spec, 2, SimTime::from_secs(10), 1);
        let _ = tr.position(0, SimTime::from_secs(1000));
        let _ = tr.position(50, SimTime::ZERO);
        let _ = tr.digest();
    }
}
