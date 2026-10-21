//! Scenario configuration: everything a run is, reproducible from a seed plus
//! this struct.
//!
//! Serde round-trips, so the CLI can emit a template, a human can edit it, and
//! the same file re-run a year later gives the same numbers. Every field has a
//! default, so a scenario file may be as short as `{"nodes": 20}`.

use crate::clock::SimTime;
use crate::link::LinkConfig;
use crate::mobility::{CarrierSpec, ClusterSpec, MobilitySpec, Point};
use crate::phy::{BodyPosition, PhyConfig, PhyMode};
use crate::platform::{AppState, NodeProfile, Platform, PlatformConfig};
use crate::SimError;
use serde::{Deserialize, Serialize};

/// Which world shape to build.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Topology {
    /// Everyone milling about in one disc. The density-sweep topology:
    /// 5/20/50/150 nodes in range of each other.
    Cluster { radius_m: f64 },
    /// A line of nodes at fixed spacing. The M2 static-chain regime: adjacent
    /// pairs are in range, non-adjacent pairs are not, so hop count is forced.
    StaticChain { spacing_m: f64 },
    /// Clusters placed far enough apart that no radio path exists between
    /// them, plus carriers who walk between them. The M2 carrier regime.
    CarrierClusters {
        clusters: usize,
        spacing_m: f64,
        radius_m: f64,
        /// How many nodes walk the route. Zero is the control case: the chain
        /// stays broken and nothing should be delivered across it.
        carriers: usize,
        dwell_s: f64,
        speed_mps: f64,
    },
    /// Anything else, written out longhand.
    Custom { mobility: MobilitySpec },
}

impl Default for Topology {
    fn default() -> Self {
        Topology::Cluster { radius_m: 30.0 }
    }
}

/// Who generates application traffic.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SourceSpec {
    /// Every node sends.
    All,
    /// Only node 0. Used for chain and carrier scenarios, where the point is
    /// one message crossing a known number of hops.
    First,
    Nodes { nodes: Vec<usize> },
}

impl Default for SourceSpec {
    fn default() -> Self {
        SourceSpec::All
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct OfferedLoad {
    /// Messages per sending node per minute, as a Poisson rate.
    pub msgs_per_node_per_min: f64,
    /// Application payload size. `docs/BRIEF.md` caps user text at 500 bytes;
    /// the default is a typical canned-pad selection plus a location pin.
    pub body_bytes: usize,
    pub urgent_fraction: f64,
    pub want_ack: bool,
    pub sources: SourceSpec,
    /// Stop generating new traffic this many seconds before the end, so that
    /// late messages are not counted as failures for want of time to arrive.
    pub quiet_tail_s: f64,
}

impl Default for OfferedLoad {
    fn default() -> Self {
        OfferedLoad {
            msgs_per_node_per_min: 2.0,
            body_bytes: 48,
            urgent_fraction: 0.0,
            want_ack: false,
            sources: SourceSpec::default(),
            quiet_tail_s: 30.0,
        }
    }
}

/// Nodes joining and leaving.
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct ChurnSpec {
    /// Expected number of node departures per minute across the whole world.
    pub departures_per_min: f64,
    /// Mean time a departed node stays away.
    pub mean_absence_s: f64,
}

impl Default for ChurnSpec {
    fn default() -> Self {
        ChurnSpec {
            departures_per_min: 0.0,
            mean_absence_s: 60.0,
        }
    }
}

/// The platform and app-state mix. `docs/METRICS.md`: a foreground-only number
/// is not a number, so the default is a realistic mixed, mostly-backgrounded
/// world rather than a flattering one.
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeMix {
    pub ios_fraction: f64,
    pub background_fraction: f64,
    /// Fraction of nodes held in a hand rather than carried in a pocket.
    pub in_hand_fraction: f64,
    /// Of the pocketed nodes, the fraction with the torso in the path.
    pub body_blocked_fraction: f64,
    pub phy: PhyMode,
}

impl Default for NodeMix {
    fn default() -> Self {
        NodeMix {
            ios_fraction: 0.5,
            background_fraction: 1.0,
            in_hand_fraction: 0.0,
            body_blocked_fraction: 0.5,
            phy: PhyMode::Ble1M,
        }
    }
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Scenario {
    pub name: String,
    pub seed: u64,
    pub duration_s: f64,
    pub nodes: usize,
    pub mix: NodeMix,
    pub topology: Topology,
    pub load: OfferedLoad,
    pub churn: ChurnSpec,
    pub phy: PhyConfig,
    pub platforms: PlatformConfig,
    pub link: LinkConfig,
    /// Delivery-rate deadlines, seconds. `docs/METRICS.md` fixes these at
    /// 30 s / 5 min / 30 min / 2 h, because "eventually" is a different product
    /// from "now".
    pub deadlines_s: Vec<f64>,
    /// Pedestrian wander speed inside a cluster.
    pub wander_speed_mps: f64,
}

impl Default for Scenario {
    fn default() -> Self {
        Scenario {
            name: "default".into(),
            seed: 1,
            duration_s: 300.0,
            nodes: 20,
            mix: NodeMix::default(),
            topology: Topology::default(),
            load: OfferedLoad::default(),
            churn: ChurnSpec::default(),
            phy: PhyConfig::default(),
            platforms: PlatformConfig::default(),
            link: LinkConfig::default(),
            deadlines_s: vec![30.0, 300.0, 1800.0, 7200.0],
            wander_speed_mps: 1.3,
        }
    }
}

impl Scenario {
    pub fn duration(&self) -> SimTime {
        SimTime::from_secs_f64(self.duration_s)
    }

    /// Reject anything that cannot be simulated, rather than producing numbers
    /// from a nonsense world.
    pub fn validate(&self) -> Result<(), SimError> {
        let bad = |m: &str| Err(SimError::BadScenario(m.to_string()));
        if self.nodes == 0 {
            return bad("nodes must be at least 1");
        }
        if self.nodes > 2000 {
            return bad("nodes capped at 2000; the engine is O(n^2) in neighbour checks");
        }
        if !(self.duration_s.is_finite() && self.duration_s > 0.0) {
            return bad("duration_s must be finite and positive");
        }
        if self.duration_s > 86_400.0 {
            return bad("duration_s capped at 86400 (one day)");
        }
        if self.load.body_bytes > gdc_wire::MAX_BODY_LEN {
            return bad("load.body_bytes exceeds gdc_wire::MAX_BODY_LEN");
        }
        if self.deadlines_s.is_empty() {
            return bad("at least one deadline is required");
        }
        if self.deadlines_s.iter().any(|d| !d.is_finite() || *d <= 0.0) {
            return bad("deadlines must be finite and positive");
        }
        for f in [
            self.mix.ios_fraction,
            self.mix.background_fraction,
            self.mix.in_hand_fraction,
            self.mix.body_blocked_fraction,
            self.load.urgent_fraction,
        ] {
            if !(0.0..=1.0).contains(&f) {
                return bad("fractions in mix and load must lie in [0, 1]");
            }
        }
        if let Topology::CarrierClusters { clusters, .. } = &self.topology {
            if *clusters < 2 {
                return bad("CarrierClusters needs at least 2 clusters");
            }
            if *clusters > self.nodes {
                return bad("more clusters than nodes");
            }
        }
        Ok(())
    }

    /// Per-node platform, app state, body position and PHY.
    ///
    /// Deterministic in the seed and interleaved rather than blocked, so a
    /// chain scenario does not accidentally put all the iOS devices at one end.
    pub fn node_profiles(&self) -> Vec<NodeProfile> {
        let rng = crate::rng::CounterRng::new(self.seed, "node-mix");
        (0..self.nodes)
            .map(|i| {
                let n = i as u64;
                NodeProfile {
                    platform: if rng.uniform(n, 0, 0) < self.mix.ios_fraction {
                        Platform::Ios
                    } else {
                        Platform::Android
                    },
                    state: if rng.uniform(n, 1, 0) < self.mix.background_fraction {
                        AppState::Background
                    } else {
                        AppState::Foreground
                    },
                    body: if rng.uniform(n, 2, 0) < self.mix.in_hand_fraction {
                        BodyPosition::InHand
                    } else if rng.uniform(n, 3, 0) < self.mix.body_blocked_fraction {
                        BodyPosition::PocketBodyBlocked
                    } else {
                        BodyPosition::Pocket
                    },
                    phy: self.mix.phy,
                }
            })
            .collect()
    }

    /// Which nodes generate traffic.
    pub fn source_nodes(&self) -> Vec<usize> {
        match &self.load.sources {
            SourceSpec::All => (0..self.nodes).collect(),
            SourceSpec::First => vec![0],
            SourceSpec::Nodes { nodes } => {
                nodes.iter().copied().filter(|n| *n < self.nodes).collect()
            }
        }
    }

    /// Turn the topology into a mobility spec.
    pub fn mobility(&self) -> MobilitySpec {
        let wander = self.wander_speed_mps.max(0.0);
        match &self.topology {
            Topology::Cluster { radius_m } => MobilitySpec {
                clusters: vec![ClusterSpec {
                    centre: Point::new(0.0, 0.0),
                    radius_m: radius_m.max(0.0),
                    speed_mps: wander,
                    pause_s: 15.0,
                }],
                assignment: vec![0; self.nodes],
                ..MobilitySpec::default()
            },
            Topology::StaticChain { spacing_m } => {
                // One node per cluster, each cluster a zero-radius point on a
                // straight street. No wander, so the chain geometry is exact
                // and the hop count is not an accident of a random draw.
                let clusters: Vec<ClusterSpec> = (0..self.nodes)
                    .map(|i| {
                        ClusterSpec::stationary(
                            Point::new(i as f64 * spacing_m.max(1.0), 0.0),
                            0.0,
                        )
                    })
                    .collect();
                MobilitySpec {
                    clusters,
                    assignment: (0..self.nodes).collect(),
                    ..MobilitySpec::default()
                }
            }
            Topology::CarrierClusters {
                clusters,
                spacing_m,
                radius_m,
                carriers,
                dwell_s,
                speed_mps,
            } => {
                let nc = (*clusters).clamp(2, self.nodes.max(2));
                let grid = crate::mobility::StreetGrid::default();
                let specs: Vec<ClusterSpec> = (0..nc)
                    .map(|i| {
                        let centre = grid.snap_to_intersection(Point::new(
                            i as f64 * spacing_m.max(1.0),
                            0.0,
                        ));
                        ClusterSpec {
                            centre,
                            radius_m: radius_m.max(0.0),
                            speed_mps: wander,
                            pause_s: 15.0,
                        }
                    })
                    .collect();
                // Carriers are taken from the top of the node list so that the
                // resident population of each cluster is unaffected by how many
                // carriers a scenario has. That keeps the carrier and
                // no-carrier arms comparable.
                let ncar = (*carriers).min(self.nodes.saturating_sub(nc));
                let carrier_ids: Vec<usize> =
                    (0..ncar).map(|k| self.nodes - 1 - k).collect();
                let assignment: Vec<usize> = (0..self.nodes)
                    .map(|i| if carrier_ids.contains(&i) { 0 } else { i % nc })
                    .collect();
                let route: Vec<usize> = (0..nc).collect();
                MobilitySpec {
                    grid,
                    clusters: specs,
                    assignment,
                    carriers: carrier_ids
                        .iter()
                        .enumerate()
                        .map(|(k, node)| CarrierSpec {
                            node: *node,
                            route: route.clone(),
                            speed_mps: if *speed_mps > 0.0 { *speed_mps } else { 1.3 },
                            dwell_s: dwell_s.max(0.0),
                            // Stagger carriers so they do not all arrive at
                            // once, which would flatter the carrier regime.
                            start_delay_s: 10.0 + 20.0 * k as f64,
                        })
                        .collect(),
                    step_s: 1.0,
                }
            }
            Topology::Custom { mobility } => mobility.clone(),
        }
    }

    /// Convenience constructors for the scenarios `docs/METRICS.md` names.
    pub fn density(nodes: usize, seed: u64) -> Self {
        Scenario {
            name: format!("density-{nodes}"),
            nodes,
            seed,
            duration_s: 300.0,
            topology: Topology::Cluster { radius_m: 30.0 },
            load: OfferedLoad {
                msgs_per_node_per_min: 1.0,
                ..OfferedLoad::default()
            },
            ..Scenario::default()
        }
    }

    pub fn static_chain(hops: usize, spacing_m: f64, seed: u64) -> Self {
        Scenario {
            name: format!("static-chain-{hops}hop"),
            nodes: hops + 1,
            seed,
            duration_s: 600.0,
            topology: Topology::StaticChain { spacing_m },
            load: OfferedLoad {
                msgs_per_node_per_min: 6.0,
                sources: SourceSpec::First,
                ..OfferedLoad::default()
            },
            ..Scenario::default()
        }
    }

    pub fn carrier_regime(nodes: usize, carriers: usize, seed: u64) -> Self {
        Scenario {
            name: format!("carrier-{carriers}"),
            nodes,
            seed,
            duration_s: 3600.0,
            topology: Topology::CarrierClusters {
                clusters: 2,
                spacing_m: 480.0,
                radius_m: 15.0,
                carriers,
                dwell_s: 90.0,
                speed_mps: 1.4,
            },
            load: OfferedLoad {
                msgs_per_node_per_min: 0.5,
                sources: SourceSpec::First,
                quiet_tail_s: 1200.0,
                ..OfferedLoad::default()
            },
            ..Scenario::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_json() {
        let s = Scenario::carrier_regime(10, 1, 4);
        let text = serde_json::to_string_pretty(&s).expect("serialise");
        let back: Scenario = serde_json::from_str(&text).expect("deserialise");
        assert_eq!(s, back);
    }

    #[test]
    fn a_minimal_scenario_file_is_enough() {
        let s: Scenario = serde_json::from_str(r#"{"nodes": 7}"#).expect("parse");
        assert_eq!(s.nodes, 7);
        assert_eq!(s.deadlines_s.len(), 4);
        s.validate().expect("valid");
    }

    #[test]
    fn nonsense_scenarios_are_refused_not_simulated() {
        let cases = [
            r#"{"nodes": 0}"#,
            r#"{"duration_s": -1}"#,
            r#"{"duration_s": 0}"#,
            r#"{"nodes": 5000}"#,
            r#"{"deadlines_s": []}"#,
            r#"{"mix": {"ios_fraction": 1.5}}"#,
            r#"{"load": {"body_bytes": 9000}}"#,
            r#"{"topology": {"kind":"carrier_clusters","clusters":1,"spacing_m":100,
                 "radius_m":10,"carriers":1,"dwell_s":10,"speed_mps":1.0}}"#,
        ];
        for c in cases {
            let s: Scenario = serde_json::from_str(c).expect("parses");
            assert!(s.validate().is_err(), "should have been refused: {c}");
        }
    }

    #[test]
    fn carrier_topology_puts_carriers_outside_the_resident_population() {
        let s = Scenario::carrier_regime(9, 2, 1);
        let m = s.mobility();
        assert_eq!(m.carriers.len(), 2);
        let ids: Vec<usize> = m.carriers.iter().map(|c| c.node).collect();
        assert!(ids.contains(&8) && ids.contains(&7));
        // Residents split between the two clusters.
        let in_zero = (0..7).filter(|i| m.assignment[*i] == 0).count();
        assert!(in_zero >= 3 && in_zero <= 4, "{in_zero} residents in cluster 0");
        // Zero carriers is the control arm and must still be a legal world.
        let control = Scenario::carrier_regime(9, 0, 1);
        assert!(control.mobility().carriers.is_empty());
        control.validate().expect("valid");
    }

    #[test]
    fn the_node_mix_is_deterministic_and_actually_mixed() {
        let s = Scenario {
            nodes: 200,
            mix: NodeMix {
                ios_fraction: 0.5,
                background_fraction: 0.8,
                ..NodeMix::default()
            },
            ..Scenario::default()
        };
        let a = s.node_profiles();
        assert_eq!(a, s.node_profiles());
        let ios = a.iter().filter(|p| p.platform == Platform::Ios).count();
        let bg = a.iter().filter(|p| p.state == AppState::Background).count();
        assert!((80..=120).contains(&ios), "{ios} iOS of 200");
        assert!((140..=180).contains(&bg), "{bg} backgrounded of 200");
    }

    #[test]
    fn a_static_chain_is_a_straight_line_at_the_requested_spacing() {
        let s = Scenario::static_chain(3, 18.0, 1);
        assert_eq!(s.nodes, 4);
        let m = s.mobility();
        assert_eq!(m.clusters.len(), 4);
        for i in 0..4 {
            assert!((m.clusters[i].centre.x - i as f64 * 18.0).abs() < 1e-9);
        }
        assert_eq!(s.source_nodes(), vec![0]);
    }
}
