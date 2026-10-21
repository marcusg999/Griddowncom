//! Platform asymmetry, as a first-class property of a node.
//!
//! This is the module that decides whether the simulator is worth anything. The
//! dominant cause of multi-hop failure in this class of app is not path loss,
//! it is that a backgrounded iPhone is a crippled BLE device and everybody's
//! marketing material models phones as symmetric.
//!
//! Four separate iOS background constraints are modelled, because they bite in
//! different ways:
//!
//! 1. **No simultaneous advertise and scan.** A backgrounded iOS app does not
//!    get to do both at once; CoreBluetooth time-slices the two roles. Modelled
//!    as a scan duty cycle and an advertising schedule that are disjoint in
//!    time, so two backgrounded iPhones can sit a metre apart and miss each
//!    other for a long time.
//! 2. **No local name in the advertisement.** A backgrounded iOS peripheral
//!    drops `CBAdvertisementDataLocalNameKey` and only its service UUID
//!    survives, in the "overflow" area. A peer therefore cannot identify it
//!    from the advertisement and must pay a GATT connection just to find out
//!    who it is.
//! 3. **No usable advertisement payload.** CoreBluetooth never exposed
//!    extended advertising, so an iOS advertisement cannot carry a 96-byte
//!    frame even in the foreground. Every frame to or from an iOS device goes
//!    over a GATT connection. Android, which does expose extended advertising
//!    from API 26, can flood connectionlessly. This single difference is why an
//!    all-Android mesh behaves like a broadcast medium and a mixed mesh behaves
//!    like a connection-churn machine.
//! 4. **Longer advertising interval and fewer concurrent links.** Backgrounded
//!    iOS advertises roughly once a second rather than roughly seven times a
//!    second, and sustains fewer simultaneous connections before the scheduler
//!    starts dropping events.
//!
//! Every number below is an assumption until the user's field round contradicts
//! it. They are stated here, in one place, so they can be argued with.

use crate::clock::SimTime;
use crate::phy::{BodyPosition, PhyMode};
use crate::provenance::{ParamDoc, ParamSource};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Ios,
    Android,
}

impl Platform {
    pub fn as_str(self) -> &'static str {
        match self {
            Platform::Ios => "ios",
            Platform::Android => "android",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppState {
    /// Screen on, app on top.
    Foreground,
    /// Screen off or app not on top. `docs/METRICS.md`: a foreground-only
    /// number is not a number.
    Background,
}

impl AppState {
    pub fn as_str(self) -> &'static str {
        match self {
            AppState::Foreground => "foreground",
            AppState::Background => "background",
        }
    }
}

/// The pair that names a radio regime.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
pub struct Regime {
    pub platform: Platform,
    pub state: AppState,
}

impl Regime {
    pub fn key(self) -> String {
        format!("{}_{}", self.platform.as_str(), self.state.as_str())
    }
}

/// How one platform/app-state combination actually behaves on the air.
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub struct RadioProfile {
    /// Mean interval between advertising events.
    pub adv_interval_us: u64,
    /// Scan duty cycle: a window of `scan_window_us` every `scan_interval_us`.
    pub scan_window_us: u64,
    pub scan_interval_us: u64,
    /// False for backgrounded iOS: advertising and scanning are time-sliced,
    /// never concurrent.
    pub concurrent_adv_scan: bool,
    /// Bytes of our own frame an advertisement can carry. Zero means the
    /// platform cannot flood connectionlessly at all and must use GATT.
    pub adv_payload_bytes: usize,
    /// Whether the advertisement identifies the peer. When false, a scanner
    /// must open a connection to find out who it heard.
    pub local_name_in_adv: bool,
    /// Extra time to resolve a peer's identity when the advertisement does not
    /// carry it: connect, discover services, read the identity characteristic.
    pub name_resolution_extra_us: u64,
    /// Whether this regime can initiate outgoing connections.
    pub can_initiate: bool,
    pub max_concurrent_links: u8,
    /// Connection interval once established.
    pub conn_interval_us: u64,
    /// Link-layer packets the host actually keeps up with per connection event.
    pub packets_per_conn_event: u8,
    /// Time from deciding to connect to a usable GATT link, excluding
    /// `name_resolution_extra_us`.
    pub conn_setup_us: u64,
    /// Negotiated ATT MTU.
    pub att_mtu: usize,
    /// Fraction of scheduled radio events the OS actually honours. Background
    /// app scheduling is not reliable and pretending it is makes background
    /// numbers look like foreground ones.
    pub event_reliability: f64,
}

impl RadioProfile {
    /// Fraction of wall-clock time the radio is listening.
    pub fn scan_duty(&self) -> f64 {
        if self.scan_interval_us == 0 {
            return 0.0;
        }
        (self.scan_window_us as f64 / self.scan_interval_us as f64).clamp(0.0, 1.0)
    }

    /// Advertising duty cycle, counting only the slots that fit outside the
    /// scan windows when the two roles cannot overlap.
    pub fn effective_adv_rate_hz(&self) -> f64 {
        if self.adv_interval_us == 0 {
            return 0.0;
        }
        let raw = 1e6 / self.adv_interval_us as f64;
        let share = if self.concurrent_adv_scan {
            1.0
        } else {
            (1.0 - self.scan_duty()).max(0.0)
        };
        raw * share * self.event_reliability.clamp(0.0, 1.0)
    }

    /// Theoretical GATT goodput in bytes per second.
    pub fn link_goodput_bps(&self) -> f64 {
        if self.conn_interval_us == 0 {
            return 0.0;
        }
        let per_event = (self.att_mtu.saturating_sub(3)) as f64
            * f64::from(self.packets_per_conn_event);
        per_event * 1e6 / self.conn_interval_us as f64 * self.event_reliability
    }

    /// Can this regime put a whole frame of `n` bytes into an advertisement.
    pub fn can_broadcast(&self, n: usize) -> bool {
        self.adv_payload_bytes >= n
    }
}

/// The table of profiles. Loadable from a scenario file so a field round can
/// move any of it.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct PlatformConfig {
    pub ios_foreground: RadioProfile,
    pub ios_background: RadioProfile,
    pub android_foreground: RadioProfile,
    pub android_background: RadioProfile,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        PlatformConfig {
            // iOS foreground: continuous central scanning, 152.5 ms advertising
            // interval, and a 28-byte advertisement that still cannot hold a
            // frame. CoreBluetooth exposes no extended advertising, so even in
            // the foreground every frame goes over GATT.
            ios_foreground: RadioProfile {
                adv_interval_us: 152_500,
                scan_window_us: 1_000_000,
                scan_interval_us: 1_000_000,
                concurrent_adv_scan: true,
                adv_payload_bytes: 0,
                local_name_in_adv: true,
                name_resolution_extra_us: 0,
                can_initiate: true,
                max_concurrent_links: 8,
                conn_interval_us: 30_000,
                packets_per_conn_event: 4,
                conn_setup_us: 350_000,
                att_mtu: 185,
                event_reliability: 0.98,
            },
            // iOS background: the hard case. Scan and advertise time-sliced,
            // ~1.02 s advertising interval, no local name, no advertisement
            // payload, fewer links, and an OS that drops radio events.
            ios_background: RadioProfile {
                adv_interval_us: 1_022_500,
                scan_window_us: 300_000,
                scan_interval_us: 1_000_000,
                concurrent_adv_scan: false,
                adv_payload_bytes: 0,
                local_name_in_adv: false,
                name_resolution_extra_us: 900_000,
                can_initiate: true,
                max_concurrent_links: 3,
                conn_interval_us: 60_000,
                packets_per_conn_event: 2,
                conn_setup_us: 1_200_000,
                att_mtu: 185,
                event_reliability: 0.75,
            },
            // Android foreground: SCAN_MODE_LOW_LATENCY is a 4096 ms window
            // every 4096 ms, i.e. continuous, and extended advertising carries a
            // whole frame connectionlessly.
            android_foreground: RadioProfile {
                adv_interval_us: 100_000,
                scan_window_us: 4_096_000,
                scan_interval_us: 4_096_000,
                concurrent_adv_scan: true,
                adv_payload_bytes: 255,
                local_name_in_adv: true,
                name_resolution_extra_us: 0,
                can_initiate: true,
                max_concurrent_links: 7,
                conn_interval_us: 30_000,
                packets_per_conn_event: 6,
                conn_setup_us: 250_000,
                att_mtu: 247,
                event_reliability: 0.98,
            },
            // Android background, inside a foreground service so the scan is
            // not throttled away: SCAN_MODE_BALANCED is 1024 ms every 4096 ms.
            // Still advertises and scans at the same time, still carries frames
            // in extended advertisements. This is the asymmetry.
            android_background: RadioProfile {
                adv_interval_us: 250_000,
                scan_window_us: 1_024_000,
                scan_interval_us: 4_096_000,
                concurrent_adv_scan: true,
                adv_payload_bytes: 255,
                local_name_in_adv: true,
                name_resolution_extra_us: 0,
                can_initiate: true,
                max_concurrent_links: 5,
                conn_interval_us: 60_000,
                packets_per_conn_event: 4,
                conn_setup_us: 400_000,
                att_mtu: 247,
                event_reliability: 0.92,
            },
        }
    }
}

impl PlatformConfig {
    pub fn profile(&self, r: Regime) -> &RadioProfile {
        match (r.platform, r.state) {
            (Platform::Ios, AppState::Foreground) => &self.ios_foreground,
            (Platform::Ios, AppState::Background) => &self.ios_background,
            (Platform::Android, AppState::Foreground) => &self.android_foreground,
            (Platform::Android, AppState::Background) => &self.android_background,
        }
    }

    pub fn provenance(&self) -> Vec<ParamDoc> {
        let p = &self.ios_background;
        vec![
            ParamDoc::new(
                "ios_bg_concurrent_adv_scan",
                0.0,
                "bool",
                ParamSource::lit(
                    "A backgrounded CoreBluetooth app does not reliably advertise and \
                     scan at the same time; the roles are time-sliced by the OS. \
                     Modelled as disjoint advertise and scan schedules.",
                ),
            ),
            ParamDoc::new(
                "ios_bg_local_name_in_adv",
                0.0,
                "bool",
                ParamSource::lit(
                    "A backgrounded iOS peripheral drops the local name from its \
                     advertisement; only the service UUID survives, in the overflow \
                     area. Identity therefore costs a GATT connection.",
                ),
            ),
            ParamDoc::new(
                "ios_adv_payload_bytes",
                0.0,
                "bytes",
                ParamSource::lit(
                    "CoreBluetooth exposes no extended advertising, so an iOS \
                     advertisement cannot carry a gdc-wire frame (minimum 96 bytes) \
                     in any app state. Android exposes extended advertising from API \
                     26, hence 255. THIS IS THE LARGEST SINGLE ASYMMETRY IN THE \
                     MODEL: it decides whether a platform can flood at all.",
                ),
            ),
            ParamDoc::new(
                "ios_bg_adv_interval_us",
                p.adv_interval_us as f64,
                "us",
                ParamSource::lit(
                    "Backgrounded iOS advertising interval is widely reported at \
                     1022.5 ms against 152.5 ms in the foreground.",
                ),
            ),
            ParamDoc::new(
                "ios_bg_scan_duty",
                p.scan_duty(),
                "",
                ParamSource::assumed(
                    "Backgrounded iOS scanning is coalesced and opportunistic with no \
                     documented duty cycle. 30% assumed. MEASURE: it sets \
                     background neighbour-acquisition time, the transport metric most \
                     likely to be wrong by a factor of three.",
                ),
            ),
            ParamDoc::new(
                "ios_bg_event_reliability",
                p.event_reliability,
                "",
                ParamSource::assumed(
                    "Fraction of scheduled radio events the OS honours when the app \
                     is backgrounded. 0.75 assumed for iOS, 0.92 for Android inside a \
                     foreground service.",
                ),
            ),
            ParamDoc::new(
                "android_fg_scan_duty",
                self.android_foreground.scan_duty(),
                "",
                ParamSource::spec(
                    "AOSP ScanSettings SCAN_MODE_LOW_LATENCY is a 4096 ms window \
                     every 4096 ms, i.e. continuous; SCAN_MODE_BALANCED is 1024 ms \
                     every 4096 ms, which is the backgrounded value.",
                ),
            ),
            ParamDoc::new(
                "ios_bg_conn_setup_us",
                p.conn_setup_us as f64,
                "us",
                ParamSource::assumed(
                    "Connection establishment from a backgrounded iOS central, \
                     including service discovery. 1.2 s assumed against 0.25 s for \
                     foreground Android.",
                ),
            ),
        ]
    }
}

/// Everything about one simulated phone that is not its position.
#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
pub struct NodeProfile {
    pub platform: Platform,
    pub state: AppState,
    pub body: BodyPosition,
    /// Which PHY this node transmits on. A live lever: a scenario can put the
    /// whole mesh on Coded S=8 and pay the airtime.
    pub phy: PhyMode,
}

impl NodeProfile {
    pub fn regime(&self) -> Regime {
        Regime {
            platform: self.platform,
            state: self.state,
        }
    }
}

/// Is a node's scan window open at `t`.
///
/// `phase` spreads nodes out so they do not all scan in lockstep, and comes
/// from the world seed rather than from anything a protocol does.
pub fn scanning_at(p: &RadioProfile, phase_us: u64, t: SimTime) -> bool {
    if p.scan_interval_us == 0 || p.scan_window_us == 0 {
        return false;
    }
    let pos = (t.as_micros().wrapping_add(phase_us)) % p.scan_interval_us;
    pos < p.scan_window_us
}

/// Does a scan window overlap the interval `[start, end)`.
///
/// Reception of a connectionless broadcast requires the receiver to be
/// listening for at least the whole packet; BLE has no mid-packet join, so this
/// is a containment test, not an intersection test.
pub fn scan_covers(p: &RadioProfile, phase_us: u64, start: SimTime, end: SimTime) -> bool {
    scanning_at(p, phase_us, start) && scanning_at(p, phase_us, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backgrounded_ios_is_a_materially_worse_relay_than_backgrounded_android() {
        let c = PlatformConfig::default();
        let ios = c.profile(Regime {
            platform: Platform::Ios,
            state: AppState::Background,
        });
        let andro = c.profile(Regime {
            platform: Platform::Android,
            state: AppState::Background,
        });

        // It advertises less often...
        assert!(
            ios.effective_adv_rate_hz() < andro.effective_adv_rate_hz() * 0.5,
            "ios bg {:.2} Hz vs android bg {:.2} Hz",
            ios.effective_adv_rate_hz(),
            andro.effective_adv_rate_hz()
        );
        // ...it cannot flood connectionlessly at all...
        assert!(!ios.can_broadcast(96));
        assert!(andro.can_broadcast(96));
        // ...it needs a connection just to learn who it heard...
        assert!(!ios.local_name_in_adv);
        assert!(ios.name_resolution_extra_us > 0);
        // ...it holds fewer links and pushes fewer bytes through each.
        assert!(ios.max_concurrent_links < andro.max_concurrent_links);
        assert!(ios.link_goodput_bps() < andro.link_goodput_bps() * 0.5);
    }

    #[test]
    fn backgrounded_ios_cannot_advertise_and_scan_at_once() {
        let c = PlatformConfig::default();
        let ios_bg = c.profile(Regime {
            platform: Platform::Ios,
            state: AppState::Background,
        });
        assert!(!ios_bg.concurrent_adv_scan);
        // The advertising rate is reduced by exactly the scan duty cycle,
        // because the two roles cannot share the radio.
        let raw = 1e6 / ios_bg.adv_interval_us as f64;
        let expect = raw * (1.0 - ios_bg.scan_duty()) * ios_bg.event_reliability;
        assert!((ios_bg.effective_adv_rate_hz() - expect).abs() < 1e-9);
        // Android does not pay this.
        let a = c.profile(Regime {
            platform: Platform::Android,
            state: AppState::Foreground,
        });
        assert!(a.concurrent_adv_scan);
    }

    #[test]
    fn foreground_beats_background_on_every_platform() {
        let c = PlatformConfig::default();
        for pf in [Platform::Ios, Platform::Android] {
            let fg = c.profile(Regime {
                platform: pf,
                state: AppState::Foreground,
            });
            let bg = c.profile(Regime {
                platform: pf,
                state: AppState::Background,
            });
            assert!(fg.scan_duty() >= bg.scan_duty(), "{pf:?}");
            assert!(
                fg.effective_adv_rate_hz() > bg.effective_adv_rate_hz(),
                "{pf:?}"
            );
            assert!(fg.link_goodput_bps() > bg.link_goodput_bps(), "{pf:?}");
        }
    }

    #[test]
    fn scan_schedules_are_disjoint_enough_to_miss_each_other() {
        // Two backgrounded iPhones with different phases: there are instants
        // where neither is listening, which is the whole point.
        let c = PlatformConfig::default();
        let p = c.profile(Regime {
            platform: Platform::Ios,
            state: AppState::Background,
        });
        let mut both_deaf = 0;
        for k in 0..1000u64 {
            let t = SimTime::from_micros(k * 1_000);
            if !scanning_at(p, 0, t) && !scanning_at(p, 500_000, t) {
                both_deaf += 1;
            }
        }
        assert!(both_deaf > 300, "expected long mutual deafness, got {both_deaf}");
    }

    #[test]
    fn degenerate_profiles_do_not_divide_by_zero() {
        let mut p = PlatformConfig::default().android_foreground;
        p.scan_interval_us = 0;
        p.adv_interval_us = 0;
        p.conn_interval_us = 0;
        assert_eq!(p.scan_duty(), 0.0);
        assert_eq!(p.effective_adv_rate_hz(), 0.0);
        assert_eq!(p.link_goodput_bps(), 0.0);
        assert!(!scanning_at(&p, 0, SimTime::ZERO));
    }
}
