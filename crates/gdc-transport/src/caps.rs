//! The platform capability matrix, as data.
//!
//! One table. Four rows: {iOS, Android} x {foreground, background}. Every
//! awkward radio fact about either operating system lives here with a comment
//! explaining the constraint, so the rest of the stack reads a table instead of
//! scattering `if platform == ios` through the link layer.
//!
//! # Why this table is a first-class object
//!
//! The single most consequential fact about this product is that **an iPhone in
//! a pocket is a much weaker relay than an Android in a pocket**, and that
//! there is no infrastructure-free high-throughput path between the two
//! platforms at all. Those are not footnotes to be remembered by whoever is
//! reading the code that day; they are rows in [`MATRIX`], and the selection,
//! role-election and link-usability logic all derive from them.
//!
//! # Verification status
//!
//! iOS cannot be compiled, let alone run, in this environment: no Swift
//! toolchain, no macOS, no devices. Android can be compiled but not run. So
//! every row below is sourced from vendor documentation and published
//! behaviour, and every claim whose *numeric* value we have not measured is
//! marked `UNVERIFIED:` in a comment next to the field. Those markers are the
//! list of things the first instrumented field round has to settle.
//!
//! Device-specific truth narrows this table but never widens it: the native
//! shell reports a [`LocalCaps`] at startup and [`Caps::narrow`] intersects the
//! two. A platform row says what is *possible*; the host says what this handset
//! actually does.

use core::fmt;

/// The two platforms this product ships on.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Platform {
    Ios,
    Android,
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Platform::Ios => "iOS",
            Platform::Android => "Android",
        })
    }
}

/// Whether the app is in the foreground on a given end of a link.
///
/// This is the axis that `docs/METRICS.md` demands every transport number be
/// split on, because a foreground-only number is not a number.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum AppState {
    Foreground,
    /// Backgrounded, screen off, or otherwise not the active app. On Android we
    /// assume a running foreground service (the only way to keep BLE alive at
    /// all); on iOS we assume `bluetooth-central` + `bluetooth-peripheral`
    /// background modes.
    Background,
}

impl AppState {
    #[must_use]
    pub fn is_foreground(self) -> bool {
        matches!(self, AppState::Foreground)
    }
}

/// An infrastructure-free peer-to-peer Wi-Fi protocol.
///
/// These are listed as separate variants rather than a single "Wi-Fi" because
/// **none of them interoperate with any other**. Two Android phones can only
/// burst if they pick the same one; an iPhone and an Android cannot burst at
/// all, in either direction, under any configuration. That impossibility falls
/// out of [`shared_wifi`] returning `None`, rather than being special-cased.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum WifiFlavour {
    /// Wi-Fi Aware (NAN). Android 8+, and only on hardware that reports
    /// `FEATURE_WIFI_AWARE`. Preferred over Wi-Fi Direct where present: it
    /// does not take over the station interface and does not show the group
    /// negotiation UI.
    WifiAware,
    /// Wi-Fi Direct / p2p. Near-universal on Android, but heavier to bring up
    /// and more disruptive to any concurrent infrastructure connection.
    WifiDirect,
    /// MultipeerConnectivity over AWDL. iOS only. There is no public iOS API
    /// for Wi-Fi Direct or Wi-Fi Aware, so this is the only infra-free
    /// high-throughput option on that platform and it speaks to nothing else.
    Multipeer,
}

impl WifiFlavour {
    /// Preference order used when both ends offer more than one flavour.
    /// Lower is better.
    const fn rank(self) -> u8 {
        match self {
            WifiFlavour::WifiAware => 0,
            WifiFlavour::WifiDirect => 1,
            WifiFlavour::Multipeer => 2,
        }
    }
}

/// Three-valued support, because "we do not know" is a real and common answer
/// for a hardware feature we cannot probe from a Linux container.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Support {
    Yes,
    No,
    /// Hardware- or OS-version-dependent. Treated as [`Support::No`] by every
    /// policy decision until the host reports otherwise, so an unknown never
    /// turns into an optimistic assumption on a real radio.
    Unknown,
}

impl Support {
    /// Policy reads this, not the variant: unknown is not permission.
    #[must_use]
    pub fn is_usable(self) -> bool {
        matches!(self, Support::Yes)
    }

    #[must_use]
    fn and(self, other: Support) -> Support {
        match (self, other) {
            (Support::No, _) | (_, Support::No) => Support::No,
            (Support::Yes, Support::Yes) => Support::Yes,
            _ => Support::Unknown,
        }
    }
}

/// ATT MTU floor mandated by the Bluetooth spec. A peer may legally never
/// negotiate past this, so the fragmenter has to work here.
pub const ATT_MTU_FLOOR: u16 = 23;

/// Bytes of ATT overhead on a write-without-response or a notification:
/// 1-byte opcode + 2-byte attribute handle. The usable datagram is
/// `att_mtu - 3`, which at the floor is 20 bytes.
pub const ATT_OVERHEAD: u16 = 3;

/// One row of the capability matrix: what a given platform can do in a given
/// app state.
#[derive(Clone, Copy, Debug)]
pub struct Caps {
    pub platform: Platform,
    pub state: AppState,

    /// Can act as a BLE peripheral and be discovered.
    pub can_advertise: bool,
    /// Can act as a BLE central and discover others.
    pub can_scan: bool,
    /// Can do both at the same time without one starving the other.
    ///
    /// This is the field that encodes the central asymmetry of the product.
    pub can_advertise_and_scan: bool,
    /// Whether the advertisement carries a readable local name.
    ///
    /// A backgrounded iOS peripheral publishes **no** local name, so no part of
    /// the stack may use the advertised name for identification or for peer
    /// matching. (It must not anyway: `BRIDGEFY-FINDINGS` P-1 is exactly the
    /// bug of putting a stable identifier in `ADV_IND`. Here the platform
    /// enforces our own rule for us on one row and we enforce it ourselves on
    /// the other three.)
    pub local_name_visible: bool,
    /// Whether the OS lets us advertise a full 128-bit service UUID in the
    /// primary advertisement, or only in the vendor "overflow" area that is
    /// visible to a scanner explicitly looking for that UUID.
    pub service_uuid_in_primary_adv: bool,

    /// Infra-free Wi-Fi protocols available in this state, best first.
    pub wifi: &'static [WifiFlavour],

    /// Whether the platform exposes any API to select the BLE PHY.
    pub phy_selectable: Support,
    /// Whether LE Coded PHY (S=8) can be requested.
    pub coded_phy: Support,

    /// ATT MTU we expect after negotiation. A prior, not a promise: the
    /// fragmenter always uses the MTU the host reports for the live link.
    pub expected_att_mtu: u16,

    /// 0-10 score for how good a BLE scanner this row is. Drives role election:
    /// the better scanner becomes central, which is how we stop two
    /// backgrounded iPhones from both waiting to be found.
    pub scan_strength: u8,
    /// 0-10 score for how discoverable this row is.
    pub advertise_strength: u8,

    /// Multiplier applied to the BLE goodput prior for this state. Background
    /// connection intervals are stretched by the OS, which costs throughput.
    pub goodput_derate: f32,

    /// Human-readable note, surfaced in diagnostics and in the report.
    pub note: &'static str,
}

/// The matrix.
///
/// Read this table top to bottom before changing any policy in this crate.
pub static MATRIX: [Caps; 4] = [
    // ---------------------------------------------------------------------
    Caps {
        platform: Platform::Ios,
        state: AppState::Foreground,
        can_advertise: true,
        can_scan: true,
        // Foreground CoreBluetooth happily runs a CBCentralManager and a
        // CBPeripheralManager in the same process at the same time.
        can_advertise_and_scan: true,
        local_name_visible: true,
        service_uuid_in_primary_adv: true,
        wifi: &[WifiFlavour::Multipeer],
        // CoreBluetooth exposes no PHY selection of any kind. There is no
        // equivalent of Android's setPreferredPhy. An iOS device will use
        // Coded PHY only if the peer requests it and the iPhone's controller
        // accepts, which we cannot observe or control from the app.
        phy_selectable: Support::No,
        coded_phy: Support::Unknown,
        // UNVERIFIED: 185 is the ATT MTU iOS has negotiated for LE since iOS
        // 10 on most hardware; some devices report 527. We take the pessimistic
        // documented value and let the host correct it per link.
        expected_att_mtu: 185,
        scan_strength: 9,
        advertise_strength: 9,
        goodput_derate: 1.0,
        note: "iOS foreground: full dual role. The best iOS can be.",
    },
    // ---------------------------------------------------------------------
    Caps {
        platform: Platform::Ios,
        state: AppState::Background,
        // Requires the bluetooth-peripheral background mode. Advertising
        // continues, but see local_name_visible and
        // service_uuid_in_primary_adv below.
        can_advertise: true,
        // Requires bluetooth-central. Background scanning only works with an
        // explicit service-UUID filter, and the OS coalesces and throttles it;
        // callbacks arrive on the order of seconds to tens of seconds.
        can_scan: true,
        // THE constraint. A backgrounded iOS device cannot reliably advertise
        // and scan simultaneously: the OS schedules the two against each other
        // and neither gets a useful duty cycle. Two backgrounded iPhones in
        // each other's pockets may never find one another at all. Every policy
        // in this crate that assumes symmetric discovery is wrong because of
        // this one `false`.
        can_advertise_and_scan: false,
        // A backgrounded iOS peripheral publishes no CBAdvertisementDataLocalNameKey.
        local_name_visible: false,
        // In the background the service UUID moves to the vendor-specific
        // "overflow" area. It is only matched by a scanner that names that
        // exact UUID in its scan filter — it does not appear in a generic scan.
        // Consequence: our scan filter is mandatory, not an optimisation.
        service_uuid_in_primary_adv: false,
        // MultipeerConnectivity does not run in the background. No exceptions,
        // no background mode, no entitlement. A backgrounded iPhone has BLE
        // and nothing else.
        wifi: &[],
        phy_selectable: Support::No,
        coded_phy: Support::Unknown,
        // UNVERIFIED: background MTU negotiation is not documented to differ
        // from foreground, and we have no reason to think it does.
        expected_att_mtu: 185,
        // Deliberately asymmetric: a backgrounded iPhone is a far better
        // beacon than it is a scanner, so role election should make it the
        // peripheral and let the peer do the finding.
        scan_strength: 2,
        advertise_strength: 4,
        // UNVERIFIED: background connection intervals are stretched hard by
        // iOS. 0.15 is a placeholder for a measured derate.
        goodput_derate: 0.15,
        note: "iOS background: BLE only, no concurrent adv+scan, no local name, \
               no Wi-Fi. The weakest relay in the network and the reason this \
               table exists.",
    },
    // ---------------------------------------------------------------------
    Caps {
        platform: Platform::Android,
        state: AppState::Foreground,
        can_advertise: true,
        can_scan: true,
        can_advertise_and_scan: true,
        local_name_visible: true,
        service_uuid_in_primary_adv: true,
        // UNVERIFIED per device: Wi-Fi Aware needs FEATURE_WIFI_AWARE, which
        // a large minority of shipped Android hardware does not have. The host
        // narrows this list at startup.
        wifi: &[WifiFlavour::WifiAware, WifiFlavour::WifiDirect],
        // setPreferredPhy exists from API 26.
        phy_selectable: Support::Yes,
        // isLeCodedPhySupported() is per-controller. Unknown until the host
        // answers, and unknown means "no" to policy.
        coded_phy: Support::Unknown,
        // UNVERIFIED: Android requests 517 and commonly settles at 247 on the
        // peer's terms. 247 is the conservative planning number.
        expected_att_mtu: 247,
        scan_strength: 10,
        advertise_strength: 10,
        goodput_derate: 1.0,
        note: "Android foreground: everything available. The reference case.",
    },
    // ---------------------------------------------------------------------
    Caps {
        platform: Platform::Android,
        state: AppState::Background,
        can_advertise: true,
        can_scan: true,
        // With a foreground service holding the connection, Android keeps
        // doing both. This single `true` against iOS's `false` on the same row
        // is the whole pocket-relay asymmetry.
        can_advertise_and_scan: true,
        local_name_visible: true,
        service_uuid_in_primary_adv: true,
        // Wi-Fi Direct / Aware can technically be driven from a foreground
        // service, but it is expensive, it fights the station interface, and
        // we have never measured it.
        // UNVERIFIED: left empty so that the default policy never brings a
        // Wi-Fi radio up behind the user's back. Enable via LocalCaps once
        // measured.
        wifi: &[],
        phy_selectable: Support::Yes,
        coded_phy: Support::Unknown,
        expected_att_mtu: 247,
        // Scan throttling applies to unfiltered background scans (roughly 5
        // starts per 30 s window per app since Android 7), so we scan filtered
        // and long rather than often and short. Still a far better scanner
        // than a backgrounded iPhone.
        scan_strength: 7,
        advertise_strength: 8,
        // UNVERIFIED: Doze and the OS's own connection-interval choices.
        goodput_derate: 0.45,
        note: "Android background: still a dual-role relay. An Android in a \
               pocket carries the mesh; an iPhone in a pocket mostly beacons.",
    },
];

/// Look up a row. Total: the matrix covers the whole product of the two enums.
#[must_use]
pub fn caps(platform: Platform, state: AppState) -> &'static Caps {
    // A linear scan over four entries, rather than an index computation, so
    // that adding a platform cannot silently produce a wrong row.
    MATRIX
        .iter()
        .find(|c| c.platform == platform && c.state == state)
        .unwrap_or(&MATRIX[1]) // unreachable; iOS-background is the safe default
}

/// What the native shell reports about *this* handset at startup.
///
/// This can only narrow a [`Caps`] row, never widen it. The shell is allowed to
/// be wrong in the pessimistic direction and the stack still works.
#[derive(Clone, Debug)]
pub struct LocalCaps {
    pub platform: Platform,
    /// Flavours this device actually has, after checking
    /// `FEATURE_WIFI_AWARE` / `FEATURE_WIFI_DIRECT` or the iOS equivalent.
    pub wifi: Vec<WifiFlavour>,
    /// Result of `isLeCodedPhySupported()`, or [`Support::No`] on iOS.
    pub coded_phy: Support,
    /// Largest ATT MTU this device will request.
    pub max_att_mtu: u16,
}

impl Caps {
    /// Intersect the platform row with device truth.
    #[must_use]
    pub fn narrow(&self, local: &LocalCaps) -> Caps {
        let mut out = *self;
        // A flavour survives only if it is in both the platform row and the
        // device's list. `wifi` has to stay `&'static` for the table, so the
        // narrowed set is recomputed into the same static slices where possible
        // and emptied otherwise; callers that need the exact set use
        // `wifi_intersection`.
        out.coded_phy = self.coded_phy.and(local.coded_phy);
        out.expected_att_mtu = self.expected_att_mtu.min(local.max_att_mtu).max(ATT_MTU_FLOOR);
        if !self.wifi.iter().any(|f| local.wifi.contains(f)) {
            out.wifi = &[];
        }
        out
    }

    /// Flavours available after narrowing, best first.
    #[must_use]
    pub fn wifi_intersection(&self, local: &LocalCaps) -> Vec<WifiFlavour> {
        let mut v: Vec<WifiFlavour> = self
            .wifi
            .iter()
            .copied()
            .filter(|f| local.wifi.contains(f))
            .collect();
        v.sort_by_key(|f| f.rank());
        v
    }

    /// Usable datagram payload in bytes, given the ATT MTU actually negotiated.
    #[must_use]
    pub fn datagram_payload(att_mtu: u16) -> u16 {
        att_mtu.max(ATT_MTU_FLOOR).saturating_sub(ATT_OVERHEAD)
    }
}

/// The three platform pairs `docs/METRICS.md` requires every number to be split
/// by. Unordered: a link between an iPhone and an Android is the same pair
/// whichever end is reporting.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum PairKind {
    IosIos,
    AndroidAndroid,
    /// The mixed pair. The one that matters and the one everybody else is worst
    /// at. Note that it can never carry a Wi-Fi burst.
    IosAndroid,
}

impl PairKind {
    #[must_use]
    pub fn of(a: Platform, b: Platform) -> PairKind {
        match (a, b) {
            (Platform::Ios, Platform::Ios) => PairKind::IosIos,
            (Platform::Android, Platform::Android) => PairKind::AndroidAndroid,
            _ => PairKind::IosAndroid,
        }
    }

    /// Whether any infra-free high-throughput path can exist for this pair, in
    /// any app state, on any hardware. For the mixed pair the answer is a flat
    /// no and it is a platform fact, not a tuning decision.
    #[must_use]
    pub fn wifi_possible(self) -> bool {
        !matches!(self, PairKind::IosAndroid)
    }
}

impl fmt::Display for PairKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PairKind::IosIos => "iOS-iOS",
            PairKind::AndroidAndroid => "Android-Android",
            PairKind::IosAndroid => "iOS-Android",
        })
    }
}

/// Both ends' app states, as a single key. `docs/METRICS.md` wants a
/// foreground/background split; for a link there are three meaningful classes
/// and the mixed one behaves quite differently from either extreme.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum StatePair {
    BothForeground,
    /// One end foreground, one end background. The realistic relay case: a
    /// person using the app next to a pocketed phone.
    Mixed,
    /// Both backgrounded. The case M2 insists on measuring and the case the
    /// iOS row above makes nearly impossible for an iOS-iOS pair.
    BothBackground,
}

impl StatePair {
    #[must_use]
    pub fn of(a: AppState, b: AppState) -> StatePair {
        match (a, b) {
            (AppState::Foreground, AppState::Foreground) => StatePair::BothForeground,
            (AppState::Background, AppState::Background) => StatePair::BothBackground,
            _ => StatePair::Mixed,
        }
    }
}

/// The best Wi-Fi flavour two ends share, or `None`.
///
/// This is the function that encodes "there is no infra-free high-throughput
/// iOS-to-Android path". It returns `None` for that pair not because of a check
/// against platforms but because the flavour sets are disjoint.
#[must_use]
pub fn shared_wifi(a: &Caps, b: &Caps) -> Option<WifiFlavour> {
    let mut best: Option<WifiFlavour> = None;
    for f in a.wifi {
        if b.wifi.contains(f) && best.is_none_or(|cur| f.rank() < cur.rank()) {
            best = Some(*f);
        }
    }
    best
}

/// Which end should take the BLE central role.
///
/// Returns `true` if the *local* end should be central. Decided by scanning
/// strength from the matrix, because the end that is better at finding should
/// do the finding. Ties break on a per-session random nonce — never on a
/// device address, a name or anything else stable, per hard rule 6.
#[must_use]
pub fn local_should_be_central(
    local: &Caps,
    remote: &Caps,
    local_nonce: u64,
    remote_nonce: u64,
) -> bool {
    // A peer that cannot scan at all must be the peripheral regardless of score.
    if !remote.can_scan {
        return true;
    }
    if !local.can_scan {
        return false;
    }
    match local.scan_strength.cmp(&remote.scan_strength) {
        core::cmp::Ordering::Greater => true,
        core::cmp::Ordering::Less => false,
        // Equal strength: deterministic from the two nonces, so both ends reach
        // the same answer without another round trip.
        core::cmp::Ordering::Equal => local_nonce > remote_nonce,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_covers_every_platform_and_state() {
        for p in [Platform::Ios, Platform::Android] {
            for s in [AppState::Foreground, AppState::Background] {
                let c = caps(p, s);
                assert_eq!(c.platform, p);
                assert_eq!(c.state, s);
            }
        }
    }

    #[test]
    fn backgrounded_ios_cannot_advertise_and_scan_at_once() {
        // The fact the whole design turns on. If this assertion is ever
        // "fixed" to true, re-read the CoreBluetooth background documentation
        // before believing it.
        let ios_bg = caps(Platform::Ios, AppState::Background);
        assert!(!ios_bg.can_advertise_and_scan);
        assert!(!ios_bg.local_name_visible);
        assert!(ios_bg.wifi.is_empty());

        let android_bg = caps(Platform::Android, AppState::Background);
        assert!(android_bg.can_advertise_and_scan, "the asymmetry");
    }

    #[test]
    fn no_infra_free_wifi_between_ios_and_android() {
        // Every combination of app states, both directions. There is no
        // configuration in which this pair gets a Wi-Fi burst.
        for ios_state in [AppState::Foreground, AppState::Background] {
            for android_state in [AppState::Foreground, AppState::Background] {
                let i = caps(Platform::Ios, ios_state);
                let a = caps(Platform::Android, android_state);
                assert_eq!(shared_wifi(i, a), None);
                assert_eq!(shared_wifi(a, i), None);
            }
        }
        assert!(!PairKind::IosAndroid.wifi_possible());
    }

    #[test]
    fn two_foreground_androids_share_a_flavour() {
        let a = caps(Platform::Android, AppState::Foreground);
        assert_eq!(shared_wifi(a, a), Some(WifiFlavour::WifiAware));
    }

    #[test]
    fn backgrounded_android_offers_no_wifi_by_default() {
        let fg = caps(Platform::Android, AppState::Foreground);
        let bg = caps(Platform::Android, AppState::Background);
        assert_eq!(shared_wifi(fg, bg), None);
    }

    #[test]
    fn unknown_support_is_not_permission() {
        assert!(!Support::Unknown.is_usable());
        assert!(!Support::No.is_usable());
        assert!(Support::Yes.is_usable());
    }

    #[test]
    fn narrowing_cannot_widen() {
        let android = caps(Platform::Android, AppState::Foreground);
        let local = LocalCaps {
            platform: Platform::Android,
            // No Aware on this handset.
            wifi: vec![WifiFlavour::WifiDirect],
            coded_phy: Support::Yes,
            max_att_mtu: 517,
        };
        let n = android.narrow(&local);
        assert_eq!(n.coded_phy, Support::Yes);
        // The narrowed MTU is the min of the platform prior and the device max,
        // never the device max alone.
        assert_eq!(n.expected_att_mtu, 247);
        assert_eq!(android.wifi_intersection(&local), vec![WifiFlavour::WifiDirect]);

        // And a device claiming Coded PHY on iOS still cannot select a PHY.
        let ios = caps(Platform::Ios, AppState::Foreground);
        let lying_host = LocalCaps {
            platform: Platform::Ios,
            wifi: vec![WifiFlavour::Multipeer],
            coded_phy: Support::Yes,
            max_att_mtu: 527,
        };
        assert_eq!(ios.narrow(&lying_host).phy_selectable, Support::No);
    }

    #[test]
    fn datagram_payload_at_the_floor_is_twenty() {
        assert_eq!(Caps::datagram_payload(ATT_MTU_FLOOR), 20);
        // And a host reporting nonsense below the spec floor is clamped up
        // rather than underflowing.
        assert_eq!(Caps::datagram_payload(0), 20);
        assert_eq!(Caps::datagram_payload(247), 244);
    }

    #[test]
    fn the_better_scanner_becomes_central() {
        let ios_bg = caps(Platform::Ios, AppState::Background);
        let android_bg = caps(Platform::Android, AppState::Background);
        // Android background (7) beats iOS background (2): Android does the
        // finding, the pocketed iPhone just beacons.
        assert!(local_should_be_central(android_bg, ios_bg, 0, u64::MAX));
        assert!(!local_should_be_central(ios_bg, android_bg, u64::MAX, 0));
    }

    #[test]
    fn role_ties_break_on_the_nonce_not_on_identity() {
        let a = caps(Platform::Android, AppState::Foreground);
        assert!(local_should_be_central(a, a, 9, 4));
        assert!(!local_should_be_central(a, a, 4, 9));
        // Both ends must agree.
        assert_ne!(
            local_should_be_central(a, a, 9, 4),
            local_should_be_central(a, a, 4, 9)
        );
    }
}
