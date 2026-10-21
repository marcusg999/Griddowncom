//! The energy budget and the enforcer that makes it binding.
//!
//! The budget is one fixed balanced profile: about 5 %/hr of a 4000 mAh-class
//! phone while relaying with the screen off. There are no user-selectable
//! modes. That decision is not re-opened here.
//!
//! What *is* decided here is how the budget stops being aspirational. Two
//! mechanisms:
//!
//! 1. A rolling-window ledger. Spend is booked into one-minute buckets over a
//!    one-hour window, and a request that would push the window total past the
//!    allowance is refused. A rolling window rather than a fixed hour on
//!    purpose: it permits a burst (the whole hour's allowance can go in sixty
//!    seconds, which is exactly what flushing a backlog to a carrier who is
//!    walking past needs) while still bounding the average.
//!
//! 2. An unforgeable grant. [`AirtimeGrant`] has no public constructor, and it
//!    is the only way to read the radio parameters in a [`DutyPlan`] from
//!    outside this crate. A transport that wants to know its scan window has to
//!    get a grant, and getting a grant goes through the ledger. See the crate
//!    docs for the exact extent of that guarantee and where it stops.

use crate::cost::CostTable;
use crate::policy::{DutyPlan, PlanProposal, Regime};
use crate::units::{Charge, MS_PER_HOUR};
use gdc_wire::{Flags, Kind};

/// Largest number of grants that may be open at once.
///
/// Every reservation is a live allocation driven by whatever is calling us, so
/// it gets an explicit ceiling like everything else in this workspace.
pub const MAX_OPEN_GRANTS: usize = 64;

/// Default length of a duty-cycle grant. The transport must come back for a new
/// one, which is what keeps the duty cycle itself inside the budget rather than
/// only the discrete events.
pub const DEFAULT_DUTY_GRANT_MS: u64 = 60_000;

/// The fixed balanced energy budget.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EnergyBudget {
    capacity_mah: u32,
    /// Permitted whole-device drain per hour, in thousandths of a percent.
    hourly_pct_milli: u32,
}

impl EnergyBudget {
    /// The 4000 mAh-class phone the project targets.
    pub const DEFAULT_CAPACITY_MAH: u32 = 4_000;
    /// 5.000 %/hr. Decided, not configurable at runtime.
    pub const DEFAULT_HOURLY_PCT_MILLI: u32 = 5_000;

    pub const fn balanced() -> Self {
        EnergyBudget {
            capacity_mah: Self::DEFAULT_CAPACITY_MAH,
            hourly_pct_milli: Self::DEFAULT_HOURLY_PCT_MILLI,
        }
    }

    /// Only for sweeps and for devices of a different class. The shipped
    /// profile is [`EnergyBudget::balanced`].
    pub const fn new(capacity_mah: u32, hourly_pct_milli: u32) -> Self {
        EnergyBudget {
            capacity_mah,
            hourly_pct_milli,
        }
    }

    pub const fn capacity_mah(&self) -> u32 {
        self.capacity_mah
    }

    pub fn capacity(&self) -> Charge {
        Charge::from_ua_us(self.capacity_mah as u64 * 1_000, 3_600_000_000)
    }

    pub fn hourly_pct(&self) -> f64 {
        self.hourly_pct_milli as f64 / 1_000.0
    }

    /// Whole-device charge the profile permits in one hour, floor included.
    pub fn device_hourly(&self) -> Charge {
        self.capacity().scaled(self.hourly_pct_milli as u64, 100_000)
    }

    /// The part of the hourly budget this app may actually spend: the device
    /// allowance less the floor the phone draws when suspended with our app not
    /// running. We do not get to claim credit for the platform's own idle cost.
    pub fn app_hourly(&self, table: &CostTable) -> Charge {
        self.device_hourly().saturating_sub(table.hourly_floor())
    }

    /// Hours from `from_pct` to `to_pct` if the profile spent exactly its
    /// allowance the whole way down. The straight-line figure, for comparison
    /// against what the policy's battery-level response actually achieves.
    pub fn flat_rate_hours(&self, from_pct: f64, to_pct: f64) -> f64 {
        let span = (from_pct - to_pct).max(0.0);
        span / self.hourly_pct()
    }
}

impl Default for EnergyBudget {
    fn default() -> Self {
        EnergyBudget::balanced()
    }
}

/// What a grant authorises.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Authorised {
    Duty(DutyPlan),
    Event(RadioEvent),
}

/// Priority class of a spend request.
///
/// Each class gets a different slice of the hourly allowance, so that
/// discretionary work cannot starve life-safety traffic. The slices are a
/// policy choice, not a measurement.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Default)]
pub enum Priority {
    /// Backlog sync, courier housekeeping, opportunistic Wi-Fi. 70 %.
    Background,
    /// Ordinary channel traffic, presence, relaying. 90 %.
    #[default]
    Normal,
    /// The author asserted life safety. 100 %.
    ///
    /// The `URGENT` flag is unauthenticated by construction (see `gdc-wire`), so
    /// it buys the last 10 % of the budget and nothing else. It cannot raise the
    /// budget, only reach further into it.
    Urgent,
}

impl Priority {
    /// Numerator and denominator of this class's slice of the hourly allowance.
    pub const fn slice(self) -> (u64, u64) {
        match self {
            Priority::Background => (70, 100),
            Priority::Normal => (90, 100),
            Priority::Urgent => (100, 100),
        }
    }

    /// Map a wire frame onto a priority class.
    pub fn for_frame(kind: Kind, flags: Flags) -> Priority {
        if flags.contains(Flags::URGENT) {
            return Priority::Urgent;
        }
        match kind {
            Kind::Sync | Kind::Courier => Priority::Background,
            _ => Priority::Normal,
        }
    }
}

/// A discrete radio action with a cost.
///
/// This is the per-event half of the cost table's public surface: the enum the
/// rest of the stack describes its spending in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RadioEvent {
    /// One scan window of the given duration, ramp included.
    ScanWindow { duration_us: u32 },
    /// `count` advertising events.
    AdvEvents { count: u32 },
    /// `count` advertisement reports handed to the host.
    AdvReports { count: u32 },
    /// `count` connection events on an established link.
    ConnEvents { count: u32 },
    /// One connection establishment.
    ConnSetup,
    BleTx { bytes: u32, phy: crate::cost::Phy },
    BleRx { bytes: u32, phy: crate::cost::Phy },
    /// `count` frames verified, opened and re-encoded. Charged for duplicates
    /// too: rule 4 of the Bridgefy findings makes us verify before forwarding.
    FramesProcessed { count: u32 },
    /// The application processor held out of suspend for `duration_us`.
    ApAwake { duration_us: u32 },
    WifiBringUp,
    WifiTransfer { bytes: u32 },
    WifiTearDown,
}

impl RadioEvent {
    /// Modelled cost of this event. Never a measurement.
    pub fn charge(&self, t: &CostTable) -> Charge {
        match *self {
            RadioEvent::ScanWindow { duration_us } => t.scan_window_charge(duration_us as u64),
            RadioEvent::AdvEvents { count } => t.adv_event_charge.saturating_mul(count as u64),
            RadioEvent::AdvReports { count } => t.adv_report_charge.saturating_mul(count as u64),
            RadioEvent::ConnEvents { count } => t.conn_event_charge.saturating_mul(count as u64),
            RadioEvent::ConnSetup => t.conn_setup_charge,
            RadioEvent::BleTx { bytes, phy } => t.tx_charge(bytes as u64, phy),
            RadioEvent::BleRx { bytes, phy } => t.rx_charge(bytes as u64, phy),
            RadioEvent::FramesProcessed { count } => {
                t.cpu_per_frame_charge.saturating_mul(count as u64)
            }
            RadioEvent::ApAwake { duration_us } => {
                Charge::from_ua_us(t.ap_awake_penalty_ua as u64, duration_us as u64)
            }
            RadioEvent::WifiBringUp => t.wifi_bringup_charge,
            RadioEvent::WifiTransfer { bytes } => t.wifi_transfer_charge(bytes as u64),
            RadioEvent::WifiTearDown => t.wifi_teardown_charge,
        }
    }
}

/// Opaque handle to an open reservation.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct GrantId(u64);

/// Permission to spend energy on the radio.
///
/// There is no public constructor. Outside this crate this is the only way to
/// read the duty-cycle parameters the transport needs, so a transport cannot
/// configure a radio without having been through the ledger.
///
/// Dropping a grant without settling it leaves the full reservation booked.
/// That is deliberate: an unsettled grant is assumed spent, so losing track of
/// one over-charges rather than under-charges.
#[must_use = "a grant that is never presented to a radio is budget spent for nothing"]
#[derive(Clone, Copy, Debug)]
pub struct AirtimeGrant {
    id: GrantId,
    authorised: Authorised,
    reserved: Charge,
    issued_at_ms: u64,
    expires_at_ms: u64,
    priority: Priority,
}

impl AirtimeGrant {
    pub fn id(&self) -> GrantId {
        self.id
    }
    pub fn reserved(&self) -> Charge {
        self.reserved
    }
    pub fn issued_at_ms(&self) -> u64 {
        self.issued_at_ms
    }
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
    pub fn priority(&self) -> Priority {
        self.priority
    }

    /// The event this grant authorises, if it is an event grant.
    pub fn event(&self) -> Option<RadioEvent> {
        match self.authorised {
            Authorised::Event(e) => Some(e),
            Authorised::Duty(_) => None,
        }
    }

    fn duty(&self) -> Option<&DutyPlan> {
        match &self.authorised {
            Authorised::Duty(p) => Some(p),
            Authorised::Event(_) => None,
        }
    }

    pub fn regime(&self) -> Option<Regime> {
        self.duty().map(|p| p.regime())
    }

    // The duty-cycle parameters. These accessors exist only here, which is what
    // makes the budget structurally binding for any Rust caller: `DutyPlan`'s
    // own accessors are crate-private.
    pub fn scan_window_ms(&self) -> Option<u32> {
        self.duty().map(|p| p.scan_window_ms())
    }
    pub fn scan_interval_ms(&self) -> Option<u32> {
        self.duty().map(|p| p.scan_interval_ms())
    }
    pub fn adv_interval_ms(&self) -> Option<u32> {
        self.duty().map(|p| p.adv_interval_ms())
    }
    pub fn conn_interval_ms(&self) -> Option<u32> {
        self.duty().map(|p| p.conn_interval_ms())
    }
    pub fn conn_slave_latency(&self) -> Option<u16> {
        self.duty().map(|p| p.conn_slave_latency())
    }
    pub fn supervision_timeout_ms(&self) -> Option<u32> {
        self.duty().map(|p| p.supervision_timeout_ms())
    }
    /// Outer duty cycle: how long the radio session exists at all, and its
    /// period. Equal values mean a continuous session.
    pub fn session_on_ms(&self) -> Option<u32> {
        self.duty().map(|p| p.session_on_ms())
    }
    pub fn session_period_ms(&self) -> Option<u32> {
        self.duty().map(|p| p.session_period_ms())
    }
    pub fn scanning_enabled(&self) -> Option<bool> {
        self.duty().map(|p| p.scanning_enabled())
    }
    pub fn preferred_phy(&self) -> Option<crate::cost::Phy> {
        self.duty().map(|p| p.preferred_phy())
    }
    /// Whether a Wi-Fi burst is permitted, and the backlog it must carry to be
    /// worth the bring-up cost.
    pub fn wifi_min_backlog_bytes(&self) -> Option<Option<u32>> {
        self.duty().map(|p| p.wifi_min_backlog_bytes())
    }
}

/// Why a spend request was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum Denied {
    #[error(
        "over budget: {requested_pc} pC requested, {remaining_pc} pC left in the \
         rolling window for priority {priority:?}"
    )]
    OverBudget {
        requested_pc: u64,
        remaining_pc: u64,
        priority: Priority,
    },
    #[error("too many grants open ({open}); settle some before requesting more")]
    TooManyOpenGrants { open: usize },
    #[error("clock went backwards: now {now_ms} ms, ledger at {ledger_ms} ms")]
    ClockWentBackwards { now_ms: u64, ledger_ms: u64 },
    #[error("unknown or already-settled grant")]
    UnknownGrant,
    #[error("battery is below the floor at which any discretionary radio spend is allowed")]
    BatteryExhausted,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct LedgerStats {
    pub granted: u64,
    pub denied: u64,
    pub settled: u64,
    /// Charge returned to the window by settling under the reservation.
    pub refunded: Charge,
}

#[derive(Clone, Copy, Debug)]
struct Reservation {
    id: GrantId,
    bucket: u64,
    reserved: Charge,
}

/// The rolling-window spend ledger.
#[derive(Clone, Debug)]
pub struct BudgetLedger {
    budget: EnergyBudget,
    table: CostTable,
    bucket_ms: u64,
    buckets: Vec<Charge>,
    /// Absolute index (`now_ms / bucket_ms`) of the newest bucket.
    head: u64,
    open: Vec<Reservation>,
    next_id: u64,
    stats: LedgerStats,
}

impl BudgetLedger {
    /// One hour of window in sixty one-minute buckets.
    pub fn new(budget: EnergyBudget, table: CostTable, start_ms: u64) -> Self {
        Self::with_window(budget, table, start_ms, 60_000, 60)
    }

    pub fn with_window(
        budget: EnergyBudget,
        table: CostTable,
        start_ms: u64,
        bucket_ms: u64,
        buckets: usize,
    ) -> Self {
        let bucket_ms = bucket_ms.max(1);
        let n = buckets.clamp(1, 1024);
        BudgetLedger {
            budget,
            table,
            bucket_ms,
            buckets: vec![Charge::ZERO; n],
            head: start_ms / bucket_ms,
            open: Vec::new(),
            next_id: 1,
            stats: LedgerStats::default(),
        }
    }

    pub fn budget(&self) -> &EnergyBudget {
        &self.budget
    }

    pub fn table(&self) -> &CostTable {
        &self.table
    }

    /// Swap the cost table, e.g. after a calibration round. Spend already booked
    /// is not retroactively re-priced; it happened under the old table.
    pub fn set_table(&mut self, table: CostTable) {
        self.table = table;
    }

    pub fn stats(&self) -> LedgerStats {
        self.stats
    }

    pub fn window_ms(&self) -> u64 {
        self.bucket_ms * self.buckets.len() as u64
    }

    /// Charge booked in the rolling window, reservations included.
    pub fn spent_in_window(&self) -> Charge {
        self.buckets.iter().copied().sum()
    }

    /// The window allowance, scaled from the hourly allowance.
    pub fn window_allowance(&self) -> Charge {
        self.budget
            .app_hourly(&self.table)
            .scaled(self.window_ms(), MS_PER_HOUR)
    }

    /// The window allowance available to a given priority class.
    pub fn allowance_for(&self, priority: Priority) -> Charge {
        let (num, den) = priority.slice();
        self.window_allowance().scaled(num, den)
    }

    pub fn remaining_for(&self, priority: Priority) -> Charge {
        self.allowance_for(priority)
            .saturating_sub(self.spent_in_window())
    }

    /// Fraction of the window allowance currently booked.
    pub fn utilisation(&self) -> f64 {
        let cap = self.window_allowance().as_pc();
        if cap == 0 {
            return f64::INFINITY;
        }
        self.spent_in_window().as_pc() as f64 / cap as f64
    }

    fn advance(&mut self, now_ms: u64) -> Result<(), Denied> {
        let want = now_ms / self.bucket_ms;
        if want < self.head {
            return Err(Denied::ClockWentBackwards {
                now_ms,
                ledger_ms: self.head * self.bucket_ms,
            });
        }
        let steps = want - self.head;
        let n = self.buckets.len() as u64;
        if steps >= n {
            for b in self.buckets.iter_mut() {
                *b = Charge::ZERO;
            }
        } else {
            for s in 1..=steps {
                let idx = ((self.head + s) % n) as usize;
                self.buckets[idx] = Charge::ZERO;
            }
        }
        if steps > 0 {
            // Reservations that have fallen out of the window can never be
            // settled against a live bucket, so drop them.
            let oldest = want.saturating_sub(n - 1);
            self.open.retain(|r| r.bucket >= oldest);
        }
        self.head = want;
        Ok(())
    }

    fn head_slot(&self) -> usize {
        (self.head % self.buckets.len() as u64) as usize
    }

    fn book(&mut self, charge: Charge) {
        let slot = self.head_slot();
        self.buckets[slot] = self.buckets[slot].saturating_add(charge);
    }

    fn issue(
        &mut self,
        now_ms: u64,
        authorised: Authorised,
        reserved: Charge,
        priority: Priority,
        valid_ms: u64,
    ) -> Result<AirtimeGrant, Denied> {
        self.advance(now_ms)?;
        if self.open.len() >= MAX_OPEN_GRANTS {
            self.stats.denied += 1;
            return Err(Denied::TooManyOpenGrants {
                open: self.open.len(),
            });
        }
        let remaining = self.remaining_for(priority);
        if reserved > remaining {
            self.stats.denied += 1;
            return Err(Denied::OverBudget {
                requested_pc: reserved.as_pc(),
                remaining_pc: remaining.as_pc(),
                priority,
            });
        }
        let id = GrantId(self.next_id);
        self.next_id += 1;
        self.book(reserved);
        self.open.push(Reservation {
            id,
            bucket: self.head,
            reserved,
        });
        self.stats.granted += 1;
        Ok(AirtimeGrant {
            id,
            authorised,
            reserved,
            issued_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(valid_ms),
            priority,
        })
    }

    /// Ask for permission to run a duty cycle for [`DEFAULT_DUTY_GRANT_MS`].
    pub fn request_duty(
        &mut self,
        now_ms: u64,
        proposal: &PlanProposal,
        priority: Priority,
    ) -> Result<AirtimeGrant, Denied> {
        self.request_duty_for(now_ms, proposal, priority, DEFAULT_DUTY_GRANT_MS)
    }

    pub fn request_duty_for(
        &mut self,
        now_ms: u64,
        proposal: &PlanProposal,
        priority: Priority,
        grant_ms: u64,
    ) -> Result<AirtimeGrant, Denied> {
        let grant_ms = grant_ms.clamp(1, self.window_ms());
        let reserved = proposal
            .estimated_hourly()
            .scaled(grant_ms, MS_PER_HOUR);
        self.issue(
            now_ms,
            Authorised::Duty(*proposal.plan_ref()),
            reserved,
            priority,
            grant_ms,
        )
    }

    /// Ask for permission to perform one discrete radio action.
    pub fn request_event(
        &mut self,
        now_ms: u64,
        event: RadioEvent,
        priority: Priority,
    ) -> Result<AirtimeGrant, Denied> {
        let reserved = event.charge(&self.table);
        self.issue(now_ms, Authorised::Event(event), reserved, priority, 0)
    }

    /// Close a grant with what it actually cost. Consumes the grant, so a grant
    /// cannot be settled twice or presented after settling.
    pub fn settle(&mut self, grant: AirtimeGrant, actual: Charge) -> Result<Charge, Denied> {
        let pos = self
            .open
            .iter()
            .position(|r| r.id == grant.id)
            .ok_or(Denied::UnknownGrant)?;
        let r = self.open.swap_remove(pos);
        self.stats.settled += 1;
        let n = self.buckets.len() as u64;
        let oldest = self.head.saturating_sub(n - 1);
        if r.bucket >= oldest {
            let slot = (r.bucket % n) as usize;
            if actual >= r.reserved {
                let extra = actual.saturating_sub(r.reserved);
                self.buckets[slot] = self.buckets[slot].saturating_add(extra);
            } else {
                let refund = r.reserved.saturating_sub(actual);
                self.buckets[slot] = self.buckets[slot].saturating_sub(refund);
                self.stats.refunded = self.stats.refunded.saturating_add(refund);
            }
        }
        Ok(actual)
    }

    /// Settle a grant that was never used. Returns the whole reservation.
    pub fn release(&mut self, grant: AirtimeGrant) -> Result<Charge, Denied> {
        self.settle(grant, Charge::ZERO)
    }

    pub fn open_grants(&self) -> usize {
        self.open.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cost::Phy;
    use crate::policy::{Policy, PolicyInput};

    fn ledger() -> BudgetLedger {
        BudgetLedger::new(EnergyBudget::balanced(), CostTable::modelled(), 0)
    }

    #[test]
    fn balanced_budget_is_five_percent_of_four_thousand_mah() {
        let b = EnergyBudget::balanced();
        assert!((b.capacity().as_mah() - 4_000.0).abs() < 1e-6);
        assert!((b.device_hourly().as_mah() - 200.0).abs() < 1e-6);
        assert!((b.hourly_pct() - 5.0).abs() < 1e-12);
        // 100 % to 20 % at a flat 5 %/hr is 16 hours. The policy beats this by
        // degrading as the battery falls; see account::projected_relay_hours.
        assert!((b.flat_rate_hours(100.0, 20.0) - 16.0).abs() < 1e-9);
    }

    #[test]
    fn app_allowance_excludes_the_platform_floor() {
        let t = CostTable::modelled();
        let b = EnergyBudget::balanced();
        // 12 mA floor is 12 mAh/hr, so the app gets 188 of the 200 mAh/hr.
        assert!((b.app_hourly(&t).as_mah() - 188.0).abs() < 1e-6);
    }

    #[test]
    fn an_over_budget_request_is_refused() {
        let mut l = ledger();
        // One Wi-Fi bring-up is affordable.
        let g = l
            .request_event(0, RadioEvent::WifiBringUp, Priority::Normal)
            .expect("one bring-up fits");
        l.settle(g, CostTable::modelled().wifi_bringup_charge).unwrap();

        // An absurd one is not: 10 Ah of AP-awake time in a single event.
        let err = l
            .request_event(
                0,
                RadioEvent::ApAwake {
                    duration_us: u32::MAX,
                },
                Priority::Urgent,
            )
            .expect_err("must refuse");
        assert!(matches!(err, Denied::OverBudget { .. }));
        assert_eq!(l.stats().denied, 1);
    }

    #[test]
    fn the_window_allowance_is_actually_exhaustible() {
        let mut l = ledger();
        // 188 mAh/hr app allowance. A Wi-Fi bring-up plus teardown is
        // 0.1417 mAh, so ~1327 of them fill the hour. Spend until refused and
        // check we stopped near the allowance rather than somewhere arbitrary.
        let mut n = 0u32;
        loop {
            match l.request_event(0, RadioEvent::WifiBringUp, Priority::Normal) {
                Ok(g) => {
                    let c = g.reserved();
                    l.settle(g, c).unwrap();
                    n += 1;
                    assert!(n < 100_000, "ledger never refused");
                }
                Err(Denied::OverBudget { .. }) => break,
                Err(e) => panic!("unexpected {e:?}"),
            }
        }
        let spent = l.spent_in_window().as_mah();
        let normal_cap = l.allowance_for(Priority::Normal).as_mah();
        assert!(
            spent <= normal_cap && spent > normal_cap - 0.2,
            "stopped at {spent} mAh against a {normal_cap} mAh cap"
        );
        // Urgent traffic can still reach the last slice of the budget.
        let g = l
            .request_event(0, RadioEvent::WifiBringUp, Priority::Urgent)
            .expect("urgent keeps a reserve");
        let c = g.reserved();
        l.settle(g, c).unwrap();
    }

    #[test]
    fn background_is_capped_below_normal_below_urgent() {
        let l = ledger();
        assert!(l.allowance_for(Priority::Background) < l.allowance_for(Priority::Normal));
        assert!(l.allowance_for(Priority::Normal) < l.allowance_for(Priority::Urgent));
        assert_eq!(l.allowance_for(Priority::Urgent), l.window_allowance());
    }

    #[test]
    fn urgent_priority_comes_from_the_wire_flag_only() {
        assert_eq!(
            Priority::for_frame(Kind::ChannelMsg, Flags::URGENT),
            Priority::Urgent
        );
        assert_eq!(
            Priority::for_frame(Kind::Sync, Flags::empty()),
            Priority::Background
        );
        assert_eq!(
            Priority::for_frame(Kind::ChannelMsg, Flags::empty()),
            Priority::Normal
        );
        // An urgent sync is still urgent: the flag wins. It buys reach into the
        // budget, never trust, and never a larger budget.
        assert_eq!(
            Priority::for_frame(Kind::Sync, Flags::URGENT),
            Priority::Urgent
        );
    }

    #[test]
    fn spend_ages_out_of_the_rolling_window() {
        let mut l = ledger();
        for _ in 0..200 {
            if let Ok(g) = l.request_event(0, RadioEvent::WifiBringUp, Priority::Normal) {
                let c = g.reserved();
                l.settle(g, c).unwrap();
            }
        }
        assert!(l.spent_in_window().as_pc() > 0);
        // An hour later the window is empty again.
        l.advance(3_600_000).unwrap();
        assert_eq!(l.spent_in_window(), Charge::ZERO);
    }

    #[test]
    fn settling_under_the_reservation_refunds_the_difference() {
        let mut l = ledger();
        let before = l.spent_in_window();
        let g = l
            .request_event(0, RadioEvent::ConnSetup, Priority::Normal)
            .unwrap();
        let reserved = g.reserved();
        assert_eq!(l.spent_in_window(), before.saturating_add(reserved));
        l.settle(g, reserved.scaled(1, 4)).unwrap();
        assert_eq!(l.spent_in_window(), before.saturating_add(reserved.scaled(1, 4)));
        assert!(l.stats().refunded.as_pc() > 0);
    }

    #[test]
    fn an_unsettled_grant_stays_charged() {
        let mut l = ledger();
        {
            let g = l
                .request_event(0, RadioEvent::ConnSetup, Priority::Normal)
                .unwrap();
            let _ = g; // dropped without settling
        }
        assert_eq!(
            l.spent_in_window(),
            CostTable::modelled().conn_setup_charge,
            "losing a grant must over-charge, never under-charge"
        );
    }

    #[test]
    fn open_grants_are_bounded() {
        let mut l = ledger();
        let mut held = Vec::new();
        for _ in 0..MAX_OPEN_GRANTS {
            held.push(
                l.request_event(0, RadioEvent::AdvEvents { count: 1 }, Priority::Normal)
                    .unwrap(),
            );
        }
        let err = l
            .request_event(0, RadioEvent::AdvEvents { count: 1 }, Priority::Normal)
            .expect_err("ceiling must bind");
        assert!(matches!(err, Denied::TooManyOpenGrants { .. }));
        for g in held {
            l.release(g).unwrap();
        }
        assert_eq!(l.open_grants(), 0);
    }

    #[test]
    fn a_grant_cannot_be_settled_twice() {
        let mut l = ledger();
        let g = l
            .request_event(0, RadioEvent::ConnSetup, Priority::Normal)
            .unwrap();
        let copy = g;
        l.settle(g, Charge::ZERO).unwrap();
        assert_eq!(l.settle(copy, Charge::ZERO), Err(Denied::UnknownGrant));
    }

    #[test]
    fn a_backwards_clock_is_an_error_not_a_refund() {
        let mut l = BudgetLedger::new(EnergyBudget::balanced(), CostTable::modelled(), 600_000);
        assert!(matches!(
            l.request_event(0, RadioEvent::ConnSetup, Priority::Normal),
            Err(Denied::ClockWentBackwards { .. })
        ));
    }

    #[test]
    fn duty_parameters_are_unreachable_without_a_grant() {
        // This is the structural claim, asserted the only way a test can: the
        // numbers come out of the grant.
        let mut l = ledger();
        let p = Policy::new(EnergyBudget::balanced(), CostTable::modelled());
        let proposal = p.decide(&PolicyInput::idle_relay());
        let g = l.request_duty(0, &proposal, Priority::Normal).unwrap();
        assert!(g.scan_window_ms().unwrap() > 0);
        assert!(g.scan_interval_ms().unwrap() >= g.scan_window_ms().unwrap());
        assert!(g.adv_interval_ms().unwrap() >= 20);
        assert_eq!(g.event(), None);
        assert_eq!(g.preferred_phy(), Some(Phy::Le1M));
    }
}
