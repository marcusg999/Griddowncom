//! Where every number came from.
//!
//! `docs/BRIEF.md` forbids reporting a simulated number as a measurement, and
//! `docs/METRICS.md` requires every simulated result to cite the calibration it
//! rests on. That is a data-structure problem, not a discipline problem: if the
//! provenance travels with the parameter and is serialised next to the result,
//! an uncalibrated figure cannot be quoted as a field one by accident.

use serde::{Deserialize, Serialize};

/// Why a parameter has the value it has.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ParamSource {
    /// Taken from a published specification. `cite` names it precisely enough
    /// to check.
    Spec { cite: String },
    /// Taken from published measurement or vendor documentation.
    Literature { cite: String },
    /// Our guess. The string says what the guess is based on, so a reviewer can
    /// attack it. Most of this file is this variant and that is the honest
    /// state of the model before any field round.
    Assumed { rationale: String },
    /// Fitted against a field CSV in calibration round `round`.
    Fitted { round: u32, residual_db: String },
}

impl ParamSource {
    pub fn spec(cite: &str) -> Self {
        ParamSource::Spec { cite: cite.into() }
    }
    pub fn lit(cite: &str) -> Self {
        ParamSource::Literature { cite: cite.into() }
    }
    pub fn assumed(rationale: &str) -> Self {
        ParamSource::Assumed {
            rationale: rationale.into(),
        }
    }
    pub fn is_fitted(&self) -> bool {
        matches!(self, ParamSource::Fitted { .. })
    }
}

/// One parameter, its value, and its provenance.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ParamDoc {
    pub name: String,
    pub value: f64,
    pub units: String,
    pub source: ParamSource,
}

impl ParamDoc {
    pub fn new(name: &str, value: f64, units: &str, source: ParamSource) -> Self {
        ParamDoc {
            name: name.into(),
            value,
            units: units.into(),
            source,
        }
    }
}

/// The calibration state of a whole model.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Calibration {
    /// No field data has ever been fitted. This is the only value that can
    /// occur before the first walk round, and it is the current one.
    Uncalibrated {
        /// Spelled out in the JSON so a reader skimming the file sees it.
        warning: String,
    },
    /// Fitted against field round `round`.
    CalibratedAgainstRound { round: u32, residual_db: f64 },
}

impl Default for Calibration {
    fn default() -> Self {
        Calibration::Uncalibrated {
            warning: "NOT CALIBRATED: no field measurements exist yet. These are \
                      model outputs under assumed PHY parameters and must never be \
                      quoted as measured per-hop distance or delivery rate."
                .into(),
        }
    }
}

impl Calibration {
    pub fn label(&self) -> String {
        match self {
            Calibration::Uncalibrated { .. } => "simulated, uncalibrated".into(),
            Calibration::CalibratedAgainstRound { round, .. } => {
                format!("simulated, calibrated against round {round}")
            }
        }
    }
}

/// The provenance block that every result file carries.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Provenance {
    /// Always the literal string `simulated`. There is no code path in this
    /// crate that can set it to anything else.
    pub provenance: &'static str,
    pub calibration: Calibration,
    /// Human-readable restatement of `calibration`, duplicated so that a tool
    /// that only prints one field still prints the caveat.
    pub label: String,
    pub sim_version: &'static str,
    pub wire_version: u8,
    pub params: Vec<ParamDoc>,
}

impl Provenance {
    pub fn new(calibration: Calibration, params: Vec<ParamDoc>) -> Self {
        Provenance {
            provenance: "simulated",
            label: calibration.label(),
            calibration,
            sim_version: env!("CARGO_PKG_VERSION"),
            wire_version: gdc_wire::WIRE_VERSION,
            params,
        }
    }

    /// True when any parameter is still a guess, i.e. the model is not fit for
    /// quoting as anything but a model.
    pub fn has_unfitted_params(&self) -> bool {
        self.params.iter().any(|p| !p.source.is_fitted())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uncalibrated_is_the_default_and_says_so_loudly() {
        let p = Provenance::new(Calibration::default(), vec![]);
        assert_eq!(p.provenance, "simulated");
        assert!(p.label.contains("uncalibrated"));
        let json = serde_json::to_string(&p).expect("serialises");
        assert!(json.contains("NOT CALIBRATED"));
    }

    #[test]
    fn unfitted_params_are_detected() {
        let p = Provenance::new(
            Calibration::default(),
            vec![ParamDoc::new("n", 3.0, "", ParamSource::assumed("urban guess"))],
        );
        assert!(p.has_unfitted_params());
    }
}
