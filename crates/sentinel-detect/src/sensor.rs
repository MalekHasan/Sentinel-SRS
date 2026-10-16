// SPDX-License-Identifier: GPL-3.0-or-later
//! Microphone and camera use (SE-01, SE-04, ADR-0027).

use serde::{Deserialize, Serialize};

use crate::{Alert, Evidence, Rule, Severity};

/// A sensor whose use is recorded. The names are the SRS's (§13.1 `sensor_use.sensor`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Sensor {
    #[serde(rename = "mic")]
    Microphone,
    #[serde(rename = "camera")]
    Camera,
}

impl Sensor {
    /// The name stored in the history.
    pub fn as_str(self) -> &'static str {
        match self {
            Sensor::Microphone => "mic",
            Sensor::Camera => "camera",
        }
    }

    pub fn from_name(name: &str) -> Option<Sensor> {
        [Sensor::Microphone, Sensor::Camera]
            .into_iter()
            .find(|s| s.as_str() == name)
    }
}

/// How the app using a sensor was found (§13.1 `sensor_use.source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Attribution {
    /// Not at all: Android does not tell an ordinary app (AM-15).
    Unknown,
    /// A guess: the app that was on screen when the use began.
    Foreground,
    /// The platform named the app.
    Exact,
}

impl Attribution {
    /// The name stored in the history.
    pub fn as_str(self) -> &'static str {
        match self {
            Attribution::Unknown => "unknown",
            Attribution::Foreground => "foreground",
            Attribution::Exact => "exact",
        }
    }

    pub fn from_name(name: &str) -> Option<Attribution> {
        [
            Attribution::Unknown,
            Attribution::Foreground,
            Attribution::Exact,
        ]
        .into_iter()
        .find(|a| a.as_str() == name)
    }
}

/// SE-04: `sensor`, in use since `started` (Unix ms), was in use while the screen was
/// off or locked. High (SRS SE-04). `guess` is the app on screen when the use began, if
/// known; it is only a guess, so the alert is not about that app.
pub fn sensor_while_away(now: i64, sensor: Sensor, started: i64, guess: Option<&str>) -> Alert {
    Alert {
        rule: Rule::SensorWhileAway,
        severity: Severity::High,
        created: now,
        evidence: vec![Evidence::Sensor {
            sensor,
            started,
            guess: guess.map(str::to_owned),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Action, evidence_from_json, evidence_to_json};

    #[test]
    fn names_round_trip() {
        for sensor in [Sensor::Microphone, Sensor::Camera] {
            assert_eq!(Sensor::from_name(sensor.as_str()), Some(sensor));
        }
        for attribution in [
            Attribution::Unknown,
            Attribution::Foreground,
            Attribution::Exact,
        ] {
            assert_eq!(
                Attribution::from_name(attribution.as_str()),
                Some(attribution)
            );
        }
        assert_eq!(Sensor::from_name("location"), None);
    }

    /// SE-04: High, about no app (a guess is not proof), and it points to Android's
    /// privacy dashboard, which knows which app it was.
    #[test]
    fn use_while_away_is_high_and_names_no_app() {
        let alert = sensor_while_away(9, Sensor::Microphone, 5, Some("com.example.notes"));
        assert_eq!(alert.rule, Rule::SensorWhileAway);
        assert_eq!(alert.severity, Severity::High);
        assert_eq!(alert.app(), None);
        assert_eq!(alert.actions(), [Action::OpenPrivacySettings]);
        let json = evidence_to_json(&alert.evidence);
        assert_eq!(
            json,
            r#"[{"type":"sensor","sensor":"mic","started":5,"guess":"com.example.notes"}]"#
        );
        assert_eq!(evidence_from_json(&json).unwrap(), alert.evidence);
    }
}
