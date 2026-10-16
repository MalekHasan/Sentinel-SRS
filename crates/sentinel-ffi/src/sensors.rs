// SPDX-License-Identifier: GPL-3.0-or-later
//! Microphone and camera use (SE-01 basic, SE-04, ADR-0027), as seen from Kotlin.

use sentinel_detect::{Attribution, sensor_while_away};

use crate::alerts::SensorKind;
use crate::history::{HistoryError, HistoryStore, now_ms};

/// One use of the microphone or camera.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SensorUse {
    pub id: i64,
    pub sensor: SensorKind,
    pub started_ms: i64,
    /// `None` while in use.
    pub ended_ms: Option<i64>,
    /// The app that was on screen when the use began: a guess, not the app's identity.
    /// `None` when unknown.
    pub guess: Option<String>,
    /// False once the screen was off or locked during the use.
    pub user_present: bool,
}

#[uniffi::export]
impl HistoryStore {
    /// `sensor` came into use at `started_ms` (SE-01). `guess` is the app on screen then,
    /// if known. With the user away (screen off or locked), it raises a High alert
    /// (SE-04). Returns the use's id, for [`HistoryStore::sensor_stopped`].
    pub fn sensor_started(
        &self,
        sensor: SensorKind,
        started_ms: i64,
        guess: Option<String>,
        user_present: bool,
    ) -> Result<i64, HistoryError> {
        let attribution = if guess.is_some() {
            Attribution::Foreground
        } else {
            Attribution::Unknown
        };
        let id = self.store.sensor_started(
            sensor.into(),
            started_ms,
            guess.as_deref(),
            attribution,
            user_present,
        )?;
        if !user_present {
            self.raise(&sensor_while_away(
                now_ms(),
                sensor.into(),
                started_ms,
                guess.as_deref(),
            ))?;
        }
        Ok(id)
    }

    /// The screen went off or locked while use `id` went on (SE-04): a High alert, once
    /// per use.
    pub fn sensor_while_away(&self, id: i64) -> Result<(), HistoryError> {
        if let Some(used) = self.store.sensor_away(id)? {
            self.raise(&sensor_while_away(
                now_ms(),
                used.sensor,
                used.started,
                used.app.as_deref(),
            ))?;
        }
        Ok(())
    }

    /// Use `id` ended at `ended_ms`.
    pub fn sensor_stopped(&self, id: i64, ended_ms: i64) -> Result<(), HistoryError> {
        Ok(self.store.sensor_ended(id, ended_ms)?)
    }

    /// Monitoring stopped at `ended_ms`: every use still open ends then.
    pub fn end_sensor_uses(&self, ended_ms: i64) -> Result<(), HistoryError> {
        Ok(self.store.end_sensor_uses(ended_ms)?)
    }

    /// The most recent sensor uses, newest first.
    pub fn recent_sensor_uses(&self, limit: u32) -> Result<Vec<SensorUse>, HistoryError> {
        Ok(self
            .store
            .recent_sensor_uses(limit)?
            .into_iter()
            .map(|used| SensorUse {
                id: used.id,
                sensor: used.sensor.into(),
                started_ms: used.started,
                ended_ms: used.ended,
                guess: used.app,
                user_present: used.user_present,
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::alerts::{AlertAction, AlertEvidence, AlertRule, AlertSeverity};

    fn history(dir: &std::path::Path) -> Arc<HistoryStore> {
        let path = dir.join("history.db").to_string_lossy().into_owned();
        HistoryStore::open(path, vec![7; 32]).unwrap()
    }

    /// SE-01 and SE-04: uses are recorded with their guess; one that begins, or goes on,
    /// with the user away raises one High alert that names no app.
    #[test]
    fn uses_are_recorded_and_use_while_away_raises_one_alert() {
        let dir = tempfile::tempdir().unwrap();
        let history = history(dir.path());
        let notes = Some("org.example.notes".to_owned());

        // With the user there: recorded, nothing raised.
        let mic = history
            .sensor_started(SensorKind::Microphone, 1_000, notes.clone(), true)
            .unwrap();
        assert!(history.alerts(true, 10).unwrap().is_empty());
        // The screen goes off while it goes on: one alert, however often it is told.
        history.sensor_while_away(mic).unwrap();
        history.sensor_while_away(mic).unwrap();
        let alerts = history.alerts(true, 10).unwrap();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule, AlertRule::SensorWhileAway);
        assert_eq!(alerts[0].severity, AlertSeverity::High);
        assert_eq!(
            alerts[0].evidence,
            [AlertEvidence::Sensor {
                sensor: SensorKind::Microphone,
                started_ms: 1_000,
                guess: notes.clone()
            }]
        );
        assert_eq!(alerts[0].actions, [AlertAction::OpenPrivacySettings]);
        history.sensor_stopped(mic, 4_000).unwrap();

        // The camera, begun with the screen off and nobody to guess from.
        let camera = history
            .sensor_started(SensorKind::Camera, 5_000, None, false)
            .unwrap();
        history.sensor_while_away(camera).unwrap();
        assert_eq!(history.alerts(true, 10).unwrap().len(), 2);
        history.end_sensor_uses(9_000).unwrap();

        assert_eq!(
            history.recent_sensor_uses(10).unwrap(),
            [
                SensorUse {
                    id: camera,
                    sensor: SensorKind::Camera,
                    started_ms: 5_000,
                    ended_ms: Some(9_000),
                    guess: None,
                    user_present: false,
                },
                SensorUse {
                    id: mic,
                    sensor: SensorKind::Microphone,
                    started_ms: 1_000,
                    ended_ms: Some(4_000),
                    guess: notes,
                    user_present: false,
                },
            ]
        );
    }
}
