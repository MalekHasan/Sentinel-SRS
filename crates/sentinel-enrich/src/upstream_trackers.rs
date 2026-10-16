// SPDX-License-Identifier: GPL-3.0-or-later
//! Readers for the published tracker lists (LICENCE-REVIEW.md §1). Both are DuckDuckGo
//! data under CC BY-NC-SA 4.0: the tracker list built from them is shared under the same
//! licence.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::{SourceId, TrackerBuildError, TrackerDbBuilder};

#[derive(Debug, thiserror::Error)]
pub enum TrackerListError {
    #[error("not the expected JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Build(#[from] TrackerBuildError),
}

#[derive(Deserialize)]
struct Owner {
    name: Option<String>,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
}

impl Owner {
    fn shown(&self) -> Option<&str> {
        self.display_name.as_deref().or(self.name.as_deref())
    }
}

#[derive(Deserialize)]
struct RadarDomain {
    domain: String,
    owner: Option<Owner>,
    #[serde(default)]
    categories: Vec<String>,
}

/// One file of DuckDuckGo Tracker Radar's `domains/<region>/` folders: a domain, its
/// owner and its categories. Other fields are ignored.
///
/// Returns whether the domain was added. Tracker Radar lists every third-party domain
/// it saw; one with neither an owner nor a category says nothing about where data
/// goes, so it is left out. So is a name that is not a plain domain (the list has
/// `%2a.googleapis.com`).
pub fn read_tracker_radar_domain(
    json: &str,
    source: SourceId,
    builder: &mut TrackerDbBuilder,
) -> Result<bool, TrackerListError> {
    let radar: RadarDomain = serde_json::from_str(json)?;
    let categories: Vec<&str> = radar.categories.iter().map(String::as_str).collect();
    let company = radar.owner.as_ref().and_then(Owner::shown);
    match builder.add_domain(source, &radar.domain, company, &categories) {
        Ok(added) => Ok(added),
        Err(TrackerBuildError::BadDomain(_)) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

#[derive(Deserialize)]
struct AppList {
    trackers: BTreeMap<String, AppTracker>,
}

#[derive(Deserialize)]
struct AppTracker {
    owner: Option<Owner>,
}

/// DuckDuckGo's app tracker blocklist (`app/android-tds.json` in `tracker-blocklists`):
/// tracker domains seen in Android apps and their owners. It has no categories. Returns
/// the number of domains added: those with an owner.
pub fn read_ddg_app_trackers(
    json: &str,
    source: SourceId,
    builder: &mut TrackerDbBuilder,
) -> Result<usize, TrackerListError> {
    let list: AppList = serde_json::from_str(json)?;
    let mut added = 0;
    for (domain, tracker) in &list.trackers {
        let company = tracker.owner.as_ref().and_then(Owner::shown);
        added += usize::from(builder.add_domain(source, domain, company, &[])?);
    }
    Ok(added)
}
