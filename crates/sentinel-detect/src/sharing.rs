// SPDX-License-Identifier: GPL-3.0-or-later
//! Uploads to sharing sites (DL-06, ADR-0035): an app that sends data to a file-sharing,
//! paste or anonymous drop service it has nothing to do with, as spyware hands over
//! what it collected.

use serde::{Deserialize, Serialize};

use crate::{Alert, Evidence, Rule, Severity};

/// What a sharing site is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SharingSite {
    /// Text posted for anyone with the link: pastebin and the like.
    Paste,
    /// Files posted for anyone with the link.
    FileSharing,
    /// Drops that need no account or hide where the data goes: tunnels to a private
    /// server, webhook catchers, chat bot interfaces, anonymous publishing.
    AnonymousDrop,
}

/// The least an app must send in one connection for it to be an upload, not a visit: a
/// page view sends a few kilobytes.
pub const SHARING_UPLOAD_BYTES: u64 = 16 * 1024;

/// A sharing service: its domain (and the names under it), what it is for, and the
/// package names of its own apps, which upload to it as a matter of course.
struct Service {
    domain: &'static str,
    site: SharingSite,
    apps: &'static [&'static str],
}

const fn service(
    domain: &'static str,
    site: SharingSite,
    apps: &'static [&'static str],
) -> Service {
    Service { domain, site, apps }
}

/// The services' own apps, by exact package name (audit A-15). A name that only contains
/// the service's, such as `com.x.telegramsync`, is anyone's: the app's maker chooses it.
const NO_APP: &[&str] = &[];
const TELEGRAM: &[&str] = &[
    "org.telegram.messenger",
    "org.telegram.messenger.web",
    "org.thunderdog.challegram",
];
const MEGA: &[&str] = &["mega.privacy.android.app"];
const WETRANSFER: &[&str] = &["com.wetransfer.app.live"];
const MEDIAFIRE: &[&str] = &["com.mediafire.android"];

/// The category list (DL-06): well-known services by what they are for.
const SERVICES: &[Service] = &[
    service("pastebin.com", SharingSite::Paste, NO_APP),
    service("paste.ee", SharingSite::Paste, NO_APP),
    service("hastebin.com", SharingSite::Paste, NO_APP),
    service("ghostbin.co", SharingSite::Paste, NO_APP),
    service("paste.rs", SharingSite::Paste, NO_APP),
    service("dpaste.org", SharingSite::Paste, NO_APP),
    service("dpaste.com", SharingSite::Paste, NO_APP),
    service("rentry.co", SharingSite::Paste, NO_APP),
    service("rentry.org", SharingSite::Paste, NO_APP),
    service("privatebin.net", SharingSite::Paste, NO_APP),
    service("termbin.com", SharingSite::Paste, NO_APP),
    service("controlc.com", SharingSite::Paste, NO_APP),
    service("justpaste.it", SharingSite::Paste, NO_APP),
    service("transfer.sh", SharingSite::FileSharing, NO_APP),
    service("file.io", SharingSite::FileSharing, NO_APP),
    service("gofile.io", SharingSite::FileSharing, NO_APP),
    service("wetransfer.com", SharingSite::FileSharing, WETRANSFER),
    service("we.tl", SharingSite::FileSharing, WETRANSFER),
    service("sendspace.com", SharingSite::FileSharing, NO_APP),
    service("mediafire.com", SharingSite::FileSharing, MEDIAFIRE),
    service("mega.nz", SharingSite::FileSharing, MEGA),
    service("mega.io", SharingSite::FileSharing, MEGA),
    service("filebin.net", SharingSite::FileSharing, NO_APP),
    service("catbox.moe", SharingSite::FileSharing, NO_APP),
    service("0x0.st", SharingSite::FileSharing, NO_APP),
    service("temp.sh", SharingSite::FileSharing, NO_APP),
    service("bashupload.com", SharingSite::FileSharing, NO_APP),
    service("uguu.se", SharingSite::FileSharing, NO_APP),
    service("ngrok.io", SharingSite::AnonymousDrop, NO_APP),
    service("ngrok-free.app", SharingSite::AnonymousDrop, NO_APP),
    service("ngrok.app", SharingSite::AnonymousDrop, NO_APP),
    service("trycloudflare.com", SharingSite::AnonymousDrop, NO_APP),
    service("loca.lt", SharingSite::AnonymousDrop, NO_APP),
    service("serveo.net", SharingSite::AnonymousDrop, NO_APP),
    service("localhost.run", SharingSite::AnonymousDrop, NO_APP),
    service("webhook.site", SharingSite::AnonymousDrop, NO_APP),
    service("pipedream.net", SharingSite::AnonymousDrop, NO_APP),
    service("requestbin.net", SharingSite::AnonymousDrop, NO_APP),
    service("api.telegram.org", SharingSite::AnonymousDrop, TELEGRAM),
    service("telegra.ph", SharingSite::AnonymousDrop, TELEGRAM),
];

/// The sharing service `hostname` belongs to, if it is one: its domain and what it is
/// for.
pub fn sharing_site(hostname: &str) -> Option<(&'static str, SharingSite)> {
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    SERVICES
        .iter()
        .find(|service| {
            hostname
                .strip_suffix(service.domain)
                .is_some_and(|rest| rest.is_empty() || rest.ends_with('.'))
        })
        .map(|service| (service.domain, service.site))
}

/// Whether `app` is one of the service's own apps, by its exact package name.
fn own_app(app: &str, domain: &str) -> bool {
    SERVICES
        .iter()
        .filter(|service| service.domain == domain)
        .any(|service| service.apps.contains(&app))
}

/// DL-06: `app` sent `bytes_up` in one connection to `hostname`. An alert if that is an
/// upload to a sharing service that is not the app's own.
pub fn sharing_site_upload(now: i64, app: &str, hostname: &str, bytes_up: u64) -> Option<Alert> {
    if bytes_up < SHARING_UPLOAD_BYTES {
        return None;
    }
    let (domain, site) = sharing_site(hostname)?;
    if own_app(app, domain) {
        return None;
    }
    Some(Alert {
        rule: Rule::SharingSiteUpload,
        severity: Severity::Warning,
        created: now,
        evidence: vec![
            Evidence::App {
                package: app.to_owned(),
            },
            Evidence::SharingSite {
                destination: hostname.to_owned(),
                site,
                bytes_up,
            },
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "org.example.flashlight";

    #[test]
    fn sites_are_known_by_their_domain_and_the_names_under_it() {
        assert_eq!(
            sharing_site("pastebin.com"),
            Some(("pastebin.com", SharingSite::Paste))
        );
        assert_eq!(
            sharing_site("abc-123.trycloudflare.com"),
            Some(("trycloudflare.com", SharingSite::AnonymousDrop))
        );
        assert_eq!(
            sharing_site("Eu.Static.MEGA.nz."),
            Some(("mega.nz", SharingSite::FileSharing))
        );
        assert_eq!(sharing_site("notpastebin.com"), None);
        assert_eq!(sharing_site("www.example.com"), None);
        assert_eq!(sharing_site("telegram.org"), None, "only the bot interface");
    }

    #[test]
    fn an_upload_by_an_app_unrelated_to_the_site_is_flagged() {
        let alert = sharing_site_upload(7, APP, "api.telegram.org", 40_000).unwrap();
        assert_eq!(alert.rule, Rule::SharingSiteUpload);
        assert_eq!(alert.severity, Severity::Warning);
        assert_eq!(alert.app(), Some(APP));
        assert_eq!(
            alert.actions(),
            vec![
                crate::Action::BlockApp {
                    package: APP.to_owned()
                },
                crate::Action::OpenApp {
                    package: APP.to_owned()
                },
            ]
        );
        assert_eq!(
            crate::evidence_to_json(&alert.evidence[1..]),
            r#"[{"type":"sharing_site","destination":"api.telegram.org","site":"anonymous_drop","bytes_up":40000}]"#
        );
    }

    #[test]
    fn a_visit_is_not_an_upload() {
        assert_eq!(
            sharing_site_upload(7, APP, "pastebin.com", SHARING_UPLOAD_BYTES - 1),
            None
        );
        assert!(sharing_site_upload(7, APP, "pastebin.com", SHARING_UPLOAD_BYTES).is_some());
    }

    /// A site's own apps are known by their exact package names. A name that only
    /// carries the service's, which any app's maker can choose, is flagged (audit A-15).
    #[test]
    fn a_sites_own_app_is_not_flagged() {
        for (app, host) in [
            ("mega.privacy.android.app", "g.api.mega.co.nz.mega.nz"),
            ("com.wetransfer.app.live", "we.tl"),
            ("com.mediafire.android", "www.mediafire.com"),
            ("org.telegram.messenger", "api.telegram.org"),
            ("org.thunderdog.challegram", "telegra.ph"),
        ] {
            assert_eq!(sharing_site_upload(7, app, host, 1_000_000), None, "{app}");
        }
        for (app, host) in [
            ("com.x.telegramsync", "api.telegram.org"),
            ("org.telegram.messenger.sync", "api.telegram.org"),
            ("nz.mega.backup", "mega.nz"),
            ("com.example.mega_fan", "mega.nz"),
            ("org.telegram.messenger", "pastebin.com"),
        ] {
            assert!(
                sharing_site_upload(7, app, host, 1_000_000).is_some(),
                "{app}"
            );
        }
    }
}
