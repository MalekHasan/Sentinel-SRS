# ADR-0035: Uploads to sharing sites

- Status: **Accepted** (Sprint 9; `crates/sentinel-detect`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-16
- Implements DL-06 on Android: "Flag uploads to file-sharing, paste and anonymous-hosting services by apps not normally associated with them". Acceptance: "Category list from destination tracing".
- Amended 2026-10-22 for audit finding A-15 ([AUDIT-PHASE-A](../AUDIT-PHASE-A.md)): decision 3, own apps by exact package name.

## Context

Spyware has to hand over what it collects. Running a server costs money and gives the operator away, so a lot of it uses services anyone can post to:
- **paste sites** for stolen text;
- **file-sharing sites** for recordings and photos;
- **anonymous drops**: tunnels to a private server (ngrok, Cloudflare quick tunnels), webhook catchers, a chat service's bot interface (`api.telegram.org`), anonymous publishing.

An ordinary app has little reason to send data to these, unless it is the service's own app.

The destination data Sentinel has (DT-01, DT-06) comes from tracker lists. They name advertising and analytics companies, not these services.

## Decision

1. **A category list in the core** (`sentinel_detect::sharing_site`), about 40 well-known services, each with:
   - its domain (names under it count);
   - what it is for: `paste`, `file_sharing` or `anonymous_drop`;
   - the exact package names of its own apps, where it has any.
2. **An upload** is one connection that sent at least 16 KiB to a listed service. A page view sends a few kilobytes, so visiting a paste is not flagged, posting one is.
   - The name is the one the connection was made to: a TLS server name, or the name the app looked up.
3. **The service's own app is not flagged:** an app whose package name is exactly one of the service's own (`mega.privacy.android.app` for `mega.nz`; `org.telegram.messenger`, `org.telegram.messenger.web` and Telegram X's `org.thunderdog.challegram` for `api.telegram.org`; WeTransfer's and MediaFire's apps). Before, any package name that carried the service's name was taken for its own, and the app's maker chooses the name: `com.x.telegramsync` could send what it collected through a Telegram bot unflagged (audit A-15).
   - An app installed with one of these names when the service's own is not installed, signed by someone else, is still not flagged. Checking the signing certificate would close that; ID-13 already reports known stalkerware by its certificate.
   - An official app missing from the list raises a Warning when it uploads, which the user can allow for that app (AL-05).
   - System apps are not counted, as for DL-04 and DL-05, nor blocked connections.
4. **The alert** (`sharing-site-upload`) is a **Warning**.
   - Its evidence is the app, the name, what the service is for, and the bytes sent.
   - It offers to block the app or look at it.
   - Its text says what such a site is and that it is not the app's own.
   - Once per app and service in a monitoring run; one open alert per app.

## Verification

- `sentinel-detect`:
  - sites are known by domain and the names under it, in any case and with a trailing dot;
  - look-alike names (`notpastebin.com`) and the rest of `telegram.org` are not;
  - the alert is a Warning about the app, offers to block and to look, and its stored JSON is fixed;
  - 1 byte under 16 KiB is a visit;
  - the services' own apps (MEGA, WeTransfer, MediaFire, Telegram, Telegram X) are not flagged, but an app whose name only contains a service's name, or is a service's own app uploading to another service, is.
- `sentinel-ffi`, through the flow observer and the history, an app's five connections:
  - a visit, two uploads to a paste site, an upload by MEGA's app to MEGA, and an upload by a system app;
  - together they raise exactly one Warning, naming the paste site with the first upload's size.
- `RtlTest.sharingSiteAlert`: the alert in Arabic, right to left.

## Consequences

- **The list is fixed in the app** and will age: services close, and new ones open. It could come with the signed feed instead, like the indicators (ADR-0019).
- **Browsers and file managers that share files for the user will be flagged** when they upload to these sites. "Not useful" quiets later ones about that app.
- **An unlisted service is not found.** Neither is an upload through a large cloud host (Google Drive, Dropbox), where an ordinary app's use is common.
- **The size of one connection decides.** Data split into many small posts, each under 16 KiB, is not flagged as an upload. It still appears as connections to the site.
