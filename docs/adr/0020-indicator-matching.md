# ADR-0020: Matching traffic against known indicators

- Status: **Accepted** (Sprint 7; `crates/sentinel-ioc`, `crates/sentinel-detect`, `crates/sentinel-store`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-16
- Implements: SRS ID-13 ("Known stalkerware and remote-access-tool signatures", from the signed IOC list), for the phone's traffic, with the Critical severity §8.3 gives an IOC match. Phase A's acceptance test: a planted test indicator alerts within 5 s. Uses the list that [ADR-0019](0019-indicator-feed-on-android.md) brings to the phone.

## Context

[ADR-0019](0019-indicator-feed-on-android.md) puts a signed list of indicators on the phone: domains, addresses, app package names and signing certificates, each with its source, date and report (MS-10). This ADR covers the domains and addresses. Package names and certificates name installed apps rather than traffic; they are checked against installed apps in Sprint 8. Some things had to be settled first:

- **What traffic to match.** The packet engine sees each DNS query sent to the tunnel's resolver, the TLS server name of each TCP connection, and the address of every connection. Names from earlier DNS answers are not reliable (one address can serve many names; [ADR-0015](0015-firewall-rules.md)).
- **Speed.** Every lookup and every new connection would be checked on the engine's threads, which must not wait ([ADR-0006](0006-android-packet-engine.md)).
- **Which list.** A list can be replaced by a newer one, or removed when it fails its hourly check (SP-04), while monitoring runs. ADR-0019 left open that a removed list must stop matching at once.
- **Noise.** An app that uses a known server once usually uses it again and again. A Critical alarm per lookup would be unbearable.
- **What to do about a match.** RA-01's default trigger is the user, or a rule the user enabled.

## Decision

1. **Three things are matched**:
   - the name in each DNS query sent through the tunnel;
   - the TLS server name of each TCP connection;
   - the address of each new connection.

   A domain indicator matches its own name and every name below it, whatever the case and with or without a final dot. An address indicator matches only that address; an IPv4 address written as IPv6 (`::ffff:a.b.c.d`) counts as the IPv4 address.
2. **Matching is a few hash lookups** (`sentinel_ioc::Matcher`). A name is looked up whole, then with one label fewer each time, down to two labels (a top-level domain alone is never an indicator). It allocates only when the name is not already in lower case. Matching happens on the engine thread in the existing hooks (`flow_started`, `hostname_seen`, `dns_query`).
3. **Only the list in force is used, and the switch is immediate.**
   - The feed keeps the indicators of its bundle in force, from its last check, apart from the bundle's files. So a check or an install, which hashes every file, never makes the engine wait.
   - The engine asks the feed for them at every match. A newer list is used as soon as it is installed.
   - A list that fails its check stops matching as soon as the check fails. This closes the point ADR-0019 left open.
   - Without a history there is nowhere to keep an alert, so nothing is matched.
4. **A match raises a Critical alert, `known-indicator`** (§8.3). Its evidence is the app, when Android names it, and the match:
   - the indicator as listed;
   - what the traffic named (the name, perhaps below the indicator, or the address);
   - how it was seen (DNS query, TLS server name, or address);
   - the family, the threat (spyware or stalkerware), the source's name, the report's date and the report's link (MS-10).

   It is stored as JSON in the alert, like all evidence ([ADR-0012](0012-alerts.md)), and its field names are fixed by a test. A match whose app Android cannot name is still raised, about the phone. As a Critical alert it is always notified, comes through Do Not Disturb where the user allows it, and cannot be "allowed" away (ADR-0012, THREAT-MODEL-A B5).
5. **The alert goes out with the next batch.** The engine thread only queues it. The batch thread stores it and tells the app 250 ms later (`BATCH_DELAY`), within CM-01's one-second batch, well inside ID-13's 5 s. An alert the history could not take, on a full disk for example, is queued again for the following batch, so the sighting is not lost for the run (audit A-25). This holds for every alert raised once a run. At most 64 wait this way, so a history that stays out of reach does not cost more each batch.
6. **One alert per app and indicator.**
   - Within one monitoring run, an app and an indicator are queued once, however they are seen again. A DNS query, then a TLS name, then a connection to the same server is one alert.
   - A later run raises nothing new while an alert about the same app and indicator is still open.
   - Once the user dismisses it, the next run raises another.
7. **Nothing is blocked without the user.** The engine lets the matched traffic through. The alert offers "Block the internet for this app" (RA-01, logged in the action journal with undo; [ADR-0018](0018-action-journal.md)) and "See what this app did".
8. **The app says "Known traces of spyware found"** and shows each line of the evidence: what was looked up or connected to, that it is on the list as a sign of the family and threat, and the source with the report's date and link. It never says "clean" or "safe". The result wording, and the advice MS-13 asks for on every match (do not reset the phone yet, move sensitive talk to another device, contact a helpline), are [ADR-0022](0022-result-wording-and-advice.md)'s.

## Verification

- `sentinel-ioc` (`tests/matcher.rs`, 5 tests):
  - a domain matches itself and every name below it, whatever the case and with a final dot;
  - it does not match its parent, a name that only ends with the same letters, or a name with more after it;
  - an address matches exactly, IPv4-mapped included;
  - names and addresses never cross, and package and certificate indicators are not kept;
  - a hit carries its source and provenance, and the first source to list an indicator wins.
- `sentinel-detect` (4 tests):
  - the alert is Critical, names the app, and offers to block and open it;
  - an alert without an app has no actions;
  - the stored JSON is fixed;
  - "the same sighting" means the same rule, app and indicator, however it was seen.
- `sentinel-store`: the open alerts of a rule are found, newest first, and a dismissed one is not among them.
- `sentinel-ffi`:
  - the feed's indicators are those of the bundle in force: a new bundle's at once, the old ones after a refused update, none after a failed check or before the first one;
  - with flows fed directly:
    - a DNS query, a TLS name and a connection each raise one Critical alert, with their provenance and without blocking;
    - an app not known is reported;
    - the same app and indicator raise one alert per run, and none in a later run while it is open, but one again once it is dismissed;
    - a list removed at its check matches nothing more;
    - while another connection holds the history, the alert cannot be written; it is raised with the next batch once the history is free (A-25);
  - through the real packet engine, a datagram to an address on the list raises the alert in under a second and is not blocked;
  - the device tests' signed lists match the planted name.
- On the Android 14 emulator (`IndicatorAlertTest`), with the signed test list in force:
  - a lookup of a name under the planted indicator, through the tunnel, raises a Critical alert within 5 s, about Sentinel's own app, with exactly the planted indicator's provenance and an offer to block;
  - a TLS connection naming the planted indicator raises one, and the server still answers;
  - the same indicator again, by name or by lookup, raises no second alert;
  - a name above the indicator raises nothing.

  `RtlTest` shows the alert in Arabic, right to left, with no "allow" button. `AlertTextTest` grades the new texts.

## Consequences

- **Lookups Sentinel does not see are not matched.** These include Private DNS and apps' own encrypted DNS, which go around the tunnel's resolver. Such an app is still matched by its TLS server name, unless Encrypted Client Hello hides it, and by address.
- **Android names a connection's app only while its socket exists.** A lookup sent from a socket that is closed at once, before the engine asks, is reported without its app, as a match about the phone. Resolvers keep their socket open until the answer comes, so their lookups are named. The first run of the device test closed its socket at once and found exactly that.
- **A DNS answer that points elsewhere (a CNAME) is not followed.** The phone's resolver asks only for the first name, so an indicator reached only through a CNAME is matched by the address it resolves to, if that address is listed.
- **Traffic from before a list arrived is not matched here.** The history is checked again when a list comes in: the retro-hunt (MS-02, [ADR-0021](0021-retro-hunt.md)).
- **The device test cannot connect to an address on the list.** The list refuses private addresses, and the test server is one. The engine test in the core covers that case with a real packet.
- **A dismissed alert stays dismissed until monitoring restarts**, even if the app keeps using the server. The alternative, alarming again after each dismissal, would let a busy app ring the Critical alarm all day. The app detail screen still shows every connection.
- **The indicators sit in memory as long as a list is in force:** a few megabytes for tens of thousands of indicators. This is to be measured with the real list when it exists (FEED-SIGNING.md, LICENCE-REVIEW L1 and L3).
