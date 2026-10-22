# ADR-0015: Firewall rules by app, domain and address

- Status: **Accepted** (Sprint 6; `crates/sentinel-detect`, then `crates/sentinel-store`, `crates/sentinel-vpn`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-15
- Implements: SRS CM-10 for Android, the Phase A subset: rules by app, domain, address and company; RA-01 (block an app, a destination or a company, from the app). Modes (CM-08) are [ADR-0016](0016-firewall-modes.md), isolation (RA-03) is [ADR-0017](0017-isolation.md); the action journal and undo are [ADR-0018](0018-action-journal.md).
- Amended 2026-10-22 for audit finding A-09 ([AUDIT-PHASE-A](../AUDIT-PHASE-A.md)): decision 1, apps that share a Linux user.

## Context

CM-10 lists rules by app (path, signer, hash), destination (address, range, domain, company, country), port, direction and network profile. Phase A needs app, domain and address ([PHASE-A-ANDROID.md](../PHASE-A-ANDROID.md), Sprint 6). On Android an app is its package: Android identifies it by its signature, so the path and hash do not apply.

The packet engine can already refuse a connection in two places ([ADR-0006](0006-android-packet-engine.md)):
- when it starts, before any connection to the server;
- when its TLS ClientHello names the server, before the ClientHello is forwarded.

Until now every verdict was "allow".

Names are the hard part. The engine learns a name for an address from the DNS answers it forwards, but it keeps one name per address: the most recent answer. Large services serve many names from the same addresses. Google's front ends serve YouTube and `doubleclick.net`, and a CDN serves thousands of sites. A rule that blocks `ads.example` would block another site on the same address if the address happened to be learned last from `ads.example`. A firewall that breaks unrelated apps will be switched off.

## Decision

1. **A rule names an app, a destination, or both, and allows or blocks.**
   - The app is a package name.
   - **Packages that share a Linux user (`sharedUserId`) are one owner on the network.** Android names a connection's owner by its Linux user, and several packages from one maker can share one. Android then names the user, for example `org.example.shared:10123`, and Kotlin also gives every package that shares it. A rule about any of those packages, or about the user's name, applies to all its connections: the network cannot tell them apart. Before, a rule made from an alert about one package (ID-12, ID-13) did not match the user's connections, so spyware made of two packages that share a user got past it (audit A-09). Allowing one package does not undo blocking another: blocking wins the tie.
   - A destination is a domain, an address range or a company. A domain covers the names below it (`example.com` covers `www.example.com` but not `notexample.com`). A single address is a range of one. A company covers the names the tracker list gives it (DT-06, [ADR-0011](0011-tracker-list.md)), spelt as the list spells it, so it is matched only where a name is: at a TLS server name and at a DNS lookup.
   - Rules are checked when made: a rule needs an app or a destination; a domain must be a plain name; a range is written one way only (no bits set past its prefix). An IPv4 address written as IPv6 is the IPv4 address.
2. **The most specific rule decides.** A rule for an app and a destination beats one for a destination, which beats one for an app. Among matching rules equally specific, blocking wins. When no rule matches, the firewall mode decides ([ADR-0016](0016-firewall-modes.md)): in Watch only, the default, that means allow.
3. **The core decides, the engine enforces.** The rules and their decision live in `sentinel-detect` (`firewall`), so every edition decides the same way. The engine asks at three moments, each with only what it knows for sure:
   - **A new connection:** its app and address. App rules and address rules decide here, and a blocked connection never reaches the server.
   - **A TLS server name:** the app, the address and that name, and the name's company if the tracker list gives one. Domain and company rules decide here too.
     - The ClientHello is read whole, joined from the handshake records TLS lets a client split it into, up to `MAX_HELLO` (about 33 KB) of records. The engine waits up to 500 ms (`sni_wait`) for its rest.
     - **A name that cannot be read is not let past a rule that blocks by name** (audit finding A-03). This covers a ClientHello that comes too slowly, is broken across records, or is longer than the engine reads; the server may still see a name. If a rule blocking a domain or a company applies to the app, the connection is blocked before anything is forwarded. Otherwise it goes on, as before. A ClientHello read whole that carries no name is not blocked: a client connecting to an address needs none.
   - **A DNS lookup through the tunnel:** the app that sent it, the name looked up and its company. A blocked name is answered "no such name" at once, so the app never learns the address. This is what blocks a domain over QUIC and plain HTTP, which carry no TLS server name the engine reads.
   - **A change of the rules or the mode, while a connection is open:** the same app, address and TLS server name, if one was seen. A connection now blocked ends at once, in both directions, and is stored as blocked. Blocking an app (RA-01) therefore also stops what it is already sending. The history signals each change to the running engine, and every open connection asks again.

   A name learned only from an earlier DNS answer is never matched against a rule, for the reason above. It still names the connection in the history.
4. **Rules are stored in the encrypted history**, in the SRS `rule` table (`kind` = `firewall`, the rule as JSON in `body`), keyed by what the rule is about. A second rule for the same app and destination replaces the first: allowing something that was blocked is one change, not two rules.
5. **Blocked connections are recorded as blocked** (`flow.verdict`), so the history shows what the firewall stopped.
6. **The app offers blocks where the user looks at an app** (RA-01):
   - The app detail screen says whether the app may use the internet, and why not: a rule the user made, or Block new apps. It offers the one change that fits: block it, take the block back, or allow a new app. Each destination can be blocked for that app, and each company in every app.
   - The "new app" and "new places" alerts (CM-04) offer to block the app.
   - Taking a block back removes its rule rather than adding an allow. An allow would outlive the block and allow-list the app, which isolation (RA-03) will treat as trusted.

## Verification

- `sentinel-detect` (`firewall` tests), one test per field and per rule of decision:
  - an app rule covers that app's traffic only, and nothing whose owner is unknown;
  - a rule about one package of a shared Linux user, or about the user's name, covers all its connections, for names blocked unread too; Block new apps and isolation treat it as one app;
  - a domain rule covers the names below it and no look-alikes (`notads.example`, `ads.example.org`). Case and the trailing dot do not matter, and an address never matches a domain;
  - a company rule covers its names only once their company is known, spelt exactly; an app's exception to it needs that app; company names are checked;
  - an address rule covers that address, also written as IPv4-in-IPv6, and a range covers exactly its range, in IPv4 and IPv6;
  - an app-and-destination rule needs both;
  - the most specific rule decides, and blocking wins a tie;
  - bad apps, domains and ranges are refused; keys ignore the action; the stored JSON is fixed by a test.
- `sentinel-store`: rules are kept encrypted, replaced by key, removed, survive reopening, and are wiped with the history.
- `sentinel-ffi`:
  - rules are checked when kept (a rule with nothing, a bad name and a badly written range are refused) and stored as matched (lower case, no trailing dot);
  - with rules for an app, a range and a domain, a connection is blocked by its app or address when it starts, and by its TLS server name once seen;
  - an app-and-domain allow wins over a domain block;
  - a name from an earlier DNS answer is not matched, and taking a rule back applies to the next connection;
  - when the rules change, an open connection is decided again by its app, address and server name, but not by a name from a DNS answer, and an ended one is not asked;
  - with a tracker list, a company rule blocks a server name and a lookup of the company's names, an app's exception lets that app through, and without the list nothing matches;
  - an app's access says which rule is about it as a whole and whether Block new apps keeps it off; a rule about one of its destinations does not count;
  - the "new app" and "new places" alerts offer to block the app;
  - through the real packet engine, blocking an app ends its open connection within a second; nothing more reaches the server, and it is stored as blocked;
  - blocked connections are stored as blocked, and without a history nothing is blocked;
  - through the real packet engine, an app's blocked datagram never reaches the server.
- `sentinel-vpn`:
  - when the firewall changes, every open flow is asked again; one still allowed goes on, one now blocked ends at once and is reported as blocked, and without a change no flow is asked;
  - a query's name is read, and answers or garbage are not queries;
  - the "no such name" reply repeats the query's id and question and names no address;
  - through the engine, a blocked lookup is answered at once and never reaches the resolver, while other lookups are forwarded as before.
- `sentinel-ffi`: a lookup is decided by the app that sends it and the name looked up, never by the resolver's address. A domain rule for every app blocks it whoever asks, and an app's exception needs that app.
- On the Android 14 emulator (`FirewallTest`), with this app's own connections through the tunnel:
  - a rule blocking the test server's address stops the request, and it gets through once the rule is removed, five times over with monitoring restarted in between. The history stores five connections as blocked and five as allowed;
  - a rule blocking this app ends its connection that is already open, within a second, and the history stores it as blocked;
  - `AppDetailTest`: blocking this app from its own detail screen stops its next request, and taking the block back lets it through; the screen blocks the app, a destination for it and a company in every app, says what is blocked, takes each block back by its own rule, and allows a new app;
  - `AlertsTest` shows the alert's block action, and `RtlTest` the app's access in Arabic, right to left;
  - a domain rule stops a connection whose TLS ClientHello names a host below it, while another name gets through;
  - (`sentinel-vpn`) a ClientHello split into records as small as one byte still gives its name, and a blocked name reaches nothing; one too slow to read is put to the observer, which may block it before a byte is forwarded; one read whole without a name, another protocol, or a client that sends nothing is not; records broken or beyond the limit are unreadable (audit finding A-03);
  - (`sentinel-detect`, `sentinel-ffi`) a name that cannot be read is blocked when a domain or company block applies to the app, for every app or this one, and let through when none does;
  - a domain rule for `localhost` (which resolves anywhere) makes the tunnel's resolver answer "no such name" with no address, and once it is removed the network's resolver answers.

## Consequences

- **A TLS connection without a server name is not stopped by a domain rule.** An app that connects to an address of its own needs no name, and only address rules apply to it. The name is needed where a server hosts many names, as content delivery networks do; there a name that cannot be read is blocked, as above.
- **A slow ClientHello is blocked whenever a domain or company block applies to the app,** whatever name it would have carried. Allow rules for some names are not weighed, since none can be shown to apply. Apps send their ClientHello at once, so this should not happen to them. The fuzzing of ADR-0036 covers the joined records.
- **Indicators (ID-13) are not matched against a name that cannot be read,** and such a connection raises no indicator alert. Indicators never block (SRS §9).
- **Apps that bypass the tunnel's DNS** (their own DNS over HTTPS, or addresses built in) are stopped by domain rules only on TLS connections that name the server. Address rules still apply. QUIC traffic that never looked a name up through the tunnel is not stopped by a domain rule.
- **Per-app domain rules at DNS lookups** depend on Android saying which app a lookup belongs to. Lookups that Android attributes to the system match only rules for every app.
- **A connection without a known owner is not stopped by an app rule** in Watch only. An app the user blocked can still send a UDP datagram if it closes its socket before Sentinel asks Android whose it is; with the socket closed, no reply reaches it. Block new apps and isolation stop such connections (audit A-09).
- **An app blocked as a whole stays blocked.** A rule allowing it one domain does not open its TLS connections, because they are refused when they start, before their name is known. Allowing it an address range works. Domain allows are for exceptions to domain blocks.
- **The moment monitoring starts.** Android moves apps into a new tunnel a moment after Sentinel creates it. A connection made in that moment goes around Sentinel, as traffic does while monitoring is off, so no rule applies to it. The device tests therefore wait until the tunnel is this app's network before connecting, and after stopping, until it no longer is: otherwise a restart finds the old tunnel still listed and connects around both.
- **Companies are only as complete as the tracker list.** A company's names that the list does not give are not blocked by its rule, and without a tracker list no company rule matches. The app detail screen offers company blocks only for companies the list named among the app's destinations.
- **Not yet:** country, port and direction rules (CM-10), Android's per-network profiles, and a screen listing every rule. Countries can be added as destinations like companies, from the IP database (DT-01).
