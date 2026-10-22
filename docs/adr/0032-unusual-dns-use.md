# ADR-0032: Unusual DNS use

- Status: **Accepted** (Sprint 9; `crates/sentinel-vpn`, `crates/sentinel-detect`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-16
- Implements DL-05 on Android: "Detect unusual DNS use: very long or high-entropy subdomains, high TXT query volume, or an app using its own encrypted DNS to bypass the system resolver". Acceptance: "Detected in the DNS-tunnel simulation test".

## Context

DNS lookups pass through almost any network, so spyware can use them to carry data. It encodes data into the names it looks up (`mzxw6ytb….t.example.com`) under a domain whose name server it runs, and reads the answers, often TXT records, as orders. Each lookup is a new, long, random-looking name.

An app can also look names up itself, over encrypted DNS (HTTPS to a public resolver, or TLS on port 853). Its lookups then pass by the phone's resolver, and by Sentinel, which sees names only in the lookups sent to the tunnel's resolver.

The engine sees every lookup sent to the tunnel's resolver with its app (ADR-0015). Until now it passed on the name but not the record type.

## Decision

1. **The engine passes on the record type** of each lookup. `Observer::dns_query` gains `qtype`, the DNS type number, and `parse_dns_query` returns a `DnsQuery` with the name and type.
2. **Data hidden in DNS** (`dns-tunnel`, a **Warning**), found by `sentinel_detect::DnsWatch` over a sliding 10 minutes:
   - **Random-looking names.** At least 20 different random-looking names under one domain from one app. A name is random-looking when the part before its domain either:
     - is at least 52 characters; or
     - is at least 24 characters, has at least 3 digits, and carries at least 3.5 bits per character (Shannon entropy, as encoded data does and words do not).
   - **The domain** is the name's last two labels, or three under a short second level of a two-letter country (`example.co.uk`). No public suffix list is used.
   - **TXT lookups.** At least 20 by one app.
   - Each app and domain, and each app's TXT lookups, is reported once per monitoring run. At most 1,024 reports are remembered, the oldest forgotten first (audit A-33); one forgotten may be reported again, which the history takes as the alert still open.
   - Memory is bounded: 1024 app and domain pairs at most; the one heard from least recently is forgotten first.
3. **Encrypted DNS of the app's own** (`own-encrypted-dns`, **Info**), when an app connects to:
   - anything on port 853 (DNS over TLS or QUIC);
   - a well-known public resolver on port 443, by address: Cloudflare, Google, Quad9, OpenDNS, AdGuard;
   - a server named as a known encrypted DNS service, by its DNS name or its TLS server name: those above, NextDNS, CleanBrowsing, Mullvad, Control D.
   - Reported once per app per run, with the server.
4. **What is not counted:**
   - system apps, as for DL-04 (ADR-0031). Android's own Private DNS is the system's, and some makers' security tools look things up in DNS;
   - lookups and connections the firewall blocked;
   - lookups of no known app.
5. Both alerts name the app and what was seen, and offer to block the app or look at it. Their texts say who else does this: some security apps for the first, browsers and privacy apps for the second.

## Verification

- `sentinel-vpn`: a query is read with its name and type.
- `sentinel-detect`, the DNS-tunnel simulation:
  - a different base32-encoded name every 3 s under one domain is found at the twentieth, once;
  - 30 TXT lookups in 5 minutes are found at the twentieth.
- `sentinel-detect`, what is not found:
  - 1000 ordinary lookups, including long or hashed names used again and again (`*.apps.googleusercontent.com`, CloudFront, YouTube);
  - one encoded name a minute;
  - the same encoded name repeated;
  - two apps sharing the lookups.
- `sentinel-detect`, other checks:
  - names are split from their domain; words and hostnames do not look random, encoded data and hex do;
  - memory stays bounded;
  - encrypted DNS is known by port, name and address; plain DNS and other HTTPS are not;
  - the stored JSON of each evidence is fixed.
- `sentinel-ffi`, through the flow observer and the history:
  - an app's tunnel lookups raise one Warning naming the domain, and a system app's identical lookups raise none;
  - three apps reaching encrypted DNS by address, by TLS server name and on port 853 raise one Info alert each.
- `RtlTest.dnsTunnelAlert` and `RtlTest.ownEncryptedDnsAlert`: the alerts in Arabic, right to left.

## Consequences

- **A slow tunnel is missed.** Fewer than 20 names in 10 minutes, such as a check-in once a minute through DNS, is not found. Its lookups are still recorded and matched against indicators.
- **Some ordinary services look random.** Ad frames under `*.safeframe.googlesyndication.com`, for example, use hashed names; an app showing 20 ads in 10 minutes could raise a Warning. "Not useful" quiets it for that app. The thresholds should be checked on the reference phones with their common apps.
- **Encrypted DNS is known only from a list** of public services and port 853. A private DoH server on an ordinary HTTPS address is not found. The list is in the code; it could later come with the feed.
- **Patterns are not kept across runs**, as for DL-04.
