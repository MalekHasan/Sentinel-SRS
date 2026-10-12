# Sentinel — Software Requirements Specification (all editions, including Windows)

Version 1.0 draft · Oct 12, 2026 · @naseem

## 1. Introduction

Sentinel lets people see every network connection and sensor access on devices they own, trace where data goes, and block suspicious activity. It ships as six editions on one shared core: Android, iOS companion, smart TV (on-TV agent and viewer), Network Sentinel (home gateway), Windows, and macOS/Linux. The Windows edition is new in this SRS and gets the deepest detail. Sentinel is defensive and complements built-in protection (Microsoft Defender, Google Play Protect, XProtect) rather than replacing it.

### 1.1 Purpose

This SRS defines the functional and non-functional requirements, interfaces, data model and acceptance criteria for every Sentinel edition, so engineering can build them without re-deciding anything. Shared requirements apply to all editions. Where an edition differs, the requirement names the platform.

### 1.2 Scope

In scope:

- All six editions listed above, sharing one Rust core for event normalisation, correlation, inference, tracing and storage.

* Monitoring of all inbound and outbound connections per process, with DNS names, byte counts and destination tracing.
* Monitoring of microphone, camera, location and screen-capture use per app.
* Detection of likely data leaks and of intrusion attempts against the device.
* Highest priority: checks for known state-grade spyware (Pegasus, Predator, Graphite and others) from outside the suspected device (section 8A).
* User-controlled response: block, isolate, stop, quarantine, roll back settings.

Out of scope: monitoring other people or other devices, decrypting third-party traffic, offensive or counter-attack features, and enterprise fleet management (a later product).

### 1.3 Honest security boundary

No product can guarantee to stop every attack. Sentinel detects and blocks defined classes of activity (section 8 and 9). An attacker who already holds administrator or kernel-level control can disable any user-installed tool. The UI must state this plainly and recommend Defender, updates, BitLocker and MFA alongside it.

### 1.4 Definitions

| Term | Meaning |
| --- | --- |
| Flow | One network conversation: process, local and remote endpoint, protocol, start/end, bytes |
| Sensor event | Start or stop of microphone, camera, location or screen-capture access by an app |
| Alert | A user-facing finding with a severity, evidence and suggested actions |
| Response action | A change Sentinel makes on the user's approval (or by a rule the user enabled) |
| ETW | Event Tracing for Windows |
| WFP | Windows Filtering Platform |

### 1.5 References

- Sentinel product specification (sections 1 to 12, mobile and TV editions) and roadmap, from this conversation.
- Microsoft documentation for WFP, ETW, Windows Security auditing and Defender interfaces (to be linked by the engineering team at design time).

## 2. Overall description

Each edition is a thin platform layer of collectors and UI on top of the shared core. On Windows, Sentinel runs as a privileged service with a signed network filter driver and a per-user desktop app. On every edition, all processing stays on the device or the user's own gateway.

### 2.1 User classes

| User | Needs | Default mode |
| --- | --- | --- |
| Home user | Plain-language alerts, one-click fixes, little tuning | Guided |
| Privacy-conscious user | See every connection, approve new apps, trace destinations | Prompt |
| Power user / IT hobbyist | Raw flow log, custom rules, export | Expert |
| Shared-PC household | Per-Windows-account view, admin-only settings | Guided |

### 2.2 Editions

| Edition | Platforms | Visibility | Main limits |
| --- | --- | --- | --- |
| Windows | Windows 10 22H2, Windows 11 23H2+ (x64, ARM64) | Full: per-process flows, DNS, sensors, security events, blocking | Admin/kernel-level attacker can disable it |
| Android | Android 10+ (12+ recommended) | Per-app flows via local VPN; sensors basic, or exact with ADB grant | Some system traffic bypasses the VPN |
| iOS companion | iOS 17+ | App Privacy Report analysis; domain view via on-device tunnel | No per-app live attribution |
| TV agent | Google TV, Android TV, Fire TV | Same as Android, 10-foot UI | ADB setup needed for full view |
| TV viewer | Samsung Tizen, LG webOS | Displays Network Sentinel data only | Cannot monitor on its own |
| Network Sentinel | Raspberry Pi 4/5, OpenWrt routers, always-on PC | DNS and flow metadata for every device on the home network | Sees only traffic that passes through it |
| macOS / Linux | macOS 13+, Ubuntu 22.04+ / Fedora 39+ | Near Windows parity (Network Extension; eBPF) | Delivered after Windows |

### 2.3 Windows operating environment

| Item | Requirement |
| --- | --- |
| OS | Windows 10 22H2 (x64), Windows 11 23H2 and later (x64 and ARM64) |
| Editions | Home, Pro, Enterprise, Education |
| Hardware | 4 GB RAM minimum, 8 GB recommended; 500 MB disk plus log storage |
| Security features | Must run with HVCI / Memory Integrity, Secure Boot, Smart App Control and Defender enabled |
| Form factors | Desktop, laptop, 2-in-1; battery and Modern Standby aware |
| Languages | English and Arabic (RTL) at launch |

### 2.4 Constraints

- Kernel components must be Microsoft attestation-signed and HVCI compatible.
- Must coexist with Windows Defender Firewall and third-party antivirus; Sentinel never disables them.
- No cloud processing of user data; optional downloads only for signed rule and threat-intel updates.
- Install and response actions that change system state require administrator consent (UAC).
- Android: Google Play VpnService policy declaration (device security use case); no Accessibility API use.
- iOS: Network Extension entitlement from Apple; App Store privacy labels.
- TV: store review on Google Play (TV), Amazon Appstore, Samsung and LG stores.
- macOS: system extension and notarization approval.

### 2.5 Assumptions

- The user owns or is authorised to administer the device.
- The machine is not already compromised at kernel level at install time; Sentinel reports if it detects signs of this.
- Most traffic is TLS/QUIC encrypted; Sentinel works from metadata, not content.

## 3. System architecture

Every edition has the same four layers: platform collectors, the shared core, a privileged control service, and the UI. Only the collectors and the UI change per platform.

### 3.1 Layers

| Layer | Responsibility | Language |
| --- | --- | --- |
| Collectors | Turn OS signals (network, DNS, sensors, devices, security events) into normalised events | Platform-native: C (Windows driver), Rust (Windows service), Kotlin (Android), Swift (Apple), eBPF/Rust (Linux, gateway) |
| Shared core | Normalisation, correlation, inference, destination tracing, rule engine, risk scoring, encrypted storage | Rust, one crate set for all editions |
| Control service | Owns privileges, applies response actions, keeps the audit and rollback journal | Rust |
| UI | Live view, timeline, alerts, settings, reports | WinUI 3 (Windows), Jetpack Compose (Android, TV), SwiftUI (Apple), web UI for gateway and Tizen/webOS viewer |

### 3.2 Windows components

| Component | Runs as | Role |
| --- | --- | --- |
| `SentinelFlt.sys` | Kernel, WFP callout driver | Per-connection authorisation (allow, block, ask), flow byte accounting, first-packet metadata for SNI |
| `SentinelSvc.exe` | Windows service, LocalSystem | Hosts collectors and shared core, applies rules and response actions, manages the driver |
| `SentinelApp.exe` | Per user, medium integrity | WinUI 3 desktop app, tray icon, toast notifications, connection prompts |
| `SentinelUpd.exe` | Scheduled task, LocalSystem | Fetches and verifies signed rule, threat-intel and app updates |

### 3.3 Other editions

- **Android / TV agent:** one foreground service hosting the local VpnService engine, sensor collectors and core via JNI.
- **iOS companion:** app plus on-device packet tunnel extension; report importer.
- **Network Sentinel:** headless daemon (DNS resolver, flow collector) with a local HTTPS API and web UI.
- **macOS:** Network Extension filter plus system extension; **Linux:** eBPF collectors plus nftables for blocking.

### 3.4 Event flow

1. A collector emits a raw event (flow start, DNS answer, sensor start, security log entry).
2. The core normalises it to the common schema (section 13) and attaches the process or app identity.
3. The correlation engine joins it with related events within a time window (e.g. microphone start and an upload by the same process).
4. Detection rules and the risk scorer produce zero or more alerts.
5. The alert manager notifies the UI; response actions run only on user approval or a rule the user enabled.
6. Everything is written to the encrypted store and the audit journal.

### 3.5 Design principles

- Local-only processing; no telemetry.
- Fail open on network: if Sentinel crashes, connectivity continues and a monitoring gap is recorded.
- Least privilege: the UI never runs elevated; only the service can change system state.
- Every automated action is reversible and logged.

## 4. Data collection layer

Each signal comes from a documented OS interface. No edition relies on undocumented hooks, exploits or root/jailbreak.

### 4.1 Windows sources

| Signal | Source | Notes |
| --- | --- | --- |
| Connection attempts and decisions | WFP ALE connect / accept layers via `SentinelFlt.sys` | Gives process ID, app path, user SID, endpoints; can pend for a user prompt |
| Bytes per flow | WFP flow context counters; ETW `Microsoft-Windows-Kernel-Network` as fallback | Up/down totals and timing |
| DNS names | ETW `Microsoft-Windows-DNS-Client` | Query, answer, requesting process |
| TLS SNI / QUIC hostname | First client packet seen at the WFP stream/datagram layer (read-only, metadata only) | No decryption, no payload storage |
| Process identity | Driver process-creation callback; ETW `Microsoft-Windows-Kernel-Process` | Path, hash, signer (WinVerifyTrust), parent, command line |
| Microphone, camera, location, screen capture | `CapabilityAccessManager\ConsentStore` usage timestamps (registry change notifications); WASAPI `IAudioSessionManager2` capture sessions for live mic PID | Desktop and Store apps |
| Devices | WinRT `DeviceWatcher` (USB, Bluetooth, HID), PnP events | New keyboard, storage, network adapter |
| Network context | `INetworkListManager`, WLAN API | Network profile (public/private), SSID, gateway MAC, DNS servers |
| Security events | Windows Event Log subscriptions: Security, System, Defender Operational, PowerShell Operational, Firewall | See section 8 for event IDs |
| Persistence state | Registry Run keys, services, scheduled tasks, startup folders, browser extensions | Snapshot + change notifications |
| Optional deep telemetry | Sysmon (standalone or the Windows built-in feature where available) with a Sentinel config | Opt-in, Expert mode |

### 4.2 Android and TV agent sources

| Signal | Source |
| --- | --- |
| Flows, DNS, SNI | Local `VpnService` + `ConnectivityManager.getConnectionOwnerUid` |
| Per-app data totals | `NetworkStatsManager` (Usage Access) |
| Mic / camera (basic) | `AudioManager` recording callback, `CameraManager` availability callback, foreground app |
| Mic / camera (exact) | App-ops history, after the user grants `GET_APP_OPS_STATS` over ADB |
| Posture | Package manager, device policy, enabled accessibility and notification-listener services, user CA store |

### 4.3 iOS companion sources

- App Privacy Report export (user-initiated JSON): per-app sensor and domain access.
- Packet tunnel extension: domains and byte counts, without per-app attribution.
- Configuration-profile and VPN state where APIs allow.

### 4.4 Network Sentinel sources

- DNS resolver logs, conntrack / NetFlow flow records, TLS SNI from first packets.
- DHCP, mDNS and SSDP for device identification.

### 4.5 macOS and Linux sources

- macOS: Network Extension content filter, unified log (TCC and sensor indicator), Endpoint Security framework (with entitlement).
- Linux: eBPF socket and process probes, PipeWire/PulseAudio clients, `/dev/video*` open handles, udev, journald.

## 5. FR: Connection monitoring and interactive firewall

Sentinel records every connection with its owning app and lets the user decide which apps may reach the network.

| ID | Requirement | Editions | Acceptance criterion |
| --- | --- | --- | --- |
| CM-01 | Record every TCP, UDP and QUIC flow with process/app, endpoints, protocol, interface, start/end, bytes up/down | All | 100% of flows in the test suite appear within 1 s |
| CM-02 | Attach DNS name and TLS SNI to each flow, recording which source supplied the name | All | Hostname present for ≥ 95% of TLS flows without ECH |
| CM-03 | Show a live connections view grouped by app, refreshed at least every 1 s | All | Verified under 500 concurrent flows |
| CM-04 | Flag first-ever network use by an app and first-seen destinations per app | All | Alert raised on first run of a new test binary |
| CM-05 | Record inbound connections and listening ports with the owning process | Windows, macOS, Linux, Android | New listener alert within 2 s |
| CM-06 | Show traffic while the user is away: screen locked, lid closed, Modern Standby, TV standby | All | Separate "while away" counter per app |
| CM-07 | Alert on changes to DNS servers, proxy settings, VPN state, hosts file and network profile | Windows, macOS, Android | Change detected within 5 s |
| CM-08 | Firewall modes: Monitor (log only), Prompt (ask for unknown apps), Block unknown, Lockdown (only allow-listed apps) | Windows, macOS, Linux, Android | Mode switch takes effect within 1 s |
| CM-09 | Prompt shows app name, signer, path, destination, company and country, with Allow once / Allow always / Block / Block always | Windows, macOS | Prompt appears within 500 ms; connection held, default deny after 60 s |
| CM-10 | Rules by app (path + signer + hash), destination (IP, CIDR, domain, company, country), port, direction, network profile | Windows, macOS, Linux, Android | Rule engine unit tests cover each field |
| CM-11 | Rules are tied to the signer and hash, so a replaced binary loses its allow rule | Windows, macOS, Linux | Modified binary triggers a new prompt |
| CM-12 | Coexist with Windows Defender Firewall: Sentinel uses its own WFP sublayer and never changes or disables Defender Firewall rules | Windows | Defender Firewall rules unchanged after install and uninstall |
| CM-13 | Network Sentinel records flows for every LAN device and labels devices by fingerprint | Gateway | ≥ 90% of reference devices labelled correctly |

## 6. FR: Microphone, camera, screen, location and sensor monitoring

Sentinel shows which app used which sensor, when, for how long, and whether the user was present.

| ID | Requirement | Editions | Acceptance criterion |
| --- | --- | --- | --- |
| SE-01 | Record start and stop of microphone and camera access per app | Windows, macOS, Linux, Android (exact with ADB grant), TV agent | Start/stop logged within 2 s; app identified correctly in 100% of test apps |
| SE-02 | Record location and programmatic screen-capture access per app where the OS exposes it | Windows 11, macOS, Android | Logged within 5 s |
| SE-03 | Show a persistent "in use now" indicator in the tray / notification while any sensor is active | All with UI | Indicator visible within 1 s |
| SE-04 | Flag sensor use while the screen is locked, the session is idle > 5 min, the lid is closed, or the app has no visible window | Windows, macOS, Android | High-severity alert in test scenario |
| SE-05 | Flag sensor use by an app that never used that sensor before, or is unsigned, or runs from a user-writable folder | Windows, macOS, Linux | Alert raised for unsigned test binary |
| SE-06 | Distinguish the remote's push-to-talk mic from the TV's far-field mic | TV agent | Correct source on reference TVs |
| SE-07 | Import and analyse the iOS App Privacy Report | iOS companion | Parses Apple's export format; per-app timeline shown |
| SE-08 | Report the state of hardware privacy controls where readable (camera shutter, mic mute key) | Windows laptops, TV | Shown where driver exposes it |
| SE-09 | Monitor new HID keyboards and input devices and alert when one appears | Windows, macOS, Linux | Alert within 2 s of plug-in |

**Known gaps (shown in the app):** Windows does not report every legacy screen-capture method or clipboard reader to third-party apps. Sentinel shows these as "not observable" instead of implying they're safe.

## 7. FR: Data-leak and exfiltration detection

Sentinel flags data leaving the device in ways that don't match how the app normally behaves. Each finding shows its evidence and a confidence level. Detection is based on metadata and behaviour, never on reading content.

| ID | Requirement | Editions | Acceptance criterion |
| --- | --- | --- | --- |
| DL-01 | Correlate sensor use with uploads by the same app (live audio, live video, photo upload, recorded-audio upload, screen streaming) using the inference table from spec section 6.4 | All | ≥ 85% precision on labelled test sessions |
| DL-02 | Baseline each app's normal upload volume, destinations and hours; alert on large deviations | All | Alert on 10× upload over a 14-day baseline |
| DL-03 | Alert when a non-browser process reads browser credential or cookie stores, password-manager vaults, SSH keys or crypto-wallet files and then connects out within a short window | Windows, macOS, Linux | Detected in the infostealer simulation test |
| DL-04 | Detect regular beacon-like traffic (fixed interval, low jitter, small payloads) from non-system apps | All | Detected in the beacon simulation test; < 5% false-positive rate on reference apps |
| DL-05 | Detect unusual DNS use: very long or high-entropy subdomains, high TXT query volume, or an app using its own encrypted DNS to bypass the system resolver | All | Detected in the DNS-tunnel simulation test |
| DL-06 | Flag uploads to file-sharing, paste and anonymous-hosting services by apps not normally associated with them | All | Category list from destination tracing |
| DL-07 | Flag network use by unsigned binaries running from Temp, Downloads or AppData | Windows | Alert on test binary |
| DL-08 | Flag large outbound transfers to removable storage or newly paired Bluetooth devices | Windows, macOS, Android | Alert on > 500 MB copy to new USB drive (threshold configurable) |
| DL-09 | Flag ACR (viewing-data reporting) and standby uploads from TVs | TV agent, Network Sentinel | Detected on reference TVs |
| DL-10 | Every DL alert lists the app, destination company, bytes, time window and the signals that triggered it | All | UI review |

## 8. FR: Intrusion and hacking-attempt detection

Sentinel detects common signs that someone is trying to get into or take control of the device, using standard OS logs and its own network view. Detection rules are written in Sigma-compatible YAML so they can be reviewed and updated as signed data.

### 8.1 Network-facing attempts

| ID | Requirement | Editions | Signal |
| --- | --- | --- | --- |
| ID-01 | Detect repeated failed sign-ins over the network (RDP, SMB, SSH) | Windows, macOS, Linux | Windows Security 4625 (logon types 3 and 10); sshd logs |
| ID-02 | Detect port scans and repeated blocked inbound attempts from one source | All except iOS | Sentinel filter drops; Windows Filtering Platform audit 5152/5157 if enabled |
| ID-03 | Alert when remote-access services become exposed (RDP, SSH, SMB, WinRM, ADB over network) | Windows, macOS, Linux, Android, TV | Listener on known ports + firewall profile |
| ID-04 | Detect local network threats: gateway MAC change, rogue DHCP server, DNS resolver change, Wi-Fi network with known SSID but weaker security | Windows, macOS, Android, Network Sentinel | Network context collector |
| ID-05 | Warn when connected to a public network with file sharing or discovery enabled | Windows | Network profile + sharing settings |

### 8.2 On-device compromise signs

| ID | Requirement | Editions | Signal |
| --- | --- | --- | --- |
| ID-06 | New local admin account or user added to Administrators | Windows | Security 4720, 4732 |
| ID-07 | New service, scheduled task, Run key, startup item or browser extension | Windows, macOS, Linux | System 7045, Security 4698, registry and folder watchers |
| ID-08 | Security log cleared or audit policy changed | Windows | Security 1102, 4719 |
| ID-09 | Defender detection, Defender real-time protection turned off, or exclusions added | Windows | Defender Operational 1116, 5001, 5007 |
| ID-10 | New trusted root certificate installed | Windows, macOS, Android | Certificate store change watcher |
| ID-11 | Suspicious script activity flagged by the OS (PowerShell script-block warnings, AMSI detections) | Windows | PowerShell Operational 4104 (warning level) |
| ID-12 | Accessibility, device-admin or notification-listener permission granted to a non-allow-listed app | Android, TV agent | Package and policy state |
| ID-13 | Known stalkerware and remote-access-tool signatures | All | Signed IOC list |
| ID-14 | Sentinel's own components stopped, driver unloaded or settings changed outside the app | All | Self-protection heartbeat (section 15) |

### 8.3 Severity mapping

- **Critical:** IOC match, security log cleared, Defender disabled, Sentinel tampered with.
- **High:** successful sign-in after many failures, new admin account, new root certificate, sensor use while locked plus upload.
- **Warning:** new persistence entry, exposed remote-access service, port scan.
- **Info:** first-seen destination, new device on network.

## 8A. FR: Advanced state-grade (mercenary) spyware

This is Sentinel's highest-priority protection area. Spyware such as Pegasus can take full control of a phone, so Sentinel never relies on the suspected device to report on itself. It checks from **outside**: the home gateway, a trusted PC, and published forensic indicators. A result can show that known traces were found. It can never prove a device is clean.

### 8A.1 Covered spyware families

| Family | Vendor (public attribution) | Platforms | Public indicator sources |
| --- | --- | --- | --- |
| Pegasus | NSO Group | iOS, Android | Amnesty Tech, Citizen Lab |
| Predator | Cytrox / Intellexa | iOS, Android | Citizen Lab, Amnesty Tech, Google TAG |
| Graphite | Paragon Solutions | iOS, Android | Citizen Lab |
| Reign | QuaDream | iOS | Citizen Lab, Microsoft |
| Hermit | RCS Lab | Android, iOS | Lookout, Google TAG |
| DevilsTongue | Candiru | Windows | Microsoft, Citizen Lab |
| FinSpy | FinFisher | Windows, macOS, Linux, Android, iOS | Amnesty Tech, Kaspersky |
| Operation Triangulation | Unattributed | iOS | Kaspersky |

The list is data, not code. New families are added through the signed indicator feed (MS-10) without an app release.

### 8A.2 Requirements

| ID | Requirement | Editions | Acceptance criterion |
| --- | --- | --- | --- |
| MS-01 | Match every DNS lookup and flow from every home device against the mercenary-spyware indicator list (domains, IPs, certificate fingerprints) | Network Sentinel | Match on a planted test indicator alerts within 5 s |
| MS-02 | **Retro-hunt:** when new indicators arrive, re-check stored DNS and flow history and alert on past matches with dates and device | Network Sentinel, Windows, macOS, Android | Past test record matched after feed update |
| MS-03 | Keep a minimal DNS history (hostname, time, device) for 12 months in High-risk mode so retro-hunts are possible | Network Sentinel, Windows, macOS | Configurable 3–24 months, encrypted |
| MS-04 | **Phone check from a PC:** guided scan of an iPhone encrypted backup or diagnostic dump, and an Android bug report or acquisition, using Amnesty's open-source Mobile Verification Toolkit (MVT) and AndroidQF as bundled engines | Windows, macOS, Linux | Detects all public MVT test cases; runs fully offline |
| MS-05 | The backup password is typed into the scan engine by the user, used in memory only, never stored; the decrypted backup is deleted after the scan | Windows, macOS, Linux | Verified by file-system audit after scan |
| MS-06 | **Desktop self-check** for families that target PCs: published file hashes, driver names, persistence paths and domains; YARA scan of user-writable folders with published rules (opt-in) | Windows, macOS, Linux | Detects planted test indicators |
| MS-07 | Check kernel-level exposure on PCs: Memory Integrity, Secure Boot, Microsoft vulnerable-driver blocklist enabled, unknown or unsigned kernel drivers loaded | Windows | Shown on posture page; unknown driver raises High |
| MS-08 | **Out-of-band alerts:** a spyware match for a phone is shown on the PC, gateway web UI or a second paired device, never only on the suspected phone | Network Sentinel, Windows, macOS | Alert delivered to a second device |
| MS-09 | Behavioural flags from the gateway: a phone uploading while idle overnight, contacting newly registered domains or rare hosting networks, or sudden changes in a phone's traffic pattern | Network Sentinel | < 1 false alert per device per week on baseline |
| MS-10 | Signed indicator feed built from public sources, with provenance (source, date, report link) on every indicator; weekly updates and urgent same-day updates | All | Feed signature and provenance checked on load |
| MS-11 | **High-risk mode** for journalists, activists, lawyers and officials: longer DNS history, weekly phone-check reminders, daily-restart reminder, stricter gateway rules, helpline links | All | One switch enables the full profile |
| MS-12 | **Hardening checklist** with guided steps: iOS Lockdown Mode, Android Advanced Protection, automatic updates, Windows Smart App Control and Memory Integrity, disabling unused messaging apps | All | Each item shows current status where readable, else a manual check |
| MS-13 | When a match is found: advise the user not to wipe or reset the device yet (evidence is lost), to move sensitive conversations to a different device, and to contact Access Now Digital Security Helpline or Amnesty Tech | All | Shown on every MS alert |
| MS-14 | **Evidence package:** user-initiated, encrypted export of the matching records, scan reports and timeline for sharing with an expert helpline | Windows, macOS, Network Sentinel | Package opens with standard tools; nothing sent automatically |
| MS-15 | Result wording: "Known traces found" or "No known traces found", with the date of the indicator list used; never "clean" or "safe" | All | UI copy review |

### 8A.3 What this cannot do

- Detect new or unpublished spyware on the infected phone itself in real time.
- See traffic sent over mobile data, unless the phone is later checked with MS-04.
- Find infections that left no known trace or were removed before the scan.

The app shows these three points before the first phone check and on every "No known traces found" result.

## 9. FR: Response and prevention actions

The user can stop a threat from the alert with one click. Every action is limited to the user's own device, is logged, and can be undone except where noted.

| ID | Action | Editions | Reversible | Default trigger |
| --- | --- | --- | --- | --- |
| RA-01 | Block a connection, an app's network access, a destination, a company or a country | All except iOS (domain-level only) | Yes | User, or a rule the user enabled |
| RA-02 | Temporarily ban a remote IP after repeated failed sign-ins (configurable threshold and duration) | Windows, macOS, Linux | Yes, auto-expires | Opt-in auto rule |
| RA-03 | Network isolation: block all traffic except Sentinel updates, DNS and allow-listed apps | Windows, macOS, Linux, Android | Yes, one click | User |
| RA-04 | Turn off microphone or camera for one app (OS privacy setting) or for all apps | Windows, macOS, Android | Yes | User |
| RA-05 | Suspend or end a process | Windows, macOS, Linux | Suspend: yes; end: no | User |
| RA-06 | Quarantine a file: move to a protected folder, strip execute rights, record hash | Windows, macOS, Linux | Yes | User |
| RA-07 | Hand a file to the built-in antivirus for scanning (Defender custom scan on Windows) | Windows, macOS | n/a | User or High alert |
| RA-08 | Remove a persistence entry (Run key, task, service, startup item, extension) with backup | Windows, macOS, Linux | Yes, from backup | User |
| RA-09 | Restore changed DNS, proxy, hosts file or network profile to the last known good state | Windows, macOS, Android | Yes | User |
| RA-10 | Close an exposed remote-access service (turn off RDP, network ADB, file sharing) | Windows, Android, TV agent | Yes | User |
| RA-11 | Remove an untrusted root certificate added after install | Windows, macOS | Yes, from backup | User |
| RA-12 | Block a newly attached input or storage device until the user approves it | Windows | Yes | Opt-in |
| RA-13 | Guide steps the app can't do itself (change passwords, enable MFA, contact bank) | All | n/a | Shown with Critical alerts |

**Rules for actions**

- Actions run in `SentinelSvc` only, after a UAC-backed approval for anything that changes system state.
- Each action writes a journal entry: who, what, when, before-state, after-state, and how to undo it.
- Automatic actions are off by default except firewall decisions in Block-unknown or Lockdown mode.
- Sentinel never acts against remote systems (no counter-scanning or retaliation).

## 10. FR: Destination tracing

For every flow, Sentinel answers which company received the data, what kind of company it is, and roughly where its server is, each with a confidence level. It can't see what happens to the data after it arrives.

| ID | Requirement | Editions | Acceptance criterion |
| --- | --- | --- | --- |
| DT-01 | Enrich each flow with ASN, network owner, resolved company, category and approximate country from bundled offline databases | All | No network lookup needed; enrichment < 1 ms per flow |
| DT-02 | Show the source and confidence of each field ("why we believe this") | All | Visible on every destination card |
| DT-03 | Opt-in RDAP/WHOIS lookup for unknown domains, with a warning that the registry sees the query | All | Off by default |
| DT-04 | Opt-in certificate check: open Sentinel's own TLS connection to the same host to read the certificate organisation; cache per destination | Windows, macOS, Linux, Android, Gateway | At most one check per destination per 7 days |
| DT-05 | On-demand traceroute with ASN and country per hop, and a latency sanity check against the claimed location | Windows, macOS, Linux, Gateway | Path shown within 30 s |
| DT-06 | Match app destinations to known SDKs (ads, analytics, crash reporting) | All | Uses signed SDK signature list |
| DT-07 | Show companies reached by several apps or devices (cross-app tracking) | All | Household view on Gateway |
| DT-08 | Destination views: card per destination, Sankey from apps to companies to countries, map with "approximate" labels | All with UI | UI review |
| DT-09 | Alert when an app's destination company changes after an update, or when data goes to a company unrelated to the app's developer | All | Alert in test scenario |

**Data sources (license check required in Phase 0):** IP-to-ASN data, GeoLite2 or DB-IP Lite geolocation, a tracker/entity list (DuckDuckGo Tracker Radar is CC BY-NC-SA, so it needs a commercial license or a substitute for a paid product), Exodus Privacy SDK signatures, and Sentinel's own curated TV and ACR list.

## 11. FR: Device-specific requirements

The same rules behave differently depending on the device's form factor, power source and where it is used.

| ID | Requirement | Device | Acceptance criterion |
| --- | --- | --- | --- |
| DV-01 | Switch to a stricter profile automatically on public or unknown Wi-Fi (Prompt mode, inbound blocked, sharing warnings) | Laptop, phone | Profile applied within 2 s of joining |
| DV-02 | Reduce collection detail on battery below 20% while keeping alerts for High and Critical events | Laptop, phone | Overhead drop measured in battery test |
| DV-03 | Monitor traffic during Modern Standby, sleep and lid-closed states, and report it as "while away" | Laptop | Standby traffic visible after resume |
| DV-04 | Resume cleanly after sleep, hibernate and network changes without losing rules | Laptop | 100 sleep/resume cycles without failure |
| DV-05 | Report status of Kernel DMA Protection, BitLocker, Secure Boot and Memory Integrity | Laptop, desktop | Shown on the posture page |
| DV-06 | Handle multiple network adapters, Wake-on-LAN and always-on use | Desktop | Rules apply per adapter and profile |
| DV-07 | Support several Windows user accounts: per-user views, admin-only settings, fast user switching | Desktop, laptop | Each user sees only their own sessions' sensor history |
| DV-08 | Use a 10-foot UI and mirror High and Critical alerts to the phone companion | TV | Alert on phone within 5 s |
| DV-09 | Keep CPU ≤ 3% and RAM ≤ 50 MB during 4K playback | TV agent | No dropped frames in playback test |
| DV-10 | Show a monitoring-gap warning when the gateway is offline or the device leaves the home network | Network Sentinel | Gap recorded and shown |

## 12. FR: Alerts, UI and reporting

Alerts must be few, clear and actionable. Users should be able to understand each one without technical knowledge.

### 12.1 Alerts

| ID | Requirement | Acceptance criterion |
| --- | --- | --- |
| AL-01 | Four severities (Info, Warning, High, Critical) with distinct sound and visual style | UI review |
| AL-02 | Plain-language title and one-sentence explanation, then evidence, then actions (from section 9) | Readability grade ≤ 8 in English |
| AL-03 | Group repeated alerts; rate-limit to ≤ 3 non-critical notifications per hour per app | Load test |
| AL-04 | Quiet hours and Focus/Do Not Disturb respected, except High and Critical | Test with Windows Focus on |
| AL-05 | Allow-list and "not useful" feedback on every alert; feedback tunes local thresholds only | Feedback stored locally |
| AL-06 | Delivery: Windows toast (App SDK notifications) and tray badge; Android notification channels; TV overlay plus phone mirror; gateway web UI and phone push via the companion app | Per-edition test |

### 12.2 Screens

- **Dashboard:** risk score, sensors in use now, active connections, today's top apps by data sent, open alerts.
- **Connections:** live and historical flows with filters (app, destination, company, country, direction, time).
- **Timeline:** sensor lanes and network lanes on one time axis, zoomable from 1 minute to 30 days.
- **App detail:** signer, path, permissions, destinations, sensor history, rules, inferences.
- **Destinations:** cards, Sankey, map (section 10).
- **Security:** intrusion alerts, posture checks, persistence list, journal of actions with Undo.
- **Rules and settings:** firewall mode, rules editor, retention, updates, privacy options.

### 12.3 Reports

- Weekly summary (in-app and optional PDF) with personal identifiers removed unless the user includes them.
- Export of flows, alerts and actions to JSON and CSV.
- Incident report for a selected alert: timeline, evidence, actions taken, suggested next steps.

### 12.4 Accessibility and language

WCAG 2.2 AA, full keyboard navigation, Narrator/TalkBack support, high-contrast themes, English and Arabic with RTL layout.

## 13. Data model and storage

All editions use one schema in an encrypted SQLite database (SQLCipher). The key is held by the platform key store: DPAPI-NG with TPM on Windows, Android Keystore, Secure Enclave on Apple, TPM or a file key with restricted permissions on Linux and the gateway.

### 13.1 Core tables

```sql
CREATE TABLE app (
  id INTEGER PRIMARY KEY, platform TEXT, identifier TEXT,   -- path or package
  signer TEXT, sha256 TEXT, first_seen INTEGER, trust TEXT  -- trusted|unknown|blocked
);
CREATE TABLE flow (
  id INTEGER PRIMARY KEY, app_id INTEGER REFERENCES app(id), user_sid TEXT,
  proto TEXT, direction TEXT, local_ip TEXT, local_port INTEGER,
  remote_ip TEXT, remote_port INTEGER, hostname TEXT, hostname_src TEXT, -- dns|sni|rdns
  iface TEXT, net_profile TEXT, started INTEGER, ended INTEGER,
  bytes_up INTEGER, bytes_down INTEGER, while_away INTEGER, verdict TEXT  -- allowed|blocked|prompted
);
CREATE TABLE destination (
  hostname TEXT PRIMARY KEY, etld1 TEXT, asn INTEGER, net_owner TEXT,
  company TEXT, category TEXT, country TEXT, confidence REAL, updated INTEGER
);
CREATE TABLE sensor_use (
  id INTEGER PRIMARY KEY, app_id INTEGER, sensor TEXT, -- mic|camera|location|screen
  started INTEGER, ended INTEGER, user_present INTEGER, source TEXT
);
CREATE TABLE device_event (
  id INTEGER PRIMARY KEY, kind TEXT, -- usb|bt|hid|nfc|lan_device
  peer_id TEXT, peer_name TEXT, detail TEXT, at INTEGER
);
CREATE TABLE security_event (
  id INTEGER PRIMARY KEY, source TEXT, event_id INTEGER, at INTEGER, summary TEXT, raw TEXT
);
CREATE TABLE alert (
  id INTEGER PRIMARY KEY, rule_id TEXT, severity TEXT, title TEXT, body TEXT,
  evidence TEXT, -- JSON array of entity references
  created INTEGER, state TEXT, user_feedback TEXT
);
CREATE TABLE action_journal (
  id INTEGER PRIMARY KEY, alert_id INTEGER, action TEXT, actor TEXT,
  before_state TEXT, after_state TEXT, undo TEXT, at INTEGER, undone_at INTEGER
);
CREATE TABLE rule (
  id TEXT PRIMARY KEY, kind TEXT, -- firewall|detection|auto_response
  body TEXT, enabled INTEGER, source TEXT, version INTEGER
);
```

### 13.2 Retention and size

| Data | Default retention | Notes |
| --- | --- | --- |
| Flows | 30 days (1–365) | Older flows rolled up to daily totals per app and destination |
| Sensor and device events | 90 days | Small volume |
| Alerts and action journal | 1 year | Needed for undo and reports |
| Raw security events | 14 days | Only those matched by a rule |

Storage target ≤ 500 MB on Windows and ≤ 200 MB on mobile at default retention. One-tap wipe deletes the database and key.

## 14. Interfaces

Components talk over authenticated local channels only. The only outbound connection Sentinel makes by default is to its signed update feed.

### 14.1 Internal interfaces

| Interface | Between | Transport | Security |
| --- | --- | --- | --- |
| Driver control | `SentinelSvc` ↔ `SentinelFlt.sys` | Device IOCTL + inverted-call queue for pended connection decisions | Device object ACL: SYSTEM only |
| Service API | `SentinelApp` ↔ `SentinelSvc` | Named pipe, protobuf messages | Pipe ACL per user SID; caller identity checked on every call; system-changing calls need an elevated token |
| Event stream | `SentinelSvc` → `SentinelApp` | Same pipe, server-push | Each user receives only events for their own sessions plus system events |
| Mobile core | Kotlin / Swift ↔ Rust core | JNI / UniFFI bindings | In-process |
| Gateway API | Network Sentinel ↔ phone, PC, TV viewer | HTTPS on LAN, mutual TLS after QR pairing | Device-bound client certificates, revocable |

### 14.2 Service API (excerpt)

| Call | Purpose |
| --- | --- |
| `ListFlows(filter, page)` | Live and historical flows |
| `SubscribeEvents(kinds)` | Stream of flows, sensor events and alerts |
| `DecidePrompt(prompt_id, decision, scope)` | Answer a pended connection |
| `UpsertRule(rule)` / `DeleteRule(id)` | Rule management |
| `RunAction(action, target)` | Execute a response action (section 9) |
| `UndoAction(journal_id)` | Roll back an action |
| `GetPosture()` | Security-posture checks |
| `Export(range, format)` | JSON/CSV export |

### 14.3 Update interface

- Content: app binaries, detection rules, IOC lists, tracker and entity data, geolocation and ASN data.
- Transport: HTTPS with certificate pinning to Sentinel's update domain.
- Integrity: every bundle signed (Ed25519) with keys kept offline; version and rollback protection.
- Privacy: requests carry no device identifiers; users can update manually from a file.

### 14.4 Rule format

Detection rules use a Sigma-compatible YAML subset extended with Sentinel fields (flow, sensor, device). Example:

```yaml
id: sen-sensor-001
title: Microphone used while screen locked, then upload
severity: high
when:
  all:
    - sensor_use: { sensor: mic, user_present: false }
    - flow: { same_app: true, direction: out, bytes_up_gt: 500000, within_s: 600 }
actions_suggested: [block_app_network, revoke_mic]
```

### 14.5 External OS interfaces

Listed per platform in section 4.

## 15. Self-protection and security of Sentinel

Sentinel stores a detailed record of the user's behaviour, so it must be at least as hard to misuse as the threats it watches for. Its goal is to make tampering visible, not to promise it can't be done.

### 15.1 Tamper resistance and evidence

| ID | Requirement | Editions |
| --- | --- | --- |
| SP-01 | Service and driver run with restricted ACLs; only SYSTEM and elevated administrators can stop or reconfigure them | Windows |
| SP-02 | Service recovery restarts Sentinel after a crash; repeated stops raise a Critical alert | Windows, macOS, Linux, Android |
| SP-03 | Collector heartbeat: each collector reports every 10 s; a missing heartbeat is logged as a monitoring gap and alerted | All |
| SP-04 | Binary and rule-bundle signatures checked at start and every hour | All |
| SP-05 | Configuration stored in ACL-protected locations; changes outside the service API raise an alert | Windows, macOS, Linux |
| SP-06 | Later option: apply to Microsoft's antimalware programme to run as a protected service | Windows (Phase 6) |

### 15.2 Data protection

- Database encrypted at rest (section 13); key never leaves the platform key store.
- Optional app lock with Windows Hello, biometrics or PIN.
- Exports are user-initiated only, with a warning that they contain sensitive data.

### 15.3 Anti-abuse rules (release blockers)

- Always-visible tray icon or notification; no hidden or stealth mode.
- No remote viewing, remote control or sending data to another person's device. The gateway API serves only devices the owner paired.
- No content capture: no audio, video, screenshots, keystrokes or message bodies are recorded.
- Install requires the device's administrator; on shared PCs, every user sees a notice that Sentinel is running.

### 15.4 Secure development

- STRIDE threat model reviewed each phase; memory-safe Rust everywhere except the driver.
- Driver: static analysis (CodeQL, SDV), Driver Verifier and fuzzing of all IOCTLs.
- Dependency scanning, SBOM published per release, reproducible builds.
- External security audit before each public release; public vulnerability disclosure policy.

## 16. Non-functional requirements

Sentinel must be light enough that users forget it is running, until it matters.

| ID | Category | Requirement | Editions |
| --- | --- | --- | --- |
| NF-01 | Performance | Average CPU ≤ 2%, RAM ≤ 150 MB (service + UI idle) | Windows, macOS, Linux |
| NF-02 | Performance | Added connection-setup latency ≤ 1 ms p95 when no prompt is needed; throughput loss ≤ 3% at 1 Gbps | Windows, macOS, Linux |
| NF-03 | Performance | Battery overhead ≤ 3% per day | Android, laptops |
| NF-04 | Performance | Local VPN adds ≤ 5 ms p95 latency | Android, TV agent |
| NF-05 | Performance | Gateway handles 20 devices at 500 Mbps on a Raspberry Pi 4 | Network Sentinel |
| NF-06 | Latency | Alert shown ≤ 2 s after the triggering event | All |
| NF-07 | Reliability | Network fails open if Sentinel crashes; gap recorded | All |
| NF-08 | Reliability | Crash-free sessions ≥ 99.5%; no system crash (bugcheck) attributable to the driver in the test matrix | All / Windows |
| NF-09 | Compatibility | Works with HVCI, Secure Boot, Smart App Control, Defender, common VPN clients and third-party antivirus | Windows |
| NF-10 | Scalability | Handles 10,000 concurrent flows and 1,000 new flows per second without loss | Windows, macOS, Linux |
| NF-11 | Privacy | No telemetry; no user data leaves the device except what the user exports or opts into | All |
| NF-12 | Usability | First-run setup in ≤ 5 minutes; Guided mode raises ≤ 5 prompts in the first day | All |
| NF-13 | Maintainability | Shared core ≥ 80% unit-test coverage; rules and data updatable without an app release | All |
| NF-14 | Localisation | English and Arabic at launch; all strings externalised | All |
| NF-15 | Compliance | GDPR-aligned privacy notice; no special-category data processed off device | All |

## 17. Build, signing, packaging and deployment

Each edition ships through its platform's official channel, signed, with reproducible builds from one monorepo.

| Edition | Toolchain | Signing | Package / channel |
| --- | --- | --- | --- |
| Windows | Rust (MSVC), C/WDK for driver, .NET 8 + Windows App SDK for UI | EV code-signing certificate; driver attestation-signed via Microsoft Partner Center; x64 and ARM64 | MSI (WiX) with driver package; later Microsoft Store listing for the UI; winget manifest |
| Android / TV agent | Kotlin, Gradle, Rust via cargo-ndk | Play App Signing | Google Play (phone + TV), Amazon Appstore, F-Droid / direct APK |
| iOS companion | Swift, Xcode, Rust via UniFFI | Apple Developer ID | App Store |
| macOS | Swift, Rust | Developer ID + notarization | Signed DMG / PKG |
| Linux | Rust, libbpf | GPG-signed packages | .deb, .rpm, Flatpak for UI |
| Network Sentinel | Rust, cross-compiled (aarch64, OpenWrt targets) | Signed images and packages | Pi image, OpenWrt package feed, Docker image |
| TV viewer | Web app (Tizen / webOS SDKs) | Store signing | Samsung and LG app stores |

### 17.1 Windows install flow

1. MSI checks OS version, architecture and Memory Integrity compatibility.
2. Installs driver, service and update task; UAC consent required once.
3. First-run wizard: choose mode (Guided, Prompt, Expert), language, and optional features (Sysmon integration, certificate checks, RDAP).
4. Learning period (default 24 h in Guided mode): known-good signed apps are allowed and recorded, unknown apps prompt.
5. Uninstall removes driver, filters, service and, if the user chooses, all data. Defender Firewall is left exactly as before.

### 17.2 CI/CD

- Per-commit: build all editions, unit tests, lint, dependency audit.
- Nightly: integration tests on device lab and VMs (section 18), driver static analysis.
- Release: staged rollout (1% → 10% → 100%) with automatic halt on crash-rate increase.

## 18. Verification and acceptance testing

Every requirement ID in sections 5 to 16 has at least one automated test. Releases are gated on the acceptance criteria in those tables.

### 18.1 Test levels

| Level | What | Tools / environment |
| --- | --- | --- |
| Unit | Core normalisation, correlation, rule engine, tracing | Rust test + property-based tests |
| Driver | WFP callout behaviour, IOCTL handling, unload safety | WDK tests, Driver Verifier, IOCTL fuzzing, HLK subset |
| Integration | Collectors → core → alerts on real OS builds | Windows 10 22H2 and 11 (x64, ARM64) VMs; Android 10–15 device lab; reference TVs; Pi 4/5 |
| Detection | Each detection rule fires on its simulation and stays quiet on benign baselines | Isolated lab network; ATT&CK-mapped test frameworks (e.g. Atomic Red Team) run only in disposable VMs |
| Performance | CPU, RAM, latency, throughput, battery (NF-01 to NF-05) | Scripted load generators; battery rundown rigs |
| Compatibility | Coexistence with Defender, top 5 antivirus products, top 5 VPN clients, Hyper-V/WSL networking | Compatibility matrix |
| Usability | First-run, alert comprehension, Arabic RTL | Moderated sessions, 8 users per round |
| Security | Pen test of service API, pipe ACLs, update channel, gateway API | External audit before each public release |

### 18.2 Detection quality targets

| Measure | Target |
| --- | --- |
| Rule recall on simulation suite | ≥ 90% |
| Data-type inference precision (DL-01) | ≥ 85% |
| False-positive alerts in a 7-day benign baseline (typical home PC) | ≤ 2 Warning or higher per day |
| "Not useful" feedback rate in beta | < 10% |

### 18.3 Release acceptance

- All Critical and High test cases pass; no open Severity-1 bugs.
- Performance targets met on the reference hardware list.
- External audit findings rated High or above fixed and retested.
- Anti-abuse checklist (section 15.3) signed off.

## 19. Limitations, risks and out of scope

The app must state these limits in its help pages and wherever a result depends on them.

### 19.1 Limitations

- Encrypted content is never visible; data types are inferred from behaviour.
- An attacker with administrator or kernel control can disable or blind Sentinel. Sentinel will try to record the gap, but cannot guarantee it.
- ECH and app-level encrypted DNS hide some hostnames; tracing then falls back to IP, ASN and certificate data.
- Geolocation shows the nearest server, not where data is stored; onward sharing by the receiving company is invisible.
- iOS and closed TV platforms (Tizen, webOS, Roku, tvOS) expose little to third-party apps.
- Some Windows activity (legacy screen capture, clipboard reads) is not observable to third-party apps.
- State-grade spyware with kernel control can hide from any on-device monitor. Sentinel detects it only through outside checks against published indicators (section 8A), so new or unpublished spyware may go unnoticed.

### 19.2 Risks

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Driver bug causes system crashes | Severe user harm, store removal | Minimal driver scope, Driver Verifier, fuzzing, staged rollout, kill switch that falls back to user-mode monitoring |
| Store policy rejection (Play VpnService, Apple entitlement) | Delayed edition | Early submissions, alternative channels |
| Alert fatigue from false positives | Users ignore or uninstall | Conservative defaults, evidence on every alert, feedback loop |
| Conflicts with antivirus or VPN products | Broken connectivity | Compatibility matrix, own WFP sublayer, fail open |
| Misuse as a monitoring tool against others | Legal and reputational harm | Anti-abuse rules (15.3), no remote viewing, visible presence |
| Dataset licensing | Legal exposure | Phase 0 license review, substitutes ready |
| Windows driver signing delays | Phase slips | Start EV certificate and attestation setup early |

### 19.3 Out of scope

- Decrypting other apps' traffic (except an opt-in, browser-only local inspection mode considered for Phase 6).
- Monitoring devices the user does not own, or other people.
- Any active response against remote systems.
- Enterprise fleet management, SIEM integration and MDM (candidate follow-on product).

## 20. Delivery plan and traceability

Spyware protection ships first: a standalone PC Phone Check by month 7 and gateway indicator matching by month 9. The full Windows edition starts in month 8, enters beta in month 12 and becomes generally available in month 14, with macOS following.

### 20.1 Phases

| Phase | Months | Scope | Gate |
| --- | --- | --- | --- |
| P0 Foundations | 1–1.5 | Architecture, threat model, store and license reviews, EV certificate and Partner Center setup, indicator-source agreements | Decisions recorded |
| P1 Android MVP | 2–5 | CM, SE, posture, alerts on Android | Public beta + audit 1 |
| **P1b Spyware Check (priority)** | **3–7** | **Standalone PC "Phone Check" app for Windows and macOS (MS-04, MS-05, MS-13 to MS-15), signed indicator feed (MS-10), High-risk mode checklist (MS-11, MS-12)** | **Detects all public MVT test cases; expert review by a helpline partner** |
| P2 Correlation and tracing | 5–8 | DL-01 to DL-06, DT-01 to DT-09, response actions on Android | Android v1.0 |
| P3 Network Sentinel | 4–9 | Gateway, TV ACR detection, household view, **spyware indicator matching, retro-hunt and out-of-band alerts (MS-01 to MS-03, MS-08, MS-09)** | 6 reference TVs pass; planted indicators detected |
| P4 TV agent | 9–12 | Google TV / Android TV / Fire TV agent | Store approval |
| **P5a Windows** | **8–14** | Driver, service, WinUI app; all CM, SE, DL, ID, RA, DV requirements for Windows; Phone Check folded in; desktop spyware self-check (MS-06, MS-07) | **Beta month 12, GA month 14, audit 2** |
| P5b macOS | 12–16 | Network Extension edition at near Windows parity | Notarized release |
| P6 Advanced | 13–18 | ML inference, IOC feed expansion, iOS companion, TV viewer apps, Linux | v2.0 + audit 3 |

### 20.2 Windows edition sprints (2 weeks each)

1. Driver skeleton: WFP sublayer, ALE connect/accept monitoring, fail-open unload.
2. Service host, named-pipe API, encrypted store, core integration.
3. DNS and process collectors; flow enrichment; live connections view.
4. Firewall modes and prompts (CM-08 to CM-12).
5. Sensor collectors (SE-01 to SE-05, SE-09).
6. Security-event subscriptions and detection rules (ID-01 to ID-11).
7. Data-leak rules (DL-01 to DL-08) and destination tracing UI.
8. Response actions and journal with undo (RA-01 to RA-13).
9. Laptop and desktop specifics (DV-01 to DV-07), ARM64 build.
10. Hardening, performance tuning, HLK and compatibility matrix.
11. Beta, feedback, false-positive tuning.
12. External audit fixes, GA release.

### 20.3 Traceability

| Requirement group | Source in product spec | Verified by |
| --- | --- | --- |
| CM-01 to CM-13 | Spec 6.1, TV-FR-1, TV-FR-4 | Integration tests, section 18.1 |
| SE-01 to SE-09 | Spec 6.3, TV-FR-3 | Integration + usability tests |
| DL-01 to DL-10 | Spec 6.4, TV-FR-7 to TV-FR-10 | Detection suite, 18.2 targets |
| ID-01 to ID-14 | Spec 6.5, TV-FR-5, TV-FR-11, TV-FR-12 | Detection suite |
| MS-01 to MS-15 | Mercenary-spyware discussion (Pegasus and similar) | Planted-indicator tests, public MVT test data, helpline partner review |
| RA-01 to RA-13 | Spec 6.6 (FR-20) | Integration tests, journal/undo tests |
| DT-01 to DT-09 | Spec 12 (DT-FR-1 to DT-FR-10) | Unit + UI tests |
| DV-01 to DV-10 | Spec 11.5, TV-NFR | Performance and device tests |
| NF-01 to NF-15 | Spec 7, TV-NFR | Performance, compatibility, audit |

### 20.4 Open questions

- [ ] Commercial or free product? This decides the tracker dataset license.
- [ ] Should Windows GA move ahead of the TV agent, if desktop users are the priority?
- [ ] Is enterprise/fleet management a later product or out of scope entirely?
