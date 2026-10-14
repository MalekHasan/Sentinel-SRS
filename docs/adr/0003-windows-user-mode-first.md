# ADR-0003: Windows edition in user mode first, kernel driver later

- Status: Proposed
- Date: 2026-10-13
- Changes: SRS §3.2, §4.1, CM-02, CM-09, NF-02 (see SRS-AMENDMENTS AM-03, AM-04)

## Context

The SRS puts a WFP callout driver (`SentinelFlt.sys`) at the centre of the Windows edition. Shipping a kernel driver requires:

- an EV code-signing certificate, which is issued only to registered organisations;
- registration in Microsoft Partner Center and attestation signing for every build;
- HVCI compatibility, Driver Verifier, IOCTL fuzzing and HLK testing (§15.4, §18.1);
- accepting that a driver bug crashes the user's machine (§19.2, top risk).

After the July 2024 CrowdStrike outage, Microsoft has been moving security products out of the kernel. A new kernel driver from a small team goes against that direction.

Most of what the SRS needs is available from user mode:

| Need | User-mode source |
| --- | --- |
| Per-process connections and bytes | ETW `Microsoft-Windows-Kernel-Network`; WFP net events |
| DNS names per process | ETW `Microsoft-Windows-DNS-Client` |
| Process identity | ETW `Microsoft-Windows-Kernel-Process`; `WinVerifyTrust` for signers |
| Blocking per app, destination, port | WFP filters added from user mode in our own sublayer (as simplewall does), with no callout driver |
| Security events | Event Log subscriptions (`EvtSubscribe`) |
| Sensors | Capability consent store, WASAPI sessions |

## Decision

Phase D ships the Windows edition with no kernel driver:

- A Rust service (LocalSystem) hosts the collectors listed above and the shared core.
- Blocking uses persistent WFP filters in Sentinel's own sublayer, so Defender Firewall rules are never touched (CM-12 holds).
- CM-09 becomes **block and notify**: an unknown app's connection is blocked, the user is notified with the same details the SRS lists, and "Allow" adds a permit filter so the app's next attempt succeeds.
- Hostnames come from DNS correlation. SNI capture is deferred.

The driver is reconsidered in Phase E, once the project has an organisation, an EV certificate and funding for its testing.

## Consequences

- No EV certificate or Partner Center setup is needed for the first Windows release.
- No risk of driver-caused system crashes (NF-08), and nothing to do for HVCI.
- Added connection latency is effectively zero, because WFP filters run in the kernel's own filter engine (NF-02 is easier to meet).
- **Given up until Phase E:** truly holding a connection while the user decides (CM-09 as written), SNI for flows whose DNS lookup we did not see (CM-02 coverage drops for apps using their own encrypted DNS), and per-flow byte counters from the driver. DL-05 still flags the apps that use their own encrypted DNS.
- An attacker with admin rights can remove our filters. This is no worse than with a driver, which an admin can also unload (§1.3).

## Alternatives considered

- **Callout driver from day one (as in the SRS):** the full feature set, but the highest cost, risk and delay; blocked until there is a registered organisation.
- **WinDivert (existing signed packet-diverting driver):** gives packet access without writing a driver, but adds per-packet user-mode latency (against NF-02) and an external kernel dependency we do not control.
