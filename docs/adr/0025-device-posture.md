# ADR-0025: Wireless debugging and certificates the user added

- Status: **Accepted** (Sprint 8; `crates/sentinel-detect`, `crates/sentinel-store`, `crates/sentinel-ffi`, `apps/android`)
- Date: 2026-10-16
- Implements: SRS ID-03 ("Alert when remote-access services become exposed (… ADB over network)") and ID-10 ("New trusted root certificate installed") on Android. Follows the pattern of [ADR-0014](0014-network-settings.md): the settings last seen are kept, and a change raises an alert.

## Context

Two device settings open a phone to someone else without any app looking suspicious.

- **Wireless debugging** (Android 11 and later) lets a computer paired over Wi-Fi install apps, read data and control the phone. It sits in developer options. Someone who had the phone for a few minutes can pair their own computer and leave it on.
- **A certificate authority the user added** is trusted for every TLS connection of the apps that trust user certificates, and by Android for Wi-Fi and VPN. Whoever holds its key can read and change that traffic: this is how commercial monitoring proxies work. Android shows "Network may be monitored", which is easy to dismiss.

How each can be read without root:

| Setting | How to read it | Change announced? |
| --- | --- | --- |
| Wireless debugging | the global setting `adb_wifi_enabled`, which apps may read | yes, to an observer of the setting |
| Certificates the user added | the `AndroidCAStore` key store, aliases starting with `user:` (public API) | yes, `KeyChain.ACTION_TRUST_STORE_CHANGED` to receivers registered while running |

The older `adb tcpip`, which makes ADB listen on a fixed port, leaves no setting an app may read.

## Decision

1. **Two rules.**
   - `remote-access-exposed`: wireless debugging is on. Warning, like any remote-access service exposed (SRS §8.3). The rule id is general, for the services of other platforms (ID-03); its evidence names the service.
   - `new-root-certificate`: a certificate authority the user added. High, like a new root certificate (SRS §8.3). Its evidence is the certificate's SHA-256 and who it was issued to.
2. **The device settings last seen are kept** (table `posture_state`, schema 16, JSON like the network settings). A check compares the settings now with those. The settings now are kept only once their alerts are, so a change whose alert could not be kept is reported at the next check (audit A-35).
   - Wireless debugging turned on, and each certificate not trusted before, raises an alert. Turned off and on again, or removed and added again, it raises another.
   - Unlike network settings, **the first state seen is reported too**: wireless debugging already on, or a certificate already trusted, is a risk however long it has been there.
3. **When to check.** While monitoring runs: at once when the setting changes or Android announces a change to the trusted certificates (`DeviceWatch`). Also when monitoring starts and when Sentinel opens. A change made while monitoring was off is found at the next of these.
4. **What the alert offers.**
   - Wireless debugging: Android's developer options, where it is turned off.
   - A certificate: Android's list of trusted certificates on the user's tab, where it can be removed. Phones that do not open that screen by name get the security settings.
5. **No allowing.** These alerts are about the phone, not an app, so they cannot be allowed (AL-05, ADR-0012): allowing one would stop its rule for good, with no more alerts about wireless debugging, or about any certificate added later (audit A-08). They can be dismissed or marked not useful.

## Verification

- `sentinel-detect`:
  - the first state reports what is on and trusted;
  - only what is turned on or added later is reported, again after off and on;
  - the stored JSON of the state and of the evidence is fixed.
- `sentinel-store`: the state is kept across reopening and forgotten by a wipe.
- `sentinel-ffi`:
  - a certificate is reported when first seen, with its fingerprint in lower case;
  - wireless debugging and a second certificate are reported when they appear, and not again while they stay;
  - wireless debugging cannot be allowed, and turned off and on again it is reported again.
- On the Android 14 emulator (`PostureTest`):
  - with monitoring on, the probe app is made device owner and adds a test certificate authority, whose key was deleted once it was made; a High alert names its subject and fingerprint within 5 s, and checking again raises nothing more;
  - wireless debugging is read as `settings` reports it, and raises an alert only when on.

  `RtlTest` shows the certificate alert in Arabic, right to left.

## Consequences

- **Wireless debugging is not turned on in the device tests.** On a Wi-Fi network it was never paired on, Android turns it straight back off and asks the user, which would block the other tests. Reporting it is tested in the core; on the device, the test checks that the setting can be read and that nothing is raised while it is off.
- **`adb tcpip` is not found.** It needs a computer on USB first, and ends at the next restart. USB debugging itself belongs to the hardening checklist (MS-12).
- **A certificate added through a work profile or by a device owner is reported like any other.** On work phones that is expected, and the user can dismiss it. It cannot be allowed, as that would stop every later certificate alert too (audit A-08); a certificate added later is reported again.
- **Android may stop letting apps read `adb_wifi_enabled`.** It is a hidden setting. If it closes, wireless debugging would read as off; the device test would then fail, rather than the check failing silently.
