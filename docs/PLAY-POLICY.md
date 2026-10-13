# Google Play policy review (A0)

Version 0.1 · Oct 2026 · Status: **desk review**, to be re-checked against the live policy pages before submitting.

Distribution plan (PLAN.md D8): GitHub releases and F-Droid first; Google Play once the declarations below are accepted. Nothing here blocks the first beta.

## What Sentinel uses that Play restricts

| Feature | Why Sentinel needs it | Play requirement | Our position |
| --- | --- | --- | --- |
| `VpnService` | Per-app connections, DNS and blocking (CM-01 to CM-10) | VpnService declaration in Play Console. "Device security" (anti-virus, firewall) is a permitted category. The use must be the app's core purpose and must be explained in the store listing | Core purpose is a device-security firewall and monitor. The listing must say plainly that the VPN is local: traffic never leaves through our servers, because we have none |
| `QUERY_ALL_PACKAGES` | ID-12 (apps with accessibility, device-admin or listener access) and ID-13 (stalkerware package check) need the full list of installed apps | Permissions Declaration Form; "antivirus" is a permitted use; must show that a narrower visibility method is not enough; reviewers may ask for a video | Matching against a stalkerware list is impossible without seeing every package, so `<queries>` filters cannot work |
| Foreground service | The tunnel must keep running | Android 14+ requires a foreground service type. `systemExempted` is allowed for "VPN apps (configured using Settings > Network & Internet > VPN)" | Declare `systemExempted` with `FOREGROUND_SERVICE_SYSTEM_EXEMPTED`. Fallback: `specialUse` with a written justification |
| Usage access (`PACKAGE_USAGE_STATS`) | Foreground app for basic sensor attribution; per-app data totals | Special access the user grants in Settings | Ask only when the user turns on the feature, with an explanation first |

## Things we deliberately do not use

| Not used | Why it matters |
| --- | --- |
| Accessibility API | Heavily restricted on Play, and banned for this purpose by the SRS (§2.4) |
| Remote VPN servers | No traffic ever leaves through Sentinel; this also avoids most VPN-provider rules |
| Analytics or crash SDKs | Keeps the Data safety form simple (NF-11) |

## Data safety form (draft answers)

- **Data collected:** none. Everything stays on the device.
- **Data shared:** none.
- **Network use:** optional download of the signed indicator feed from GitHub releases. That host sees the device's IP address, as with any download. No identifiers are sent.
- **Encryption:** the local database is encrypted (SQLCipher, key protected by the Android Keystore).
- **Deletion:** one-tap wipe in the app; uninstalling removes everything.

## Target API level

Play requires new apps and updates to target a recent API level, and the minimum rises every August. The skeleton targets API 36 (`apps/android/app/build.gradle.kts`). Check the current requirement before each submission.

## Risks

| Risk | Mitigation |
| --- | --- |
| A reviewer reads "VPN" and expects encryption to a remote server | Explain in the declaration and listing that this is an on-device firewall, like other local-VPN firewalls on Play |
| `QUERY_ALL_PACKAGES` rejected | Ship ID-12 and ID-13 in the F-Droid/GitHub build; in the Play build, fall back to checking only packages named in the stalkerware list, through `<queries>`, and say what is lost |
| Policy changes | Re-read the policies before each submission; keep F-Droid and GitHub as the primary channels |

## Sources

- [Google Play: VpnService policy and declaration](https://support.google.com/googleplay/android-developer/answer/12564964?hl=en)
- [Google Play: upcoming policies](https://Support.Google.Com/googleplay/android-developer/answer/14554661)
- [Google Play: use of the QUERY_ALL_PACKAGES permission](https://support.google.com/googleplay/android-developer/answer/10158779?hl=en)
- [Android: foreground service types (systemExempted, specialUse)](https://developer.android.com/develop/background-work/services/fgs/service-types)
- [Android 14: foreground service types are required](https://developer.android.com/about/versions/14/changes/fgs-types-required?hl=pt)
