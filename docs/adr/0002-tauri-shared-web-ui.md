# ADR-0002: One web UI, with Tauri 2 on desktop

- Status: Proposed
- Date: 2026-10-13
- Changes: SRS §3.1 (UI row) and §17 (Windows and macOS toolchains)

## Context

The SRS lists four UI technologies: WinUI 3 (Windows), SwiftUI (macOS), Jetpack Compose (Android and TV) and a web UI (gateway, Tizen and webOS viewers). Each must support English and Arabic with RTL, WCAG 2.2 AA and screen readers (§12.4). For a small team, four UI codebases means building every screen, every translation and every accessibility fix up to four times.

The gateway UI and the Tizen and webOS viewers must be web apps anyway (§17).

## Decision

Build one web UI in TypeScript and React, in `ui/`. Use it for:

- desktop on Windows, macOS and Linux, inside a Tauri 2 shell (`apps/desktop`);
- the Network Sentinel web UI (served by the gateway);
- the Tizen and webOS TV viewers (Phase E).

Keep native UIs only where the platform requires them: Kotlin and Jetpack Compose on Android and Android TV, SwiftUI for the iOS companion.

Supporting choices:

- i18n with message catalogues; layout with CSS logical properties, so RTL works without a separate stylesheet.
- Charts (Sankey, timeline) with a library that works offline; maps drawn from a bundled world outline, with no tile server, so nothing leaks to a map provider.
- Tauri's tray icon, notification and signed-updater plugins on desktop.

## Consequences

- Each screen, translation and accessibility fix is done once for desktop, gateway and TV viewer.
- The Tauri backend is Rust, so it calls the core directly, with no C#-to-Rust interop layer.
- Desktop apps use the system web view (WebView2 on Windows, WebKit on macOS and Linux), so behaviour can differ slightly between platforms. Each release is tested on all three.
- Narrator and VoiceOver work through the web view's accessibility tree, so semantic HTML and ARIA must be done well. This is checked in the Phase A accessibility pass.
- Amendment AM-02 (.NET 8 end of support) no longer applies.

## Alternatives considered

- **WinUI 3 + SwiftUI + web (as in the SRS):** the most native feel, but three desktop UIs to build and maintain.
- **Electron:** same web UI, but much larger installs and memory use, against NF-01 (RAM ≤ 150 MB).
- **Flutter:** one UI for mobile and desktop, but it cannot replace the web UI the gateway and TV viewers need, and its desktop screen-reader support is less mature than the web's.
