# Building the Android app

The app is Kotlin and Jetpack Compose (`apps/android`). The core is Rust (`crates/`); the Gradle build compiles it for each Android ABI with `cargo-ndk`, and generates Kotlin bindings with UniFFI.

## Requirements

| Tool | Version | How |
| --- | --- | --- |
| JDK | 17 | Android Studio's bundled JDK is fine |
| Android SDK | Platform 37, build tools 36 | Android Studio SDK Manager |
| Android NDK | Any recent (r28 or later) | SDK Manager → SDK Tools → NDK |
| Rust | Pinned by `rust-toolchain.toml` | `rustup` installs it on first use |
| Rust Android targets | | `rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android` |
| cargo-ndk | 4.1.2 | `cargo install --locked cargo-ndk --version 4.1.2` |

Set `ANDROID_NDK_HOME` to the NDK folder, for example `~/Android/Sdk/ndk/28.2.13676358`.

## Build

```sh
cd apps/android
./gradlew assembleDebug           # APK in app/build/outputs/apk/debug/
./gradlew lintDebug
./gradlew :app:connectedDebugAndroidTest   # needs a device or emulator, see below
```

`MonitoringTest` and `LiveViewTest` start the VPN and connect through the engine to an HTTP server on the test machine, which the emulator reaches as `10.0.2.2`. Start it first:

```sh
python3 apps/android/scripts/test-server.py
```

It is Python's `http.server` with a listen backlog large enough for the 500 connections `LiveViewTest` opens at once.

The tests that need an indicator list (`FeedTest`, `DestinationFactsTest`, `TrackerListTest`) install the signed lists in the test APK's `assets/feed`. `apps/android/scripts/make-test-feed.sh` builds them from `apps/android/scripts/test-feed/` with a key it makes and deletes; debug builds trust that key, release builds do not ([ADR-0019](adr/0019-indicator-feed-on-android.md)). Run it again when the feed's format changes; the Rust tests fail first if the lists no longer install.

`FirewallModeTest` needs an app installed while it runs. The `probe` module is that app: a test fixture that opens one connection where it is told and ships nowhere. The app's Gradle build copies its APK into the test APK's assets, and the test installs it with `pm install`. Run the device tests of the app module only (`:app:connectedDebugAndroidTest`): the probe has none. On a real phone, run it with `--bind 0.0.0.0` on a computer the phone can reach and pass its address with `-Pandroid.testInstrumentationRunnerArguments.sentinelTestServer=192.168.1.10:8765`. The tests grant themselves the VPN consent through `appops` and need no tapping.

Two Gradle tasks run before the Android build. Both are skipped when nothing under `crates/` or `third_party/` changed.

| Task | Does | Output |
| --- | --- | --- |
| `cargoNdkBuild` | `cargo ndk … build --release -p sentinel-ffi` for arm64-v8a, armeabi-v7a, x86_64 | `libsentinel_ffi.so` per ABI, packaged as jniLibs |
| `uniffiBindings` | Builds `sentinel-ffi` for the host, then runs `uniffi-bindgen` on it | Kotlin package `io.github.malekhasan.sentinel.core` |

## CI

`.github/workflows/android.yml` runs on every push:

- **build, lint:** builds the debug APK and runs lint; the APK is uploaded as an artifact.
- **instrumented tests:** starts an x86_64 emulator (API 34) and runs the device tests, then lists each test case and its result:
  - `CoreBindingTest` loads the Rust library and calls it through UniFFI;
  - `MonitoringTest` runs the VPN end to end (see above; CI starts the HTTP server);
  - `GapLogTest` checks the monitoring-gap file.
