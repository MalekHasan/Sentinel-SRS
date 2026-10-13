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
./gradlew connectedDebugAndroidTest   # needs a device or emulator
```

Two Gradle tasks run before the Android build. Both are skipped when nothing under `crates/` or `third_party/` changed.

| Task | Does | Output |
| --- | --- | --- |
| `cargoNdkBuild` | `cargo ndk … build --release -p sentinel-ffi` for arm64-v8a, armeabi-v7a, x86_64 | `libsentinel_ffi.so` per ABI, packaged as jniLibs |
| `uniffiBindings` | Builds `sentinel-ffi` for the host, then runs `uniffi-bindgen` on it | Kotlin package `io.github.malekhasan.sentinel.core` |

## CI

`.github/workflows/android.yml` runs on every push:

- **build, lint:** builds the debug APK and runs lint; the APK is uploaded as an artifact.
- **instrumented tests:** starts an x86_64 emulator (API 34) and runs `CoreBindingTest`, which loads the Rust library and calls it through UniFFI.
