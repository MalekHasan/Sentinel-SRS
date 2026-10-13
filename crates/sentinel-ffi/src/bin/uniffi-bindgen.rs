// SPDX-License-Identifier: GPL-3.0-or-later
//! Generates the Kotlin bindings. Used by the Android Gradle build.

fn main() {
    uniffi::uniffi_bindgen_main()
}
