// SPDX-License-Identifier: GPL-3.0-or-later
// A tiny app the device tests install while they run, so that Sentinel sees an app
// installed after it started (CM-04) or after Block-unknown was turned on (CM-08). It
// connects where the test tells it to. It is never shipped: the app's androidTest APK
// carries it as an asset.
plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "io.github.malekhasan.sentinel.probe"
    compileSdk = 37

    defaultConfig {
        applicationId = "io.github.malekhasan.sentinel.probe"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "1"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    lint {
        abortOnError = true
    }
}
