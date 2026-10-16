// SPDX-License-Identifier: GPL-3.0-or-later
// A tiny app the device tests install while they run, so that Sentinel sees an app
// installed after it started (CM-04) or after Block-unknown was turned on (CM-08), one the
// test indicator lists name (ID-13), or one that holds special access (ID-12). It connects
// where the test tells it to. It is never shipped: the app's androidTest APK carries it as
// an asset.
plugins {
    alias(libs.plugins.android.application)
}

android {
    namespace = "io.github.malekhasan.sentinel.probe"
    compileSdk = 37

    signingConfigs {
        // A fixed test key, so that the test indicator lists can name the probe's signing
        // certificate (SHA-256 be9200574eb6aa1083aa108b7e50625edc2c86787593ad5b35a68c110284b64f,
        // apps/android/scripts/test-feed/indicators-v5.json). It signs nothing else, and
        // its password is no secret.
        getByName("debug") {
            storeFile = file("test-signing.p12")
            storeType = "pkcs12"
            storePassword = "android"
            keyAlias = "probe"
            keyPassword = "android"
        }
    }

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
