#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Builds the signed indicator-feed bundles the device tests install (ADR-0019), from the
# files in scripts/test-feed/:
#
#   app/src/androidTest/assets/feed/v1 to v5     bundles of versions 1 to 5
#   scripts/test-feed/test-key.pub               the public key that signed them
#   app/src/debug/kotlin/.../FeedKeys.kt         debug builds trust that key too
#
# The secret key is made in a temporary directory and deleted at the end, so nobody can
# sign with it afterwards: a debug build trusts the test key, and no one can use it.
# Release builds trust only keys/feed. The bundles stay current for ten years; run this
# again when their format changes.
#
#   apps/android/scripts/make-test-feed.sh

set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
inputs=$here/test-feed
out=$repo/apps/android/app/src/androidTest/assets/feed
keys_kt=$repo/apps/android/app/src/debug/kotlin/io/github/malekhasan/sentinel/FeedKeys.kt

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

cargo build --quiet --release --manifest-path "$repo/Cargo.toml" -p sentinel-feed-tool
tool=$repo/target/release/sentinel-feed-tool

"$tool" keygen --secret "$work/test.key" --public "$work/test.pub"

for version in 1 2 3 4 5; do
    bundle=$out/v$version
    rm -rf "$bundle"
    mkdir -p "$bundle"
    cp "$inputs/ip.db" "$inputs/trackers.db" "$bundle/"
    cp "$inputs/indicators-v$version.json" "$bundle/indicators-sentinel-test.json"
    "$tool" manifest --dir "$bundle" --version "$version" --valid-days 3650 \
        --out "$work/manifest-$version.json"
    "$tool" sign --manifest "$work/manifest-$version.json" --secret "$work/test.key" \
        --out "$bundle/manifest.dsse.json"
    "$tool" verify --dir "$bundle" --public "$work/test.pub"
done

cp "$work/test.pub" "$inputs/test-key.pub"
key=$(tr -d '\n' <"$work/test.pub")
mkdir -p "$(dirname "$keys_kt")"
cat >"$keys_kt" <<EOF
// SPDX-License-Identifier: GPL-3.0-or-later
// Written by apps/android/scripts/make-test-feed.sh.
package io.github.malekhasan.sentinel

import io.github.malekhasan.sentinel.core.trustedFeedKeys

/**
 * The keys a debug build trusts to sign the indicator feed: those of keys/feed, and the
 * key that signed the device tests' bundles (ADR-0019). Its secret key was deleted once
 * they were signed. Release builds trust keys/feed only.
 */
object FeedKeys {
    private const val TEST_KEY = "$key"

    val trusted: List<String> = trustedFeedKeys() + TEST_KEY
}
EOF
echo "test bundles in $out, signed by $key"
