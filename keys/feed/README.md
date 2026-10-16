# Indicator feed keys

The public keys the apps trust to sign the indicator feed (ADR-0005, ADR-0019). Each
`*.pub` file here holds one key, 64 hex characters, as `sentinel-feed-tool keygen` writes
it. Every key in this folder is compiled into the apps (`crates/sentinel-ffi/build.rs`), so
adding or removing one is a reviewed change, followed by an app release.

The secret keys never come here, or anywhere near a computer on a network: see
[FEED-SIGNING.md](../../docs/FEED-SIGNING.md).

**There are no keys yet.** Until the maintainers create theirs, the apps cannot check any
indicator list, so they install none and say so.
