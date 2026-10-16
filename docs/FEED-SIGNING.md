# Feed signing procedure

How maintainers create signing keys and sign indicator-feed bundles. The format and the reasons behind it are in [ADR-0005](adr/0005-signed-feed-format.md).

**The secret keys never touch a computer that is connected to a network.**

## Roles

| Role | Who | Holds |
| --- | --- | --- |
| Signer A | Maintainer 1 | Secret key A on an encrypted USB drive; a backup copy kept somewhere else |
| Signer B | Maintainer 2 | Secret key B, the same way |
| Reviewer | Any maintainer other than the signer | Reviews the bundle diff before signing |

In Phase A the threshold is 1: either signer can sign alone, so urgent same-day updates (MS-10) are possible. When there are three maintainers, move to threshold 2.

## The offline signing machine

- A laptop that never connects to a network, or any computer booted from a live USB with networking disabled.
- It needs only the `sentinel-feed-tool` binary. Build it on a normal machine (`cargo build --release -p sentinel-feed-tool`) and copy it over on a USB drive. Check its SHA-256 against the CI build first.
- Disk encryption on; no other software installed.

## One-time: create a key

On the offline machine:

```sh
sentinel-feed-tool keygen --secret /media/usb/feed-a.key --public /media/usb/feed-a.pub
```

- The secret key file is created with owner-only permissions, and the tool refuses to overwrite an existing file.
- Make a backup copy of the secret key on a second encrypted USB drive, stored in a different place.
- Copy **only** `feed-a.pub` back to a networked computer. Commit it as `keys/feed/feed-a.pub` in a reviewed PR: every `.pub` file in `keys/feed` is compiled into the apps' trust root (ADR-0019), so the next app release trusts it.

## Every release: build, review, sign, publish

1. **Build (online, in CI or on a maintainer's machine).** Prepare the bundle directory with the new data files, then:

   ```sh
   sentinel-feed-tool manifest --dir bundle/ --version <previous + 1> --valid-days 14 --out manifest.json
   ```

2. **Review (online).** A reviewer checks the human-readable diff of indicators against the previous release, including the source and report link for each new indicator. The reviewer writes down the SHA-256 of `manifest.json`.
3. **Sign (offline).** Copy `manifest.json` to the offline machine on a USB drive, then:

   ```sh
   sha256sum manifest.json        # must match what the reviewer wrote down
   sentinel-feed-tool sign --manifest manifest.json --secret /media/usb/feed-a.key --out manifest.dsse.json
   ```

   The tool prints the version, expiry and every file's hash before signing. Compare them with the reviewed diff.

4. **Verify and publish (online).** Copy `manifest.dsse.json` back into `bundle/`, then:

   ```sh
   sentinel-feed-tool verify --dir bundle/ --public keys/feed/feed-a.pub --public keys/feed/feed-b.pub --installed-version <previous>
   ```

   Publish the bundle only if this prints `OK`. The apps fetch the newest bundle from the GitHub release tagged `feed` ([ADR-0019](adr/0019-indicator-feed-on-android.md)): replace all of its assets with the manifest and every file of the bundle, side by side, and upload nothing else there. To keep a record, also publish the bundle as its own release, tagged `feed-<version>`.

## Urgent updates

Same steps, same day, when a new public report names indicators that users need now (MS-10). The review in step 2 may be done by the signer alone if no other maintainer is reachable; the next regular release is then reviewed by someone else.

## If a key is lost or leaked

1. Stop using it immediately.
2. Generate a new key (above) and ship an app update whose trust root drops the old key and adds the new one.
3. If it leaked, publish a security advisory. After the app update, a bundle signed only by the leaked key fails the start-up re-check (SP-04). The app then discards it and installs the next good bundle, even if the attacker's bundle used a higher version number.
