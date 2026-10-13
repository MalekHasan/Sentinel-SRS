# Security policy

Sentinel is a security tool, so its own security matters a great deal. Thank you for helping.

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Only the maintainers can see the report.

Please include:

- what an attacker could do, and what they need first (for example: same Wi-Fi network, an installed app, physical access);
- steps to reproduce, or a proof of concept;
- the version or commit you tested.

## What to expect

| Step | Target |
| --- | --- |
| We confirm we received your report | Within 3 working days |
| We tell you whether we accept it and how severe we think it is | Within 10 working days |
| Fix released for High and Critical issues | As fast as possible; we keep you informed |

We credit reporters in the release notes unless you ask us not to.

## Scope

In scope: everything in this repository, including the indicator feed format and signing process.

Especially interesting:

- ways to make the app hide a real finding, or show a false one;
- ways to read the encrypted local database or the signed feed keys;
- parser bugs (DNS, TLS, QUIC, STIX) reachable from network traffic or from a feed file;
- anything that breaks the anti-abuse rules in SRS §15.3 (hidden operation, remote viewing, content capture).

Out of scope: an attacker who already has root or administrator control of the device. The SRS (§1.3) states this limit openly.
