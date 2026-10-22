# ADR-0036: Fuzzing the parsers

- Status: **Accepted** (Sprint 10; `fuzz/`, `.github/workflows/fuzz.yml`)
- Date: 2026-10-16
- Implements THREAT-MODEL-A D3 ("Malformed packets crash the parsers"), whose plan item reads "fuzz the DNS, TLS and QUIC parsers" ([PHASE-A-ANDROID.md](../PHASE-A-ANDROID.md), Sprint 10).

## Context

The engine reads bytes that any app on the phone, or any server it talks to, chooses:
- the first bytes of each TCP connection, for the TLS server name (CM-02);
- every DNS query and answer that passes the tunnel;
- since Sprint 9, the names the detection rules look at (DL-05, DL-06).

A panic in the engine stops monitoring. Android then sends traffic outside the tunnel (NF-07), so the engine fails open, and an app that can crash it on purpose can turn monitoring off. The parsers already check every length and were unit-tested with truncated, corrupted and pseudo-random input, but only with the inputs those tests thought of.

Sentinel parses no QUIC: a QUIC connection is relayed as UDP, and its server name is not read. So there is no QUIC parser to fuzz.

## Decision

1. **Coverage-guided fuzzing with cargo-fuzz** (libFuzzer), in `fuzz/`, a workspace of its own: it needs nightly Rust and cargo-fuzz, and the rest of the build does not.
2. **Eight targets**, each checking what its parser promises as well as that it does not crash:
   - `tls_client_hello`: it never asks for fewer bytes than it has, or more than one record. A server name is a valid lower-case host name.
   - `dns_query`: a query it can read, it can answer "no such name". That answer is neither a query nor an answer with addresses. The name holds only lower-case letters, digits, `-`, `_`, `.` and `\` (audit A-31). Every question is read the same way, the first being the query's (audit A-39).
   - `dns_response`: the name is lower-case without a trailing dot, holds only those characters, and there are addresses.
   - `dns_names`: lines of any text through the DNS-tunnel watch, the encrypted DNS and sharing-site checks.
   - The feed's files, which come from a download or a folder the user picks, and are read before their signature is checked or once it has been (audit A-49):
     - `feed_manifest`: the signed envelope and the manifest. A manifest it reads, it writes and reads back the same, with the same digest of its files.
     - `indicator_file`: every indicator it accepts is found by the matcher under its own value. One that never could would be read and never matched.
     - `ip_db` and `tracker_db`: a file it accepts can be looked up at any address or name, among them ones made from the file's own bytes.
3. **Seeds** in `fuzz/seeds/`: one valid input per target. What a run grows (`corpus/`) and finds (`artifacts/`) is not kept in the repository.
4. **CI runs each target for ten minutes** every Monday and on demand, and keeps an input that fails. It does not run on every push, which would add ten minutes of runner time to each.
5. **A failing input becomes a unit test** next to its parser, before the parser is fixed (`fuzz/README.md`).

## Verification

On this change, each target ran for three minutes on a developer machine, with no crash and no broken check:

| Target | Runs | Coverage (edges) | Corpus |
| --- | --- | --- | --- |
| `tls_client_hello` | 72.6 million | 175 | 109 inputs |
| `dns_query` | 1.08 million | 1589 | 617 inputs |
| `dns_response` | 4.79 million | 1555 | 829 inputs |
| `dns_names` | 1.08 million | 690 | 856 inputs |

The weekly CI job had not run by audit A-49: it reached the main branch on a Tuesday, after the Monday it would first have run. It was then run by hand on all eight targets. The four feed targets each ran for one minute on a developer machine when added, with no crash and no broken check: `feed_manifest` 3.2 million runs, `indicator_file` 3.9 million, `ip_db` 11.9 million and `tracker_db` 5.4 million. With its check reversed, `indicator_file` fails at once on its seed, which shows the seeds reach the matcher.

## Consequences

- **Three minutes is a start, not an assurance.** The weekly runs carry it further; a longer run before the public beta is worth it.
- **What is fuzzed is the parsing, not the engine.** The packet stacks (smoltcp, ipstack) are fuzzed by their own projects, or not at all; a crash in them stops monitoring just the same. Fuzzing the engine with whole packets through the socketpair harness is left for later (audit A-49).
- **If Sentinel ever reads QUIC Initial packets** for their server name, that parser needs a target here.
