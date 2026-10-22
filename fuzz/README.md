# Fuzzing

Coverage-guided fuzzing of the parsers that read what apps and the network send (THREAT-MODEL-A D3, [ADR-0036](../docs/adr/0036-fuzzing.md)).

| Target | What it reads | What it checks besides not crashing |
| --- | --- | --- |
| `tls_client_hello` | The first bytes an app sends on a TCP connection (`scan_client_hello`) | Never asks for fewer bytes than it has, or more than one record; a server name is a valid lower-case host name |
| `dns_query` | DNS queries from apps (`parse_dns_query`, `name_error_reply`) | A query it reads, it can answer; the answer is neither a query nor an answer with addresses |
| `dns_response` | DNS answers from the network (`parse_dns_response`) | The name is lower-case, without a trailing dot, and there are addresses |
| `dns_names` | Names as the DNS-tunnel, encrypted-DNS and sharing-site rules see them (DL-05, DL-06) | — |
| `feed_manifest` | The feed's signed envelope and its manifest, before any signature is checked (`Envelope::from_json`, `Manifest::from_json`) | A manifest it reads, it writes and reads back the same |
| `indicator_file` | An indicator file from the feed (`IndicatorFile::parse`) | Every indicator it accepts is found by the matcher under its own value |
| `ip_db` | The feed's IP database (`IpDb::from_bytes`) | A file it accepts can be looked up at any address |
| `tracker_db` | The feed's tracker list (`TrackerDb::from_bytes`) | A file it accepts can be looked up with any name |
| `packet_stack` | Packets from apps through the tunnel, into smoltcp through the patched netstack-smoltcp, with the connections they open answered, reset or dropped as the relay would | What the stack sends back is an IP packet as long as it says |

The fuzz crate is its own workspace: it needs a nightly toolchain and cargo-fuzz, which nothing else does.

```sh
rustup toolchain install nightly --profile minimal
cargo +nightly install cargo-fuzz --locked
cd fuzz
mkdir -p corpus/dns_query
cargo +nightly fuzz run dns_query corpus/dns_query seeds/dns_query -- -max_total_time=600
```

`seeds/` holds a valid input for each target: a ClientHello with a server name, DNS queries for A and TXT records, an answer with an A and an AAAA record, names, the device tests' signed feed (an envelope, its manifest, two indicator files, `ip.db` and `trackers.db`), and runs of TCP and UDP packets over IPv4 and IPv6. A `packet_stack` input is a flag byte, then packets each after its length in two bytes; when the flag byte is even, the packets' checksums are set right before they are sent, as the stack drops packets with wrong ones. `corpus/` and `artifacts/` are what a run grows and finds, and are not kept. An input that crashes a target is saved in `artifacts/<target>/`. Make it a unit test next to the parser before fixing the parser.

CI runs each target for ten minutes every Monday, and on demand (`.github/workflows/fuzz.yml`).
