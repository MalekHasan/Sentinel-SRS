# Fuzzing

Coverage-guided fuzzing of the parsers that read what apps and the network send (THREAT-MODEL-A D3, [ADR-0036](../docs/adr/0036-fuzzing.md)).

| Target | What it reads | What it checks besides not crashing |
| --- | --- | --- |
| `tls_client_hello` | The first bytes an app sends on a TCP connection (`scan_client_hello`) | Never asks for fewer bytes than it has, or more than one record; a server name is a valid lower-case host name |
| `dns_query` | DNS queries from apps (`parse_dns_query`, `name_error_reply`) | A query it reads, it can answer; the answer is neither a query nor an answer with addresses |
| `dns_response` | DNS answers from the network (`parse_dns_response`) | The name is lower-case, without a trailing dot, and there are addresses |
| `dns_names` | Names as the DNS-tunnel, encrypted-DNS and sharing-site rules see them (DL-05, DL-06) | — |

The fuzz crate is its own workspace: it needs a nightly toolchain and cargo-fuzz, which nothing else does.

```sh
rustup toolchain install nightly --profile minimal
cargo +nightly install cargo-fuzz --locked
cd fuzz
mkdir -p corpus/dns_query
cargo +nightly fuzz run dns_query corpus/dns_query seeds/dns_query -- -max_total_time=600
```

`seeds/` holds a valid input for each target: a ClientHello with a server name, DNS queries for A and TXT records, an answer with an A and an AAAA record, and names. `corpus/` and `artifacts/` are what a run grows and finds, and are not kept. An input that crashes a target is saved in `artifacts/<target>/`. Make it a unit test next to the parser before fixing the parser.

CI runs each target for ten minutes every Monday, and on demand (`.github/workflows/fuzz.yml`).
