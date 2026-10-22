// SPDX-License-Identifier: GPL-3.0-or-later
//! Linux lab driver for A0 Spike 1. Runs the engine on a TUN device the same way
//! Android would, with a socket mark standing in for `VpnService.protect()`.
//!
//! Normally started by `crates/sentinel-vpn/lab/run-lab.sh`, inside a network namespace:
//!
//! ```sh
//! linux_lab --tun sntun0 --mark 1 [--threads 2] [--stack smoltcp|ipstack] [--block-host blocked.lab.test]
//! ```
//!
//! Prints one JSON line per finished flow and per DNS answer on stdout, and engine
//! statistics on stderr every few seconds.

#[cfg(target_os = "linux")]
fn main() -> std::io::Result<()> {
    lab::main()
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("the lab driver runs on Linux only");
}

#[cfg(target_os = "linux")]
mod lab {
    use std::collections::HashSet;
    use std::io::{self, Write as _};
    use std::net::IpAddr;
    use std::os::fd::{AsRawFd, OwnedFd};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use sentinel_vpn::{
        EngineConfig, EngineStats, FlowInfo, FlowTotals, HostnameSource, Observer, Proto, SoMark,
        TunDevice, Verdict, run,
    };

    struct Args {
        tun: String,
        mark: u32,
        threads: usize,
        block_hosts: HashSet<String>,
        stack: String,
        tcp_buffer: Option<u32>,
    }

    fn parse_args() -> io::Result<Args> {
        let mut args = Args {
            tun: "sntun0".into(),
            mark: 1,
            threads: 2,
            block_hosts: HashSet::new(),
            stack: "smoltcp".into(),
            tcp_buffer: None,
        };
        let mut it = std::env::args().skip(1);
        let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidInput, m.to_owned());
        while let Some(flag) = it.next() {
            let value = it.next().ok_or_else(|| bad("missing value"))?;
            match flag.as_str() {
                "--tun" => args.tun = value,
                "--mark" => args.mark = value.parse().map_err(|_| bad("bad --mark"))?,
                "--threads" => args.threads = value.parse().map_err(|_| bad("bad --threads"))?,
                "--stack" => args.stack = value,
                "--tcp-buffer" => {
                    args.tcp_buffer = Some(value.parse().map_err(|_| bad("bad --tcp-buffer"))?)
                }
                "--block-host" => {
                    args.block_hosts.insert(value);
                }
                other => return Err(bad(&format!("unknown flag {other}"))),
            }
        }
        Ok(args)
    }

    /// Attach to an existing persistent TUN device (created with `ip tuntap add`).
    fn open_tun(name: &str) -> io::Result<OwnedFd> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;
        let bytes = name.as_bytes();
        if bytes.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "name too long"));
        }
        // SAFETY: `ifreq` is a plain C struct; all-zero is a valid value.
        #[allow(unsafe_code)]
        let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in req.ifr_name.iter_mut().zip(bytes) {
            *dst = *src as libc::c_char;
        }
        req.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
        // SAFETY: valid open descriptor and a pointer to a live, initialised ifreq.
        #[allow(unsafe_code)]
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut req) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(file.into())
    }

    struct JsonObserver {
        block_hosts: HashSet<String>,
        out: Mutex<io::Stdout>,
    }

    impl JsonObserver {
        fn emit(&self, line: String) {
            if let Ok(mut out) = self.out.lock() {
                let _ = writeln!(out, "{line}");
            }
        }
    }

    fn json_str(s: &str) -> String {
        // Hostnames are validated to [a-z0-9._-], so plain quoting is enough here.
        format!("\"{s}\"")
    }

    impl Observer for JsonObserver {
        fn hostname_seen(&self, _flow: &FlowInfo, hostname: &str) -> Verdict {
            if self.block_hosts.contains(hostname) {
                Verdict::Block
            } else {
                Verdict::Allow
            }
        }

        fn dns_answer(&self, _flow: &FlowInfo, qname: &str, ips: &[IpAddr]) {
            let ips: Vec<String> = ips.iter().map(|ip| json_str(&ip.to_string())).collect();
            self.emit(format!(
                "{{\"event\":\"dns\",\"qname\":{},\"ips\":[{}]}}",
                json_str(qname),
                ips.join(",")
            ));
        }

        fn flow_ended(&self, flow: &FlowInfo, totals: FlowTotals) {
            let proto = match flow.proto {
                Proto::Tcp => "tcp",
                Proto::Udp => "udp",
            };
            let source = match flow.hostname_source {
                Some(HostnameSource::Dns) => "\"dns\"",
                Some(HostnameSource::Sni) => "\"sni\"",
                None => "null",
            };
            let host = flow.hostname.as_deref().map_or("null".into(), json_str);
            let verdict = match totals.verdict {
                Verdict::Allow => "allow",
                Verdict::Block => "block",
            };
            self.emit(format!(
                "{{\"event\":\"flow\",\"id\":{},\"proto\":\"{proto}\",\"dst\":\"{}\",\"host\":{host},\"host_src\":{source},\"up\":{},\"down\":{},\"ms\":{},\"verdict\":\"{verdict}\"}}",
                flow.id,
                flow.dst,
                totals.bytes_up,
                totals.bytes_down,
                totals.ended_ms.saturating_sub(flow.started_ms),
            ));
        }
    }

    pub fn main() -> io::Result<()> {
        let args = parse_args()?;
        let fd = open_tun(&args.tun)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(args.threads.max(1))
            .enable_all()
            .build()?;
        runtime.block_on(async move {
            let device = TunDevice::new(fd)?;
            let stats = Arc::new(EngineStats::default());
            let observer = Arc::new(JsonObserver {
                block_hosts: args.block_hosts,
                out: Mutex::new(io::stdout()),
            });
            let reporter = Arc::clone(&stats);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    eprintln!(
                        "stats: total={} active={} blocked={} upstream_failures={} unsupported={}",
                        reporter.flows_total(),
                        reporter.flows_active(),
                        reporter.flows_blocked(),
                        reporter.upstream_failures(),
                        reporter.unsupported_packets()
                    );
                }
            });
            eprintln!(
                "engine ({}) running on {} (pid {})",
                args.stack,
                args.tun,
                std::process::id()
            );
            let protect = Arc::new(SoMark(args.mark));
            let mut config = EngineConfig::default();
            if args.tcp_buffer.is_some() {
                config.tcp_buffer = args.tcp_buffer;
            }
            match args.stack.as_str() {
                "smoltcp" => run(device, protect, observer, config, stats).await,
                #[cfg(feature = "ipstack")]
                "ipstack" => {
                    sentinel_vpn::run_ipstack(device, protect, observer, config, stats).await
                }
                other => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown --stack {other} (ipstack needs --features ipstack)"),
                )),
            }
        })
    }
}
