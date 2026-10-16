// SPDX-License-Identifier: GPL-3.0-or-later
//! Userspace packet engine for the Android `VpnService` tunnel.
//!
//! Built on smoltcp (through a patched `netstack-smoltcp`); the stack choice and its
//! measurements are in `docs/adr/0006-android-packet-engine.md`.
//!
//! How it works:
//!
//! 1. Android hands us the tunnel as a file descriptor ([`TunDevice`]).
//! 2. A userspace TCP/IP stack (smoltcp) terminates every TCP and UDP flow from the
//!    apps inside this process.
//! 3. For each flow we open a real socket to the original destination. That socket is
//!    *protected* ([`Protect`]) so its traffic leaves through the normal network instead
//!    of looping back into the tunnel.
//! 4. Bytes are copied in both directions and counted. We look only at metadata: the
//!    destination, DNS answers and the TLS ClientHello server name. Payloads are never
//!    stored (SRS §2.5).
//! 5. An [`Observer`] is told about every flow and can block it before any upstream
//!    connection is made, or when its server name becomes known.

mod device;
mod dns;
mod engine;
mod flow;
mod forward;
mod protect;
mod relay;
mod sni;
#[cfg(feature = "ipstack")]
mod stack_ipstack;
mod stack_smoltcp;

pub use device::{TunClosed, TunDevice};
pub use dns::{DnsAnswer, DnsCache, name_error_reply, parse_dns_query, parse_dns_response};
pub use engine::{EngineConfig, EngineStats};
pub use flow::{FlowCounters, FlowInfo, FlowTotals, HostnameSource, Observer, Proto, Verdict};
pub use forward::DnsForward;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use protect::SoMark;
pub use protect::{NoProtect, Protect};
pub use sni::{ClientHelloScan, scan_client_hello};
#[cfg(feature = "ipstack")]
pub use stack_ipstack::run_ipstack;
pub use stack_smoltcp::run;
