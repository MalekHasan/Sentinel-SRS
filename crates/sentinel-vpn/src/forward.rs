// SPDX-License-Identifier: GPL-3.0-or-later
//! DNS forwarding: the tunnel's own resolver address (SRS CM-02, Sprint 1).
//!
//! The VPN tells apps to use a resolver address inside the tunnel. The engine sends
//! queries for that address to the network's real resolvers, which the app updates
//! whenever the phone changes network. So DNS keeps working after a switch from Wi-Fi
//! to mobile data, and every lookup passes through the engine, where its answer names
//! later connections.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{PoisonError, RwLock};

const DNS_PORT: u16 = 53;

#[derive(Debug)]
pub struct DnsForward {
    /// Resolver addresses the tunnel advertises (`VpnService.Builder.addDnsServer`).
    listen: Vec<IpAddr>,
    /// The current network's resolvers, in order of preference.
    upstream: RwLock<Vec<SocketAddr>>,
}

impl DnsForward {
    pub fn new(listen: Vec<IpAddr>) -> Self {
        DnsForward {
            listen,
            upstream: RwLock::new(Vec::new()),
        }
    }

    /// Replace the real resolvers, for example after a network change. Queries already
    /// in flight keep their resolver; new ones use the first of `servers`.
    pub fn set_upstream(&self, servers: Vec<SocketAddr>) {
        *self
            .upstream
            .write()
            .unwrap_or_else(PoisonError::into_inner) = servers;
    }

    pub fn upstream(&self) -> Vec<SocketAddr> {
        self.upstream
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Where to connect for a flow the app sent to `dst`: `dst` itself, or the current
    /// real resolver if `dst` is the tunnel's resolver address. Only DNS is served
    /// there; any other port is refused, so probes such as DNS-over-TLS on port 853 fail
    /// at once instead of waiting for a connect timeout.
    /// Whether `dst` is the tunnel's own resolver: one of its addresses, port 53.
    pub(crate) fn serves(&self, dst: SocketAddr) -> bool {
        self.listen.contains(&dst.ip()) && dst.port() == DNS_PORT
    }

    pub(crate) fn route(&self, dst: SocketAddr) -> io::Result<SocketAddr> {
        if !self.listen.contains(&dst.ip()) {
            return Ok(dst);
        }
        if dst.port() != DNS_PORT {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "the tunnel's resolver address serves DNS on port 53 only",
            ));
        }
        self.upstream
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .first()
            .copied()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "no resolver known"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn routes_only_dns_for_the_tunnel_resolver() {
        let forward = DnsForward::new(vec!["10.111.0.53".parse().unwrap()]);
        // Not the tunnel's resolver: unchanged.
        assert_eq!(
            forward.route(addr("93.184.215.14:443")).unwrap(),
            addr("93.184.215.14:443")
        );
        // No resolver known yet.
        let err = forward.route(addr("10.111.0.53:53")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);

        forward.set_upstream(vec![addr("192.168.1.1:53"), addr("[2001:db8::1]:53")]);
        assert_eq!(
            forward.route(addr("10.111.0.53:53")).unwrap(),
            addr("192.168.1.1:53")
        );
        let err = forward.route(addr("10.111.0.53:853")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);

        assert!(forward.serves(addr("10.111.0.53:53")));
        assert!(!forward.serves(addr("10.111.0.53:853")));
        assert!(
            !forward.serves(addr("192.168.1.1:53")),
            "a resolver the app chose"
        );

        // A network change replaces the resolvers.
        forward.set_upstream(vec![addr("[2001:db8::2]:53")]);
        assert_eq!(
            forward.route(addr("10.111.0.53:53")).unwrap(),
            addr("[2001:db8::2]:53")
        );
    }
}
