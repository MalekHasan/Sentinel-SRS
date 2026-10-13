// SPDX-License-Identifier: GPL-3.0-or-later

use std::io;
use std::os::fd::BorrowedFd;

/// Keeps the engine's own upstream sockets out of the tunnel.
///
/// Without this, every upstream connection would be routed back into the tunnel and
/// loop forever. On Android the implementation calls `VpnService.protect(fd)`.
pub trait Protect: Send + Sync + 'static {
    /// Called on every upstream socket before it connects or sends anything.
    fn protect(&self, socket: BorrowedFd<'_>) -> io::Result<()>;
}

/// For tests whose routing never sends upstream traffic into the tunnel.
pub struct NoProtect;

impl Protect for NoProtect {
    fn protect(&self, _socket: BorrowedFd<'_>) -> io::Result<()> {
        Ok(())
    }
}

/// Linux lab equivalent of `VpnService.protect`: mark the socket so a policy-routing
/// rule (`ip rule add fwmark <mark> lookup <table>`) sends it around the tunnel.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub struct SoMark(pub u32);

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Protect for SoMark {
    fn protect(&self, socket: BorrowedFd<'_>) -> io::Result<()> {
        socket2::SockRef::from(&socket).set_mark(self.0)
    }
}
