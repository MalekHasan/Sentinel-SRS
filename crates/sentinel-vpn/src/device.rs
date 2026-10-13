// SPDX-License-Identifier: GPL-3.0-or-later

use std::io;
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A TUN device: one read returns one IP packet, one write sends one IP packet.
///
/// On Android the descriptor comes from `VpnService.Builder.establish().detachFd()`.
pub struct TunDevice {
    fd: AsyncFd<OwnedFd>,
}

impl TunDevice {
    /// Take ownership of an open TUN descriptor and switch it to non-blocking mode.
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        let flags = fcntl_getfl(&fd)?;
        fcntl_setfl(&fd, flags | OFlags::NONBLOCK)?;
        // SAFETY: `OwnedFd` holds an open descriptor that stays open, and keeps the same
        // number, until the `AsyncFd` (and with it the `OwnedFd`) is dropped.
        #[allow(unsafe_code)]
        let fd = unsafe { AsyncFd::register(fd)? };
        Ok(TunDevice { fd })
    }
}

impl AsyncRead for TunDevice {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            let mut guard = ready!(self.fd.poll_read_ready(cx))?;
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|fd| Ok(rustix::io::read(fd.get_ref(), &mut *unfilled)?)) {
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => return Poll::Ready(Err(e)),
                Err(_would_block) => continue,
            }
        }
    }
}

impl AsyncWrite for TunDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        packet: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            let mut guard = ready!(self.fd.poll_write_ready(cx))?;
            match guard.try_io(|fd| Ok(rustix::io::write(fd.get_ref(), packet)?)) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
