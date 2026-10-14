// SPDX-License-Identifier: GPL-3.0-or-later

use std::io;
use std::os::fd::OwnedFd;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::watch;

/// A TUN device: one read returns one IP packet, one write sends one IP packet.
///
/// On Android the descriptor comes from `VpnService.Builder.establish().detachFd()`.
///
/// When the tunnel goes away (VPN revoked, descriptor closed), reads fail at once and
/// keep failing. The userspace stack ignores failed reads, so without care it would
/// spin forever. Instead the device remembers the first failure, stops reading, and
/// reports it through [`TunDevice::closed`] so the engine can end and the app can
/// record a monitoring gap (SRS SP-03).
pub struct TunDevice {
    fd: AsyncFd<OwnedFd>,
    closed: watch::Sender<Option<String>>,
}

/// Resolves once the tunnel has failed or closed. See [`TunDevice::closed`].
pub struct TunClosed(watch::Receiver<Option<String>>);

impl TunClosed {
    /// Wait for the tunnel to close; returns why.
    pub async fn wait(mut self) -> String {
        loop {
            if let Some(reason) = self.0.borrow().clone() {
                return reason;
            }
            if self.0.changed().await.is_err() {
                return "tunnel device dropped".to_owned();
            }
        }
    }
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
        let (closed, _) = watch::channel(None);
        Ok(TunDevice { fd, closed })
    }

    /// A handle that resolves when the tunnel fails or reaches end of stream.
    pub fn closed(&self) -> TunClosed {
        TunClosed(self.closed.subscribe())
    }

    fn mark_closed(&self, reason: String) {
        if self.closed.borrow().is_none() {
            self.closed.send_replace(Some(reason));
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.borrow().is_some()
    }
}

impl AsyncRead for TunDevice {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.is_closed() {
            // Never wake again: the engine learns about the closure through `closed()`.
            return Poll::Pending;
        }
        loop {
            let mut guard = match ready!(self.fd.poll_read_ready(cx)) {
                Ok(guard) => guard,
                Err(e) => {
                    self.mark_closed(format!("tunnel read failed: {e}"));
                    return Poll::Pending;
                }
            };
            let unfilled = buf.initialize_unfilled();
            match guard.try_io(|fd| Ok(rustix::io::read(fd.get_ref(), &mut *unfilled)?)) {
                Ok(Ok(0)) => {
                    self.mark_closed("tunnel reached end of stream".to_owned());
                    return Poll::Pending;
                }
                Ok(Ok(n)) => {
                    buf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(e)) => {
                    self.mark_closed(format!("tunnel read failed: {e}"));
                    return Poll::Pending;
                }
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
                Ok(Err(e)) => {
                    self.mark_closed(format!("tunnel write failed: {e}"));
                    return Poll::Ready(Err(e));
                }
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
