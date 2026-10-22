use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    task::{Context, Poll, Waker},
    time::{Duration as StdDuration, Instant as StdInstant},
};

use futures::Stream;
use smoltcp::{
    iface::{Config as InterfaceConfig, Interface, SocketHandle, SocketSet},
    phy::Device,
    socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState},
    storage::RingBuffer,
    time::{Duration, Instant},
    wire::{HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Address, Ipv6Address, TcpPacket},
};
use spin::Mutex as SpinMutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{
        mpsc::{unbounded_channel, Receiver, Sender, UnboundedReceiver, UnboundedSender},
        Notify,
    },
};
use tracing::{error, trace};

use crate::{
    device::VirtualDevice,
    packet::{AnyIpPktFrame, IpPacket},
    Runner,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum TcpSocketState {
    Normal,
    Close,
    Closing,
    Closed,
}

struct TcpSocketControl {
    send_buffer: RingBuffer<'static, u8>,
    send_waker: Option<Waker>,
    recv_buffer: RingBuffer<'static, u8>,
    recv_waker: Option<Waker>,
    recv_state: TcpSocketState,
    send_state: TcpSocketState,
    // Sentinel patch 3: the stream asked for a reset, and when it was dropped.
    reset: bool,
    dropped_at: Option<StdInstant>,
}

struct TcpSocketCreation {
    control: SharedControl,
    socket: TcpSocket<'static>,
    key: ConnectionKey,
}

type SharedNotify = Arc<Notify>;
type SharedControl = Arc<SpinMutex<TcpSocketControl>>;
/// A connection's (source, destination): the app's address and the one it asked for.
type ConnectionKey = (SocketAddr, SocketAddr);
/// The connections that have a socket, from its SYN until the runner removes it.
type LiveSockets = Arc<SpinMutex<HashSet<ConnectionKey>>>;

/// Sentinel patch 3: what bounds the runner's sockets.
#[derive(Debug, Clone, Default)]
pub(crate) struct TcpLimits {
    /// The most sockets at once, closing ones included. A SYN beyond them gets no
    /// socket, and smoltcp answers it with a reset. `None`: no limit.
    pub max_sockets: Option<usize>,
    /// Counts the SYNs turned away by `max_sockets`.
    pub refused: Arc<AtomicU64>,
    /// How long a socket may take to close once its stream is dropped, before it is
    /// aborted with a reset. `None`: as long as smoltcp takes.
    pub linger: Option<StdDuration>,
}

struct TcpListenerRunner;

impl TcpListenerRunner {
    #[allow(clippy::too_many_arguments)]
    fn create(
        device: VirtualDevice,
        iface: Interface,
        iface_ingress_tx: UnboundedSender<Vec<u8>>,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        tcp_rx: Receiver<AnyIpPktFrame>,
        stream_tx: UnboundedSender<TcpStream>,
        sockets: HashMap<SocketHandle, (SharedControl, ConnectionKey)>,
        tcp_recv_buffer_size: u32,
        tcp_send_buffer_size: u32,
        limits: TcpLimits,
    ) -> Runner {
        Runner::new(async move {
            let notify = Arc::new(Notify::new());
            let (socket_tx, socket_rx) = unbounded_channel::<TcpSocketCreation>();
            let live = LiveSockets::default();
            let res = tokio::select! {
                v = Self::handle_packet(notify.clone(), iface_ingress_tx, iface_ingress_tx_avail.clone(), tcp_rx, stream_tx, socket_tx, tcp_recv_buffer_size, tcp_send_buffer_size, live.clone(), limits.max_sockets, limits.refused) => v,
                v = Self::handle_socket(notify, device, iface, iface_ingress_tx_avail, sockets, socket_rx, live, limits.linger) => v,
            };
            res?;
            trace!("VirtDevice::poll thread exited");
            Ok(())
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_packet(
        notify: SharedNotify,
        iface_ingress_tx: UnboundedSender<Vec<u8>>,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        mut tcp_rx: Receiver<AnyIpPktFrame>,
        stream_tx: UnboundedSender<TcpStream>,
        socket_tx: UnboundedSender<TcpSocketCreation>,
        tcp_recv_buffer_size: u32,
        tcp_send_buffer_size: u32,
        live: LiveSockets,
        max_sockets: Option<usize>,
        refused: Arc<AtomicU64>,
    ) -> std::io::Result<()> {
        while let Some(frame) = tcp_rx.recv().await {
            let packet = match IpPacket::new_checked(frame.as_slice()) {
                Ok(p) => p,
                Err(err) => {
                    error!("invalid TCP IP packet: {:?}", err,);
                    continue;
                }
            };

            // Specially handle icmp packet by TCP interface.
            if matches!(packet.protocol(), IpProtocol::Icmp | IpProtocol::Icmpv6) {
                iface_ingress_tx
                    .send(frame)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
                iface_ingress_tx_avail.store(true, Ordering::Release);
                notify.notify_one();
                continue;
            }

            let src_ip = packet.src_addr();
            let dst_ip = packet.dst_addr();
            let payload = packet.payload();

            let packet = match TcpPacket::new_checked(payload) {
                Ok(p) => p,
                Err(err) => {
                    error!("invalid TCP err: {err}, src_ip: {src_ip}, dst_ip: {dst_ip}, payload: {payload:?}");
                    continue;
                }
            };
            let src_port = packet.src_port();
            let dst_port = packet.dst_port();

            let src_addr = SocketAddr::new(src_ip, src_port);
            let dst_addr = SocketAddr::new(dst_ip, dst_port);

            // Sentinel patch 3: one socket per connection, and no more than the limit. A
            // SYN sent again reaches the socket made for the first one: a second socket
            // would listen for good, its stream never opened. A SYN beyond the limit
            // reaches no socket, and smoltcp answers it with a reset.
            let key = (src_addr, dst_addr);
            let admitted = packet.syn() && !packet.ack() && {
                let live = live.lock();
                let full = max_sockets.is_some_and(|max| live.len() >= max);
                if full && !live.contains(&key) {
                    refused.fetch_add(1, Ordering::Relaxed);
                }
                !live.contains(&key) && !full
            };

            // TCP first handshake packet, create a new Connection
            if admitted {
                let mut socket = TcpSocket::new(
                    TcpSocketBuffer::new(vec![0u8; tcp_recv_buffer_size as usize]),
                    TcpSocketBuffer::new(vec![0u8; tcp_send_buffer_size as usize]),
                );
                socket.set_keep_alive(Some(Duration::from_secs(28)));
                // FIXME: It should follow system's setting. 7200 is Linux's default.
                socket.set_timeout(Some(Duration::from_secs(7200)));
                // NO ACK delay
                // socket.set_ack_delay(None);

                if let Err(err) = socket.listen(dst_addr) {
                    error!("listen error: {:?}", err);
                    continue;
                }

                trace!("created TCP connection for {} <-> {}", src_addr, dst_addr);
                live.lock().insert(key);

                let control = Arc::new(SpinMutex::new(TcpSocketControl {
                    send_buffer: RingBuffer::new(vec![0u8; tcp_send_buffer_size as usize]),
                    send_waker: None,
                    recv_buffer: RingBuffer::new(vec![0u8; tcp_recv_buffer_size as usize]),
                    recv_waker: None,
                    recv_state: TcpSocketState::Normal,
                    send_state: TcpSocketState::Normal,
                    reset: false,
                    dropped_at: None,
                }));

                stream_tx
                    .send(TcpStream {
                        src_addr,
                        dst_addr,
                        notify: notify.clone(),
                        control: control.clone(),
                    })
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
                socket_tx
                    .send(TcpSocketCreation {
                        control,
                        socket,
                        key,
                    })
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
            }

            // Pipeline tcp stream packet
            iface_ingress_tx
                .send(frame)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e))?;
            iface_ingress_tx_avail.store(true, Ordering::Release);
            notify.notify_one();
        }
        Ok(())
    }

    async fn handle_socket(
        notify: SharedNotify,
        mut device: VirtualDevice,
        mut iface: Interface,
        iface_ingress_tx_avail: Arc<AtomicBool>,
        mut sockets: HashMap<SocketHandle, (SharedControl, ConnectionKey)>,
        mut socket_rx: UnboundedReceiver<TcpSocketCreation>,
        live: LiveSockets,
        linger: Option<StdDuration>,
    ) -> std::io::Result<()> {
        let mut socket_set = SocketSet::new(vec![]);
        loop {
            while let Ok(TcpSocketCreation {
                control,
                socket,
                key,
            }) = socket_rx.try_recv()
            {
                let handle = socket_set.add(socket);
                sockets.insert(handle, (control, key));
            }

            let before_poll = Instant::now();
            let updated_sockets = iface.poll(before_poll, &mut device, &mut socket_set);
            if matches!(
                updated_sockets,
                smoltcp::iface::PollResult::SocketStateChanged
            ) {
                trace!("VirtDevice::poll costed {}", Instant::now() - before_poll);
            }

            // Check all the sockets' status
            let mut sockets_to_remove = Vec::new();
            // Sentinel patch 3: sockets aborted in this pass, and the next linger time.
            let mut aborted = false;
            let mut next_linger: Option<StdInstant> = None;
            let now = StdInstant::now();

            for (socket_handle, (control, _)) in sockets.iter() {
                let socket_handle = *socket_handle;
                let socket = socket_set.get_mut::<TcpSocket>(socket_handle);
                let mut control = control.lock();

                // Remove the socket only when it is in the closed state.
                if socket.state() == TcpState::Closed {
                    sockets_to_remove.push(socket_handle);

                    control.send_state = TcpSocketState::Closed;
                    control.recv_state = TcpSocketState::Closed;

                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                    if let Some(waker) = control.recv_waker.take() {
                        waker.wake();
                    }

                    trace!("closed TCP connection");
                    continue;
                }

                // Sentinel patch 3: a reset the stream asked for, or a close that
                // outlived the linger time since the stream was dropped. Aborting sends
                // a reset (RST) at the next poll; the socket then goes, as Closed. Without
                // this, a socket whose peer never acknowledges the FIN lives on for as
                // long as smoltcp retransmits it, uncounted.
                let lingered = match (control.dropped_at, linger) {
                    (Some(dropped), Some(linger)) => {
                        let due = dropped + linger;
                        if now < due {
                            next_linger = Some(next_linger.map_or(due, |next| next.min(due)));
                        }
                        now >= due
                    }
                    _ => false,
                };
                if control.reset || lingered {
                    trace!("aborting TCP connection, {:?}", socket.state());
                    socket.abort();
                    aborted = true;
                    continue;
                }

                // SHUT_WR — only close once the send_buffer has been fully
                // drained into the smoltcp socket.  Closing earlier transitions
                // the socket to FIN_WAIT_1, making can_send() return false, so
                // the send loop below never runs and the remaining data is lost.
                if matches!(control.send_state, TcpSocketState::Close)
                    && control.send_buffer.is_empty()
                {
                    trace!("closing TCP Write Half, {:?}", socket.state());

                    socket.close();
                    control.send_state = TcpSocketState::Closing;

                    // Sentinel patch 2: the FIN is queued, so a pending shutdown is done.
                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                }

                // Check if readable
                let mut wake_receiver = false;
                while socket.can_recv() && !control.recv_buffer.is_full() {
                    let result = socket.recv(|buffer| {
                        let n = control.recv_buffer.enqueue_slice(buffer);
                        (n, ())
                    });

                    match result {
                        Ok(..) => wake_receiver = true,
                        Err(err) => {
                            error!("socket recv error: {:?}, {:?}", err, socket.state());

                            // Don't know why. Abort the connection.
                            socket.abort();

                            if matches!(control.recv_state, TcpSocketState::Normal) {
                                control.recv_state = TcpSocketState::Closed;
                            }
                            wake_receiver = true;

                            // The socket will be recycled in the next poll.
                            break;
                        }
                    }
                }

                // If socket is not in ESTABLISH, FIN-WAIT-1, FIN-WAIT-2,
                // the local client have closed our receiver.
                let states = [
                    TcpState::Listen,
                    TcpState::SynReceived,
                    TcpState::Established,
                    TcpState::FinWait1,
                    TcpState::FinWait2,
                ];
                if matches!(control.recv_state, TcpSocketState::Normal)
                    && !socket.may_recv()
                    && !states.contains(&socket.state())
                {
                    trace!("closed TCP Read Half, {:?}", socket.state());

                    // Let TcpStream::poll_read returns EOF.
                    control.recv_state = TcpSocketState::Closed;
                    wake_receiver = true;
                }

                if wake_receiver && control.recv_waker.is_some() {
                    if let Some(waker) = control.recv_waker.take() {
                        waker.wake();
                    }
                }

                // Check if writable
                let mut wake_sender = false;
                while socket.can_send() && !control.send_buffer.is_empty() {
                    let result = socket.send(|buffer| {
                        let n = control.send_buffer.dequeue_slice(buffer);
                        (n, ())
                    });

                    match result {
                        Ok(..) => wake_sender = true,
                        Err(err) => {
                            error!("socket send error: {:?}, {:?}", err, socket.state());

                            // Don't know why. Abort the connection.
                            socket.abort();

                            if matches!(control.send_state, TcpSocketState::Normal) {
                                control.send_state = TcpSocketState::Closed;
                            }
                            wake_sender = true;

                            // The socket will be recycled in the next poll.
                            break;
                        }
                    }
                }

                if wake_sender && control.send_waker.is_some() {
                    if let Some(waker) = control.send_waker.take() {
                        waker.wake();
                    }
                }
            }

            for socket_handle in sockets_to_remove {
                if let Some((_, key)) = sockets.remove(&socket_handle) {
                    live.lock().remove(&key);
                }
                socket_set.remove(socket_handle);
            }

            // Ensure every loop iteration yields to the runtime. When egress
            // capacity is available OR when `poll_delay` returns ZERO ("re-poll
            // now"), this loop otherwise takes no `.await`, so under an active
            // flow it busy-spins. Because `handle_socket` and `handle_packet`
            // are arms of one `tokio::select!` future, a never-yielding
            // `handle_socket` never returns control to the sibling SYN-accept
            // arm: one core pins flat at 100% and new inbound connections are
            // starved (observed as connect timeouts with no SYN-ACK). A
            // cooperative `yield_now()` keeps the re-poll just as prompt while
            // letting `handle_packet` make progress. The timed-park path and the
            // 5 ms idle fallback are unchanged, so there is no missed-wake risk.
            // Sentinel patch 3: a socket just aborted has its reset to send, and goes
            // at the next pass, whatever smoltcp's timers say.
            if aborted || iface_ingress_tx_avail.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            } else {
                // Sentinel patch 1: with no smoltcp timer pending, sleep until notified.
                // Every event that needs a poll already notifies: incoming packets, and
                // reads, writes, shutdowns and drops on a TcpStream. The upstream 5 ms
                // fallback woke the runner 200 times a second on an idle phone.
                let timer = iface
                    .poll_delay(before_poll, &socket_set)
                    .map(StdDuration::from);
                // Sentinel patch 3: wake for the next linger time too.
                let until_linger = next_linger.map(|due| due.saturating_duration_since(now));
                let timer = match (timer, until_linger) {
                    (Some(timer), Some(linger)) => Some(timer.min(linger)),
                    (timer, linger) => timer.or(linger),
                };
                match timer {
                    Some(next_duration) if next_duration != StdDuration::ZERO => {
                        let _ = tokio::time::timeout(next_duration, notify.notified()).await;
                    }
                    Some(_) => tokio::task::yield_now().await,
                    None => notify.notified().await,
                }
            }
        }
    }
}

pub struct TcpListener {
    stream_rx: UnboundedReceiver<TcpStream>,
}

impl TcpListener {
    pub(super) fn new(
        tcp_rx: Receiver<AnyIpPktFrame>,
        stack_tx: Sender<AnyIpPktFrame>,
        mtu: usize,
        tcp_recv_buffer_size: u32,
        tcp_send_buffer_size: u32,
        limits: TcpLimits,
    ) -> std::io::Result<(Runner, Self)> {
        let (mut device, iface_ingress_tx, iface_ingress_tx_avail) =
            VirtualDevice::new(stack_tx, mtu);
        let iface = Self::create_interface(&mut device)?;

        let (stream_tx, stream_rx) = unbounded_channel();

        let runner = TcpListenerRunner::create(
            device,
            iface,
            iface_ingress_tx,
            iface_ingress_tx_avail,
            tcp_rx,
            stream_tx,
            HashMap::new(),
            tcp_recv_buffer_size,
            tcp_send_buffer_size,
            limits,
        );

        Ok((runner, Self { stream_rx }))
    }

    fn create_interface<D>(device: &mut D) -> std::io::Result<Interface>
    where
        D: Device + ?Sized,
    {
        let mut iface_config = InterfaceConfig::new(HardwareAddress::Ip);
        iface_config.random_seed = rand::random();
        let mut iface = Interface::new(iface_config, device, Instant::now());
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs
                .push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0))
                .expect("iface IPv4");
            ip_addrs
                .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0))
                .expect("iface IPv6");
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::new(0, 0, 0, 1))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, e))?;
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::AddrNotAvailable, e))?;
        iface.set_any_ip(true);
        Ok(iface)
    }
}

impl Stream for TcpListener {
    type Item = (TcpStream, SocketAddr, SocketAddr);

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        self.stream_rx.poll_recv(cx).map(|stream| {
            stream.map(|stream| {
                let local_addr = *stream.local_addr();
                let remote_addr: SocketAddr = *stream.remote_addr();
                (stream, local_addr, remote_addr)
            })
        })
    }
}

pub struct TcpStream {
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    notify: SharedNotify,
    control: SharedControl,
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        let mut control = self.control.lock();
        // Sentinel patch 3: from now on the socket has the linger time to close.
        control.dropped_at = Some(StdInstant::now());

        if matches!(control.recv_state, TcpSocketState::Normal) {
            control.recv_state = TcpSocketState::Close;
        }

        if matches!(control.send_state, TcpSocketState::Normal) {
            control.send_state = TcpSocketState::Close;
        }

        self.notify.notify_one();
    }
}

impl TcpStream {
    pub fn local_addr(&self) -> &SocketAddr {
        &self.src_addr
    }

    pub fn remote_addr(&self) -> &SocketAddr {
        &self.dst_addr
    }

    /// Sentinel patch 3: end the connection at once with a reset (RST), rather than
    /// the close that dropping the stream starts. Data not yet sent is discarded.
    pub fn reset(self) {
        self.control.lock().reset = true;
        // Dropping the stream wakes the runner.
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut control = self.control.lock();

        // Read from buffer
        if control.recv_buffer.is_empty() {
            // If socket is already closed / half closed, just return EOF directly.
            if matches!(control.recv_state, TcpSocketState::Closed) {
                return Ok(()).into();
            }

            // Nothing could be read. Wait for notify.
            if let Some(old_waker) = control.recv_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }

            return Poll::Pending;
        }

        let recv_buf = buf.initialize_unfilled();
        let n = control.recv_buffer.dequeue_slice(recv_buf);
        buf.advance(n);

        if n > 0 {
            self.notify.notify_one();
        }

        Ok(()).into()
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut control = self.control.lock();

        // If state == Close | Closing | Closed, the TCP stream WR half is closed.
        if !matches!(control.send_state, TcpSocketState::Normal) {
            return Err(std::io::ErrorKind::BrokenPipe.into()).into();
        }

        // Write to buffer

        if control.send_buffer.is_full() {
            if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
                if !old_waker.will_wake(cx.waker()) {
                    old_waker.wake();
                }
            }

            return Poll::Pending;
        }

        let n = control.send_buffer.enqueue_slice(buf);

        if n > 0 {
            self.notify.notify_one();
        }

        Ok(n).into()
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Ok(()).into()
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut control = self.control.lock();

        // Sentinel patch 2: the write half is shut down once the FIN is queued (Closing),
        // not when the whole connection has closed. Waiting for Closed made a relay wait
        // out TIME-WAIT (10 s) whenever the server closed first.
        if matches!(
            control.send_state,
            TcpSocketState::Closing | TcpSocketState::Closed
        ) {
            return Ok(()).into();
        }

        // SHUT_WR
        if matches!(control.send_state, TcpSocketState::Normal) {
            control.send_state = TcpSocketState::Close;
        }

        if let Some(old_waker) = control.send_waker.replace(cx.waker().clone()) {
            if !old_waker.will_wake(cx.waker()) {
                old_waker.wake();
            }
        }

        self.notify.notify_one();

        Poll::Pending
    }
}
