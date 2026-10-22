// SPDX-License-Identifier: GPL-3.0-or-later
//! The packet stack (smoltcp through the patched netstack-smoltcp, ADR-0006): what apps
//! send through the tunnel, before the relay sees any of it. Each input is a run of
//! packets, each after its length in two bytes. The connections they open are answered
//! and reset, dropped, or left open, as the relay would; the datagrams are read. Nothing
//! reaches the network.
//!
//! The stack drops a packet whose checksums are wrong, which a mutated packet nearly
//! always is. An input whose first byte is even therefore has its packets' IPv4, TCP and
//! UDP checksums set right before they are sent, so that the fuzzer gets past them.
#![no_main]

use std::sync::atomic::AtomicU64;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use futures::{FutureExt, SinkExt, StreamExt};
use libfuzzer_sys::fuzz_target;
use netstack_smoltcp::StackBuilder;
use tokio::io::AsyncWriteExt;

static RUNTIME: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("a runtime")
});

fuzz_target!(|data: &[u8]| RUNTIME.block_on(run(data)));

async fn run(data: &[u8]) {
    // As the engine builds it, with smaller limits so that inputs reach them.
    let (stack, runner, udp, tcp) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .mtu(1500)
        .tcp_send_buffer_size(4096)
        .tcp_recv_buffer_size(4096)
        .tcp_max_sockets(4, Arc::new(AtomicU64::new(0)))
        .tcp_linger(Duration::from_millis(1))
        .build()
        .expect("the stack builds");
    let runner = tokio::spawn(runner.expect("a TCP runner"));
    let (mut datagrams, _) = udp.expect("a UDP socket").split();
    let mut tcp = tcp.expect("a TCP listener");
    let (mut to_stack, mut from_stack) = stack.split();
    let mut open = Vec::new();
    let mut accepted = 0usize;

    let Some((first, mut rest)) = data.split_first() else {
        return;
    };
    let repair = first % 2 == 0;
    while let [high, low, tail @ ..] = rest {
        let len = usize::from(u16::from_be_bytes([*high, *low])).min(tail.len());
        let (packet, after) = tail.split_at(len);
        rest = after;
        let mut packet = packet.to_vec();
        if repair {
            set_checksums(&mut packet);
        }
        // A packet the stack cannot read is refused, and the engine drops it (A-52).
        let _ = to_stack.send(packet).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        while let Some(Some(Ok(out))) = from_stack.next().now_or_never() {
            check_sent(&out);
        }
        while let Some(Some(_)) = datagrams.next().now_or_never() {}
        while let Some(Some((mut stream, _, _))) = tcp.next().now_or_never() {
            accepted += 1;
            match accepted % 3 {
                0 => {
                    let _ = stream.write(b"answer").now_or_never();
                    stream.reset();
                }
                1 => drop(stream),
                _ => open.push(stream),
            }
        }
    }
    drop(open);
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    runner.abort();
}

/// What the stack sends towards the app is an IP packet as long as it says.
fn check_sent(packet: &[u8]) {
    match packet.first().map(|b| b >> 4) {
        Some(4) => {
            assert!(packet.len() >= 20, "short IPv4 packet");
            let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
            assert_eq!(total, packet.len(), "IPv4 length");
        }
        Some(6) => {
            assert!(packet.len() >= 40, "short IPv6 packet");
            let payload = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
            assert_eq!(payload + 40, packet.len(), "IPv6 length");
        }
        other => panic!("not an IP packet: version {other:?}"),
    }
}

/// Sets the IPv4 header's checksum, and a TCP or UDP checksum directly after an IPv4 or
/// IPv6 header, as a sender would. Leaves what it cannot place alone.
fn set_checksums(packet: &mut [u8]) {
    let (pseudo, start) = match packet.first().map(|b| b >> 4) {
        Some(4) if packet.len() >= 20 => {
            let header = usize::from(packet[0] & 0x0f) * 4;
            if header < 20 || header > packet.len() {
                return;
            }
            packet[10..12].fill(0);
            let sum = finish(add(0, &packet[..header]));
            packet[10..12].copy_from_slice(&sum.to_be_bytes());
            let length = (packet.len() - header) as u32;
            let mut pseudo = add(0, &packet[12..20]);
            pseudo += u32::from(packet[9]) + length;
            (pseudo, header)
        }
        Some(6) if packet.len() >= 40 => {
            let length = (packet.len() - 40) as u32;
            let mut pseudo = add(0, &packet[8..40]);
            pseudo += u32::from(packet[6]) + length;
            (pseudo, 40)
        }
        _ => return,
    };
    let protocol = if packet[0] >> 4 == 4 {
        packet[9]
    } else {
        packet[6]
    };
    let at = match protocol {
        6 => start + 16,
        17 => start + 6,
        _ => return,
    };
    if at + 2 > packet.len() {
        return;
    }
    packet[at..at + 2].fill(0);
    let mut sum = finish(add(pseudo, &packet[start..]));
    if protocol == 17 && sum == 0 {
        sum = 0xffff;
    }
    packet[at..at + 2].copy_from_slice(&sum.to_be_bytes());
}

/// `sum` plus `bytes` as big-endian 16-bit words, the last padded with a zero.
fn add(mut sum: u32, bytes: &[u8]) -> u32 {
    for pair in bytes.chunks(2) {
        let word = u16::from_be_bytes([pair[0], pair.get(1).copied().unwrap_or(0)]);
        sum += u32::from(word);
    }
    sum
}

/// The ones' complement of the folded sum.
fn finish(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
