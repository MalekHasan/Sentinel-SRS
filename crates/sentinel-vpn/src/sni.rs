// SPDX-License-Identifier: GPL-3.0-or-later
//! Server Name Indication from a TLS ClientHello (SRS CM-02).
//!
//! Reads only the ClientHello at the start of a connection, joined from the handshake
//! records it is split into, never decrypts anything, and never stores the bytes. Every
//! length is bounds-checked, and at most [`MAX_HELLO`] bytes are read: input comes from
//! untrusted apps.

/// Result of scanning the first bytes a client sent on a TCP connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientHelloScan {
    /// Not a TLS handshake; stop looking.
    NotTls,
    /// Looks like TLS but the ClientHello is incomplete: at least `total` bytes are
    /// needed. Modern ClientHellos with post-quantum key shares are bigger than one TCP
    /// segment, and a ClientHello may be split into several records.
    NeedMore { total: usize },
    /// The whole ClientHello was read. `None` if it carries no usable server name (no SNI
    /// extension, or a malformed one).
    Done(Option<String>),
    /// TLS, but its ClientHello cannot be read: longer than [`MAX_HELLO`] bytes of
    /// records, or broken across records. A server may still accept it and see a name
    /// that this scan does not (audit finding A-03).
    Unreadable,
}

const RECORD_HEADER: usize = 5;
/// TLS 1.3 limit for a plaintext record (2^14) plus slack some stacks use.
const MAX_RECORD: usize = 16_384 + 256;
/// The most bytes of records read to find the ClientHello: twice the largest record.
/// Real ClientHellos, with post-quantum key shares, take a few kilobytes.
pub const MAX_HELLO: usize = 2 * (RECORD_HEADER + MAX_RECORD);
/// The handshake message header: its type and a 24-bit length.
const MESSAGE_HEADER: usize = 4;
const HANDSHAKE: u8 = 0x16;
const CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const NAME_TYPE_HOST: u8 = 0x00;

/// Scan what a client sent first on a TCP connection for the server name of its
/// ClientHello. A ClientHello split into several handshake records, as TLS allows and
/// servers accept, is joined again (audit finding A-03).
pub fn scan_client_hello(buf: &[u8]) -> ClientHelloScan {
    match buf.first() {
        None => {
            return ClientHelloScan::NeedMore {
                total: RECORD_HEADER,
            };
        }
        Some(&HANDSHAKE) => {}
        Some(_) => return ClientHelloScan::NotTls,
    }
    // The handshake bytes, joined from the records they came in.
    let mut message = Vec::new();
    let mut at = 0;
    loop {
        // No more records fit in what the scan reads.
        if at + RECORD_HEADER > MAX_HELLO {
            return ClientHelloScan::Unreadable;
        }
        let Some(header) = buf.get(at..at + RECORD_HEADER) else {
            return ClientHelloScan::NeedMore {
                total: at + RECORD_HEADER,
            };
        };
        if header[1] != 0x03 {
            return if at == 0 {
                ClientHelloScan::NotTls
            } else {
                ClientHelloScan::Unreadable
            };
        }
        // Handshake messages may not be interleaved with other records, and records
        // may not be empty or oversized.
        let record_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        if header[0] != HANDSHAKE || record_len == 0 || record_len > MAX_RECORD {
            return ClientHelloScan::Unreadable;
        }
        let end = at + RECORD_HEADER + record_len;
        if end > MAX_HELLO {
            return ClientHelloScan::Unreadable;
        }
        let Some(fragment) = buf.get(at + RECORD_HEADER..end) else {
            return ClientHelloScan::NeedMore { total: end };
        };
        message.extend_from_slice(fragment);
        at = end;
        if message[0] != CLIENT_HELLO {
            return ClientHelloScan::Done(None);
        }
        if let Some(length) = (Reader {
            data: &message[1..],
        })
        .u24()
        {
            let total = MESSAGE_HEADER + length;
            if total > MAX_HELLO {
                return ClientHelloScan::Unreadable;
            }
            if message.len() >= total {
                return ClientHelloScan::Done(server_name(&message[MESSAGE_HEADER..total]));
            }
        }
    }
}

/// A cursor that refuses to read past the end instead of panicking.
struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let (&first, rest) = self.data.split_first()?;
        self.data = rest;
        Some(first)
    }

    fn u16(&mut self) -> Option<u16> {
        let bytes = self.take(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u24(&mut self) -> Option<usize> {
        let b = self.take(3)?;
        Some((usize::from(b[0]) << 16) | (usize::from(b[1]) << 8) | usize::from(b[2]))
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.data.len() < n {
            return None;
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Some(head)
    }

    fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u8()?);
        self.take(n)
    }

    fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = usize::from(self.u16()?);
        self.take(n)
    }
}

/// The server name in a ClientHello's body, the message without its header.
fn server_name(hello: &[u8]) -> Option<String> {
    let mut body = Reader { data: hello };
    body.take(2)?; // legacy_version
    body.take(32)?; // random
    body.vec8()?; // legacy_session_id
    body.vec16()?; // cipher_suites
    body.vec8()?; // legacy_compression_methods
    let mut extensions = Reader {
        data: body.vec16()?,
    };
    while !extensions.data.is_empty() {
        let kind = extensions.u16()?;
        let data = extensions.vec16()?;
        if kind == EXT_SERVER_NAME {
            return host_name(data);
        }
    }
    None
}

fn host_name(ext: &[u8]) -> Option<String> {
    let mut list = Reader {
        data: Reader { data: ext }.vec16()?,
    };
    while !list.data.is_empty() {
        let kind = list.u8()?;
        let name = list.vec16()?;
        if kind == NAME_TYPE_HOST {
            return valid_hostname(name);
        }
    }
    None
}

/// Accept only what a real hostname can contain, lower-cased, without a trailing dot.
fn valid_hostname(raw: &[u8]) -> Option<String> {
    let raw = raw.strip_suffix(b".").unwrap_or(raw);
    if raw.is_empty() || raw.len() > 253 {
        return None;
    }
    if !raw
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return None;
    }
    if raw
        .split(|&b| b == b'.')
        .any(|label| label.is_empty() || label.len() > 63)
    {
        return None;
    }
    Some(String::from_utf8_lossy(raw).to_ascii_lowercase())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build a minimal but well-formed ClientHello with the given extensions.
    pub(crate) fn client_hello(extensions: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut ext = Vec::new();
        for (kind, data) in extensions {
            ext.extend_from_slice(&kind.to_be_bytes());
            ext.extend_from_slice(&(data.len() as u16).to_be_bytes());
            ext.extend_from_slice(data);
        }
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[7u8; 32]); // random
        body.push(32);
        body.extend_from_slice(&[9u8; 32]); // session id
        body.extend_from_slice(&[0x00, 0x04, 0x13, 0x01, 0x13, 0x02]); // two suites
        body.extend_from_slice(&[0x01, 0x00]); // null compression
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut hs = vec![CLIENT_HELLO];
        hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        hs.extend_from_slice(&body);

        let mut record = vec![HANDSHAKE, 0x03, 0x01];
        record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
        record.extend_from_slice(&hs);
        record
    }

    pub(crate) fn sni_ext(name: &str) -> (u16, Vec<u8>) {
        let mut entry = vec![NAME_TYPE_HOST];
        entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
        entry.extend_from_slice(name.as_bytes());
        let mut data = (entry.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&entry);
        (EXT_SERVER_NAME, data)
    }

    #[test]
    fn finds_server_name_after_other_extensions() {
        // Browsers randomise extension order, and post-quantum key shares are large.
        let key_share = (0x0033, vec![0xAB; 1300]);
        let hello = client_hello(&[
            (0x002b, vec![0x02, 0x03, 0x04]),
            key_share,
            sni_ext("Example.COM."),
        ]);
        assert!(hello.len() > 1400);
        assert_eq!(
            scan_client_hello(&hello),
            ClientHelloScan::Done(Some("example.com".into()))
        );
    }

    #[test]
    fn asks_for_the_rest_of_a_split_record() {
        let hello = client_hello(&[(0x0033, vec![0; 1500]), sni_ext("a.example")]);
        let first_segment = &hello[..1460];
        assert_eq!(
            scan_client_hello(first_segment),
            ClientHelloScan::NeedMore { total: hello.len() }
        );
        assert_eq!(
            scan_client_hello(&hello[..3]),
            ClientHelloScan::NeedMore { total: 5 }
        );
    }

    /// The handshake message of `hello` again, split into records of the given sizes,
    /// and the rest in one record.
    pub(crate) fn in_records(hello: &[u8], sizes: &[usize]) -> Vec<u8> {
        let mut message = &hello[RECORD_HEADER..];
        let mut out = Vec::new();
        for &size in sizes.iter().chain(std::iter::once(&usize::MAX)) {
            let (fragment, rest) = message.split_at(size.min(message.len()));
            out.extend_from_slice(&[HANDSHAKE, 0x03, 0x01]);
            out.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
            out.extend_from_slice(fragment);
            message = rest;
            if message.is_empty() {
                break;
            }
        }
        out
    }

    /// Audit finding A-03: a ClientHello split into several records, as TLS allows and
    /// servers accept, still gives its name, however small the pieces.
    #[test]
    fn joins_a_client_hello_split_into_records() {
        let hello = client_hello(&[(0x0033, vec![0xAB; 1300]), sni_ext("blocked.example")]);
        for sizes in [vec![40], vec![1, 1, 1, 1, 1], vec![100; 13], vec![1; 400]] {
            let split = in_records(&hello, &sizes);
            assert!(split.len() > hello.len());
            assert_eq!(
                scan_client_hello(&split),
                ClientHelloScan::Done(Some("blocked.example".into())),
                "{sizes:?}"
            );
            // Any prefix asks for more, never for what it has.
            for len in [3, 5, 6, 47, split.len() / 2, split.len() - 1] {
                match scan_client_hello(&split[..len]) {
                    ClientHelloScan::NeedMore { total } => assert!(total > len, "{len}"),
                    other => panic!("{sizes:?} cut at {len}: {other:?}"),
                }
            }
        }
    }

    /// TLS whose ClientHello is broken across records, or longer than this scan reads,
    /// is told apart from a ClientHello without a name.
    #[test]
    fn a_broken_or_endless_client_hello_is_unreadable() {
        let hello = client_hello(&[(0x0033, vec![0xAB; 600]), sni_ext("blocked.example")]);
        let split = in_records(&hello, &[50]);
        let second = RECORD_HEADER + 50;

        // Another kind of record before the ClientHello is complete.
        let mut interleaved = split.clone();
        interleaved[second] = 0x17;
        assert_eq!(scan_client_hello(&interleaved), ClientHelloScan::Unreadable);

        // An empty record.
        let mut empty = split[..second].to_vec();
        empty.extend_from_slice(&[HANDSHAKE, 0x03, 0x01, 0, 0]);
        empty.extend_from_slice(&split[second..]);
        assert_eq!(scan_client_hello(&empty), ClientHelloScan::Unreadable);

        // A ClientHello that says it is longer than the scan reads.
        let mut long = hello.clone();
        long[RECORD_HEADER + 1..RECORD_HEADER + 4].copy_from_slice(&[0x01, 0x00, 0x00]);
        assert_eq!(scan_client_hello(&long), ClientHelloScan::Unreadable);

        // Pieces so small that the records outgrow the limit before the ClientHello ends.
        let big = client_hello(&[(0x0033, vec![0xAB; 7000]), sni_ext("blocked.example")]);
        let tiny = in_records(&big, &vec![1; 7000]);
        assert!(tiny.len() > MAX_HELLO);
        assert_eq!(scan_client_hello(&tiny), ClientHelloScan::Unreadable);
        assert_eq!(
            scan_client_hello(&tiny[..MAX_HELLO]),
            ClientHelloScan::Unreadable,
            "known before the limit is read"
        );

        // A first message that is not a ClientHello carries no name to look for.
        let mut not_hello = hello.clone();
        not_hello[RECORD_HEADER] = 0x02;
        assert_eq!(scan_client_hello(&not_hello), ClientHelloScan::Done(None));
    }

    #[test]
    fn handles_no_sni_and_non_tls() {
        assert_eq!(
            scan_client_hello(&client_hello(&[(0x000a, vec![0, 2, 0, 29])])),
            ClientHelloScan::Done(None)
        );
        assert_eq!(
            scan_client_hello(b"GET / HTTP/1.1\r\n"),
            ClientHelloScan::NotTls
        );
        assert_eq!(
            scan_client_hello(b"SSH-2.0-OpenSSH"),
            ClientHelloScan::NotTls
        );
    }

    #[test]
    fn rejects_hostile_names() {
        for bad in [
            "",
            "a..b",
            "evil\u{0}.com",
            "x y.com",
            &"a".repeat(64),
            "ü.com",
        ] {
            let hello = client_hello(&[sni_ext(bad)]);
            assert_eq!(
                scan_client_hello(&hello),
                ClientHelloScan::Done(None),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn never_panics_on_truncated_or_corrupted_input() {
        let hello = client_hello(&[(0x0033, vec![1; 200]), sni_ext("x.example")]);
        for len in 0..hello.len() {
            let _ = scan_client_hello(&hello[..len]);
        }
        // Flip every byte in turn; the parser must stay in bounds.
        for i in 0..hello.len() {
            let mut corrupted = hello.clone();
            corrupted[i] ^= 0xFF;
            let _ = scan_client_hello(&corrupted);
        }
        // Simple deterministic pseudo-random inputs.
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        for _ in 0..20_000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len = (state % 600) as usize;
            let mut data: Vec<u8> = (0..len).map(|i| (state >> (i % 56)) as u8).collect();
            if let Some(first) = data.first_mut() {
                *first = HANDSHAKE;
            }
            let _ = scan_client_hello(&data);
        }
    }
}
