// SPDX-License-Identifier: GPL-3.0-or-later
//! Server Name Indication from a TLS ClientHello (SRS CM-02).
//!
//! Reads only the first TLS record of a connection, never decrypts anything, and never
//! stores the bytes. Every length is bounds-checked: input comes from untrusted apps.

/// Result of scanning the first bytes a client sent on a TCP connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientHelloScan {
    /// Not a TLS handshake; stop looking.
    NotTls,
    /// Looks like TLS but the first record is incomplete. `total` bytes are needed.
    /// Modern ClientHellos with post-quantum key shares are bigger than one TCP segment.
    NeedMore { total: usize },
    /// The full first record was read. `None` if it carries no usable server name
    /// (no SNI extension, or a malformed one).
    Done(Option<String>),
}

const RECORD_HEADER: usize = 5;
/// TLS 1.3 limit for a plaintext record (2^14) plus slack some stacks use.
const MAX_RECORD: usize = 16_384 + 256;
const HANDSHAKE: u8 = 0x16;
const CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const NAME_TYPE_HOST: u8 = 0x00;

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
    if buf.len() < RECORD_HEADER {
        return ClientHelloScan::NeedMore {
            total: RECORD_HEADER,
        };
    }
    if buf[1] != 0x03 {
        return ClientHelloScan::NotTls;
    }
    let record_len = usize::from(u16::from_be_bytes([buf[3], buf[4]]));
    if record_len == 0 || record_len > MAX_RECORD {
        return ClientHelloScan::NotTls;
    }
    let total = RECORD_HEADER + record_len;
    if buf.len() < total {
        return ClientHelloScan::NeedMore { total };
    }
    ClientHelloScan::Done(server_name(&buf[RECORD_HEADER..total]))
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

fn server_name(record: &[u8]) -> Option<String> {
    let mut r = Reader { data: record };
    if r.u8()? != CLIENT_HELLO {
        return None;
    }
    // A ClientHello split across several records is cut short here; we then parse
    // what we have and usually still find the name, which comes early in practice.
    let declared = r.u24()?;
    let mut body = Reader {
        data: &r.data[..declared.min(r.data.len())],
    };
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
