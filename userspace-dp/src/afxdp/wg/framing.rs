//! WireGuard transport-data record framing.
//!
//! On the wire (per WireGuard whitepaper §5.4.6):
//!
//! ```text
//!   0       1       2       3       4
//!   +-------+-------+-------+-------+
//!   | type=4|       reserved        |
//!   +-------+-------+-------+-------+
//!   |        receiver_index         |
//!   +-------+-------+-------+-------+
//!   |                               |
//!   +          counter              +
//!   |                               |
//!   +-------+-------+-------+-------+
//!   |  encrypted_payload || tag16   |
//!   +-------------------------------+
//! ```
//!
//! `receiver_index` and `counter` are little-endian. The encrypted
//! payload is ChaCha20-Poly1305 with a 96-bit nonce of
//! `counter.to_le_bytes() || [0,0,0,0]`. snow's u64 nonce parameter
//! produces this exact layout, so we pass `counter` straight through.

use super::{WG_DATA_HEADER_LEN, WG_TYPE_DATA};

/// Encode the WG transport-data header (16 bytes) into the front
/// of `out`. Returns the header length so the caller can fill the
/// rest with the ciphertext.
///
/// Pure byte-shuffling. No allocations.
#[inline]
pub(crate) fn encode_data_header(
    out: &mut [u8],
    receiver_index: u32,
    counter: u64,
) -> Option<usize> {
    let hdr = out.get_mut(..WG_DATA_HEADER_LEN)?;
    hdr[0] = WG_TYPE_DATA;
    hdr[1] = 0;
    hdr[2] = 0;
    hdr[3] = 0;
    hdr[4..8].copy_from_slice(&receiver_index.to_le_bytes());
    hdr[8..16].copy_from_slice(&counter.to_le_bytes());
    Some(WG_DATA_HEADER_LEN)
}

/// Parsed WG data record. Borrows from the input buffer; the
/// `ciphertext` includes the Poly1305 tag (snow's `read_message`
/// expects ciphertext||tag as its input).
#[derive(Debug, Clone, Copy)]
pub(crate) struct ParsedDataHeader<'a> {
    pub receiver_index: u32,
    pub counter: u64,
    pub ciphertext: &'a [u8],
}

/// Parse the WG transport-data header from the front of `buf`.
///
/// Returns `None` if `buf` is too short or the type byte is not 4.
/// All errors return `None` rather than a typed enum so that the
/// hot path can just `?` the result; callers track failure counts.
#[inline]
pub(crate) fn parse_data_header(buf: &[u8]) -> Option<ParsedDataHeader<'_>> {
    if buf.len() < WG_DATA_HEADER_LEN {
        return None;
    }
    if buf[0] != WG_TYPE_DATA {
        return None;
    }
    // Bytes 1..4 are "reserved" per the WG spec; whitepaper §5.4.6
    // says they MUST be zero on transmit, but a receiver MUST NOT
    // reject non-zero values. We mirror that — ignore them.
    let receiver_index = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let counter = u64::from_le_bytes([
        buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    ]);
    Some(ParsedDataHeader {
        receiver_index,
        counter,
        ciphertext: &buf[WG_DATA_HEADER_LEN..],
    })
}

#[cfg(test)]
mod framing_tests {
    use super::*;

    #[test]
    fn roundtrip_header() {
        let mut buf = [0u8; 32];
        let n = encode_data_header(&mut buf, 0xdeadbeef, 0x0102030405060708).unwrap();
        assert_eq!(n, WG_DATA_HEADER_LEN);
        let parsed = parse_data_header(&buf[..WG_DATA_HEADER_LEN]).unwrap();
        assert_eq!(parsed.receiver_index, 0xdeadbeef);
        assert_eq!(parsed.counter, 0x0102030405060708);
        assert_eq!(parsed.ciphertext.len(), 0);
    }

    #[test]
    fn rejects_wrong_type() {
        let mut buf = [0u8; WG_DATA_HEADER_LEN];
        buf[0] = 1; // initiation, not data
        assert!(parse_data_header(&buf).is_none());
    }

    #[test]
    fn rejects_short_buf() {
        let buf = [4u8; 8];
        assert!(parse_data_header(&buf).is_none());
    }

    #[test]
    fn little_endian_counter() {
        // Spec: counter is little-endian on the wire. Verify byte
        // layout matches what an interoperating implementation
        // would expect (and what snow's ChaCha20 nonce builder
        // consumes when we pass the same u64).
        let mut buf = [0u8; WG_DATA_HEADER_LEN];
        encode_data_header(&mut buf, 0, 1).unwrap();
        assert_eq!(buf[8], 1);
        assert_eq!(&buf[9..16], &[0u8; 7]);
    }

    #[test]
    fn ignores_reserved_bytes_on_parse() {
        // Whitepaper §5.4.6: receiver MUST NOT reject non-zero
        // reserved bytes. Mirror that — accept them.
        let mut buf = [0u8; WG_DATA_HEADER_LEN];
        buf[0] = 4;
        buf[1] = 0xaa;
        buf[2] = 0xbb;
        buf[3] = 0xcc;
        buf[4..8].copy_from_slice(&7u32.to_le_bytes());
        assert!(parse_data_header(&buf).is_some());
    }
}
