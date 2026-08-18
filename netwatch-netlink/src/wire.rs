//! Netlink wire format primitives.
//!
//! Netlink messages are native endian and 4-byte aligned: a 16-byte
//! `nlmsghdr`, a fixed per-family header, then a list of attributes, each a
//! 4-byte `rtattr` header (length including the header, then type) followed
//! by the padded payload.

/// Length of `nlmsghdr`.
pub(crate) const HEADER_LEN: usize = 16;

/// Rounds `len` up to the 4-byte netlink alignment.
pub(crate) const fn align(len: usize) -> usize {
    (len + 3) & !3
}

/// A parsed `nlmsghdr`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Header {
    pub(crate) len: u32,
    pub(crate) kind: u16,
    pub(crate) seq: u32,
}

impl Header {
    /// Parses the header from the start of `data`.
    pub(crate) fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < HEADER_LEN {
            return None;
        }
        Some(Self {
            len: read_u32(data, 0)?,
            kind: read_u16(data, 4)?,
            // offset 6: flags, only meaningful in requests
            seq: read_u32(data, 8)?,
            // offset 12: pid, unused
        })
    }
}

/// Appends an `nlmsghdr` for a request whose payload is `payload_len` bytes.
pub(crate) fn push_header(buf: &mut Vec<u8>, kind: u16, flags: u16, seq: u32, payload_len: usize) {
    let len = (HEADER_LEN + payload_len) as u32;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes()); // pid: kernel fills in the sender
}

/// Iterator over the attributes of a message payload.
///
/// Yields `(type, payload)` pairs and stops at the first malformed
/// attribute.
pub(crate) struct AttrIter<'a> {
    data: &'a [u8],
}

impl<'a> AttrIter<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}

impl<'a> Iterator for AttrIter<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let len = read_u16(self.data, 0)? as usize;
        let kind = read_u16(self.data, 2)?;
        if len < 4 || len > self.data.len() {
            return None;
        }
        let payload = &self.data[4..len];
        self.data = self.data.get(align(len)..).unwrap_or_default();
        Some((kind, payload))
    }
}

pub(crate) fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes = data.get(offset..offset + 2)?;
    Some(u16::from_ne_bytes(
        bytes.try_into().expect("length checked"),
    ))
}

pub(crate) fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset + 4)?;
    Some(u32::from_ne_bytes(
        bytes.try_into().expect("length checked"),
    ))
}

pub(crate) fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
    read_u32(data, offset).map(|v| v as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align() {
        assert_eq!(align(0), 0);
        assert_eq!(align(1), 4);
        assert_eq!(align(4), 4);
        assert_eq!(align(5), 8);
    }

    #[test]
    fn test_header_roundtrip() {
        let mut buf = Vec::new();
        push_header(&mut buf, 18, 0x301, 7, 16);
        let header = Header::parse(&buf).unwrap();
        assert_eq!(header.len, 32);
        assert_eq!(header.kind, 18);
        assert_eq!(read_u16(&buf, 6), Some(0x301));
        assert_eq!(header.seq, 7);
    }

    #[test]
    fn test_attr_iter() {
        let mut data = Vec::new();
        // attr 1: type 3, payload "lo\0" (len 7, padded to 8)
        data.extend_from_slice(&7u16.to_ne_bytes());
        data.extend_from_slice(&3u16.to_ne_bytes());
        data.extend_from_slice(b"lo\0\0");
        // attr 2: type 4, payload u32
        data.extend_from_slice(&8u16.to_ne_bytes());
        data.extend_from_slice(&4u16.to_ne_bytes());
        data.extend_from_slice(&1500u32.to_ne_bytes());

        let attrs: Vec<_> = AttrIter::new(&data).collect();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[0], (3, &b"lo\0"[..]));
        assert_eq!(attrs[1].0, 4);
        assert_eq!(read_u32(attrs[1].1, 0), Some(1500));
    }

    #[test]
    fn test_attr_iter_stops_on_malformed() {
        // Claims 12 bytes but only 8 are present.
        let mut data = Vec::new();
        data.extend_from_slice(&12u16.to_ne_bytes());
        data.extend_from_slice(&1u16.to_ne_bytes());
        data.extend_from_slice(&0u32.to_ne_bytes());
        assert_eq!(AttrIter::new(&data).count(), 0);
    }
}
