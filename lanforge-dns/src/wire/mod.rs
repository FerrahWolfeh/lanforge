//! Zero-allocation DNS wire parser for hot-path routing.
//!
//! Replaces full Hickory Message parsing for local/upstream routing decisions.
//! Optimized for performance by avoiding UTF-8 validation and heap allocations.

use std::net::IpAddr;

pub mod qtypes;

/// Simple view into the DNS message header.
pub struct WireHeader<'a> {
    data: &'a [u8],
}

impl<'a> WireHeader<'a> {
    /// Parses the header from the start of the message.
    #[must_use]
    pub const fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        Some(Self { data })
    }

    #[inline]
    #[must_use]
    #[allow(dead_code)]
    pub fn id(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    #[inline]
    #[must_use]
    pub fn is_query(&self) -> bool {
        (self.data[2] & 0x80) == 0
    }

    #[inline]
    #[must_use]
    #[allow(dead_code)]
    pub fn rd(&self) -> bool {
        (self.data[2] & 0x01) != 0
    }

    #[inline]
    #[must_use]
    pub fn tc(&self) -> bool {
        (self.data[2] & 0x02) != 0
    }

    #[inline]
    #[must_use]
    pub fn qdcount(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    #[inline]
    #[must_use]
    pub fn arcount(&self) -> u16 {
        u16::from_be_bytes([self.data[10], self.data[11]])
    }

    /// Patches the DNS message ID in-place.
    #[inline]
    pub fn patch_id(data: &mut [u8], new_id: u16) {
        if data.len() >= 2 {
            let bytes = new_id.to_be_bytes();
            data[0] = bytes[0];
            data[1] = bytes[1];
        }
    }
}

/// Represents a question in the DNS message, parsed without following pointers.
///
/// This structure is used for the host-path decision and does not perform
/// full decompression of domain names. If pointers are encountered in the
/// question section, the parser returns `None`, signaling a fallback to the slow path.
pub struct WireQuestion<'a> {
    data: &'a [u8],
    qtype: u16,
    qname_end: usize,
}

impl<'a> WireQuestion<'a> {
    /// Attempts to parse the first question in the message.
    #[must_use]
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        let mut pos = 12;
        loop {
            if pos >= data.len() {
                return None;
            }
            let len = data[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if (len & 0xC0) != 0 {
                // Pointer or reserved label type in the question:
                // Fallback to the slow path (hickory-dns).
                return None;
            }
            pos += 1 + len;
            if pos > data.len() {
                return None;
            }
        }

        if pos + 4 > data.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);

        Some(Self {
            data: &data[..pos + 4],
            qtype,
            qname_end: pos,
        })
    }

    #[inline]
    #[must_use]
    pub const fn qtype(&self) -> u16 {
        self.qtype
    }

    /// Returns the raw QCLASS field.
    #[inline]
    #[must_use]
    pub const fn qclass(&self) -> u16 {
        // QCLASS is 2 bytes after QTYPE (which starts at qname_end)
        u16::from_be_bytes([self.data[self.qname_end + 2], self.data[self.qname_end + 3]])
    }

    /// Returns the raw QNAME slice (including label lengths and the null terminator).
    #[inline]
    #[must_use]
    pub fn qname_raw(&self) -> &'a [u8] {
        &self.data[12..=self.qname_end]
    }

    /// Returns an iterator over the labels in the QNAME.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lanforge_dns::wire::WireQuestion;
    ///
    /// // Raw DNS question for "host.lan"
    /// let data = b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04host\x03lan\x00\x00\x01\x00\x01";
    /// let q = WireQuestion::parse(data).unwrap();
    /// let labels: Vec<&[u8]> = q.labels().collect();
    /// assert_eq!(labels, vec![b"host".as_ref(), b"lan".as_ref()]);
    /// ```
    #[must_use]
    pub fn labels(&self) -> WireLabelIter<'a> {
        WireLabelIter {
            data: &self.data[12..self.qname_end],
            pos: 0,
        }
    }
}

#[derive(Clone)]
pub struct WireLabelIter<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for WireLabelIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.data.len() {
            return None;
        }
        let len = self.data[self.pos] as usize;
        if len == 0 {
            return None;
        }
        let start = self.pos + 1;
        let end = start + len;
        if end > self.data.len() {
            return None;
        }
        self.pos = end;
        Some(&self.data[start..end])
    }
}

/// Scans for an EDNS OPT record without parsing the entire OPT RR.
#[derive(Clone, Copy)]
pub struct WireOptScanner {
    /// The maximum message size the requester can handle.
    pub max_payload: u16,
}

impl WireOptScanner {
    /// Attempts to locate an OPT record (EDNS) without the cost of a full parse.
    /// Optimized for the common case: 1 question and 0 other records.
    #[must_use]
    pub fn scan(data: &[u8], header: &WireHeader, question: &WireQuestion) -> Option<Self> {
        if header.arcount() == 1 && header.qdcount() == 1 {
            let pos = question.data.len();
            if pos + 11 <= data.len() {
                // An OPT record starts with: Name=0 (1 byte), Type=41 (2 bytes)
                if data[pos] == 0 && u16::from_be_bytes([data[pos + 1], data[pos + 2]]) == 41 {
                    let max_payload = u16::from_be_bytes([data[pos + 3], data[pos + 4]]);
                    return Some(Self { max_payload });
                }
            }
        }
        None
    }
}

/// Helper for writing minimal DNS responses directly to the wire.
pub struct WireResponseWriter;

impl WireResponseWriter {
    /// Writes a minimal error response (REFUSED, FORMERR, etc) into the provided buffer.
    pub fn write_error_response(
        query_data: &[u8],
        question: &WireQuestion,
        rcode: u8,
        edns: Option<WireOptScanner>,
        ra: bool,
        resp: &mut Vec<u8>,
    ) {
        resp.clear();
        let capacity = 12 + question.data.len() + 11;
        if resp.capacity() < capacity {
            resp.reserve(capacity);
        }

        let mut h = [0u8; 12];
        h.copy_from_slice(&query_data[0..12]);
        h[2] |= 0x80; // QR = 1 (Response)
        h[2] |= 0x04; // AA = 1 (Authoritative Answer)
        if ra {
            h[3] |= 0x80; // RA = 1 (Recursion Available)
        }
        h[3] &= 0xF0; // Clear RCODE
        h[3] |= rcode & 0x0F;
        h[6..12].fill(0); // AN/NS/AR count reset
        if edns.is_some() {
            h[11] = 1; // ARCOUNT = 1
        }
        resp.extend_from_slice(&h);
        resp.extend_from_slice(&question.data[12..]);

        if let Some(opt) = edns {
            Self::write_opt(resp, opt);
        }
    }

    /// Writes a successful A or AAAA response with one or more IP addresses into the buffer.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub fn write_ip_response(
        query_data: &[u8],
        question: &WireQuestion,
        ips: &[IpAddr],
        ttl: u32,
        edns: Option<WireOptScanner>,
        ra: bool,
        resp: &mut Vec<u8>,
    ) {
        resp.clear();
        let is_v6 = matches!(ips.first(), Some(IpAddr::V6(_)));
        let rd_len = if is_v6 { 16 } else { 4 };
        let capacity = 12 + question.data.len() + (ips.len() * (12 + rd_len)) + 11;
        if resp.capacity() < capacity {
            resp.reserve(capacity);
        }

        // 1. Header
        let mut h = [0u8; 12];
        h.copy_from_slice(&query_data[0..12]);
        h[2] |= 0x80; // QR = 1
        h[2] |= 0x04; // AA = 1
        if ra {
            h[3] |= 0x80;
        }
        h[3] &= 0xF0; // RCODE = 0 (NoError)

        let ancount = ips.len() as u16;
        let an_bytes = ancount.to_be_bytes();
        h[6] = an_bytes[0];
        h[7] = an_bytes[1];
        h[8] = 0;
        h[9] = 0; // NSCOUNT = 0
        h[10] = 0;
        h[11] = if edns.is_some() { 1 } else { 0 }; // ARCOUNT

        resp.extend_from_slice(&h);

        // 2. Question
        resp.extend_from_slice(&question.data[12..]);

        // 3. Answers
        let qtype = if is_v6 { 28u16 } else { 1u16 }; // AAAA=28, A=1
        for ip in ips {
            // Name Pointer (0xC00C points to the QNAME starting at index 12)
            resp.extend_from_slice(&[0xC0, 0x0C]);
            resp.extend_from_slice(&qtype.to_be_bytes());
            resp.extend_from_slice(&1u16.to_be_bytes()); // Class IN (1)
            resp.extend_from_slice(&ttl.to_be_bytes());
            resp.extend_from_slice(&(rd_len as u16).to_be_bytes());
            match ip {
                IpAddr::V4(addr) => resp.extend_from_slice(&addr.octets()),
                IpAddr::V6(addr) => resp.extend_from_slice(&addr.octets()),
            }
        }

        // 4. EDNS
        if let Some(opt) = edns {
            Self::write_opt(resp, opt);
        }
    }

    /// Writes a PTR response into the buffer.
    pub fn write_ptr_response(
        query_data: &[u8],
        question: &WireQuestion,
        host: &str,
        domain: &str,
        ttl: u32,
        edns: Option<WireOptScanner>,
        ra: bool,
        resp: &mut Vec<u8>,
    ) {
        resp.clear();
        let capacity = 12 + question.data.len() + 12 + host.len() + domain.len() + 4;
        if resp.capacity() < capacity {
            resp.reserve(capacity);
        }

        // 1. Header
        let mut h = [0u8; 12];
        h.copy_from_slice(&query_data[0..12]);
        h[2] |= 0x80; // QR = 1
        h[2] |= 0x04; // AA = 1
        if ra {
            h[3] |= 0x80;
        }
        h[3] &= 0xF0;
        h[6] = 0;
        h[7] = 1; // ANCOUNT = 1
        h[8] = 0;
        h[9] = 0;
        h[10] = 0;
        h[11] = if edns.is_some() { 1 } else { 0 };
        resp.extend_from_slice(&h);

        // 2. Question
        resp.extend_from_slice(&question.data[12..]);

        // 3. Answer (PTR)
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&12u16.to_be_bytes()); // Type PTR (12)
        resp.extend_from_slice(&1u16.to_be_bytes()); // Class IN (1)
        resp.extend_from_slice(&ttl.to_be_bytes());

        // RDLEN and RDATA
        // Pre-calculate RDATA length to avoid extra Vec allocation
        let mut rdlen = 0u16;
        for label in host.split('.') {
            if label.is_empty() {
                continue;
            }
            rdlen += 1 + label.len() as u16;
        }
        for label in domain.split('.') {
            if label.is_empty() {
                continue;
            }
            rdlen += 1 + label.len() as u16;
        }
        rdlen += 1; // Null terminator

        resp.extend_from_slice(&rdlen.to_be_bytes());

        for label in host.split('.') {
            if label.is_empty() {
                continue;
            }
            resp.push(label.len() as u8);
            resp.extend_from_slice(label.as_bytes());
        }
        for label in domain.split('.') {
            if label.is_empty() {
                continue;
            }
            resp.push(label.len() as u8);
            resp.extend_from_slice(label.as_bytes());
        }
        resp.push(0); // Null terminator

        // 4. EDNS
        if let Some(opt) = edns {
            Self::write_opt(resp, opt);
        }
    }

    fn write_opt(resp: &mut Vec<u8>, opt: WireOptScanner) {
        resp.push(0); // Root Name
        resp.extend_from_slice(&41u16.to_be_bytes()); // Type 41 (OPT)
        resp.extend_from_slice(&opt.max_payload.to_be_bytes()); // Class (Max Payload)
        resp.extend_from_slice(&[0, 0, 0, 0]); // TTL
        resp.extend_from_slice(&[0, 0]); // RDLEN = 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_error_response_no_duplication() {
        // ID=0x1234, Flags=0x0100 (RD=1), QDCOUNT=1, ...
        // QNAME="\x04host\x03lan\x00", QTYPE=1 (A), QCLASS=1 (IN)
        let query_data =
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04host\x03lan\x00\x00\x01\x00\x01";
        let question = WireQuestion::parse(query_data).expect("Should parse question");
        let rcode = 5; // REFUSED
        let mut resp = Vec::new();
        WireResponseWriter::write_error_response(
            query_data, &question, rcode, None, false, &mut resp,
        );

        // Header (12) + QNAME ("4host3lan0" = 10) + QTYPE (2) + QCLASS (2) = 26 bytes
        assert_eq!(
            resp.len(),
            26,
            "Response size should be exactly 26 bytes (no 24-byte header duplication)"
        );
        assert_eq!(&resp[0..2], b"\x12\x34", "ID should match");
        assert_eq!(
            resp[2], 0x85,
            "Flags byte 1 should have QR=1, AA=1 and RD=1"
        );
        assert_eq!(resp[3] & 0x0F, 0x05, "RCODE should be 5 (REFUSED)");

        // The question part MUST start immediately after the 12-byte header
        assert_eq!(
            &resp[12..17],
            b"\x04host",
            "Question section should start at index 12"
        );
    }
}
