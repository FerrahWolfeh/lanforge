//! Zero-allocation DNS wire parser for hot-path routing.
//!
//! Replaces full Hickory Message parsing for local/upstream routing decisions.
//! Optimized for performance by avoiding UTF-8 validation and heap allocations.

pub mod qtypes;

/// Simple view into the DNS message header.
pub struct WireHeader<'a> {
    data: &'a [u8],
}

impl<'a> WireHeader<'a> {
    /// Parses the header from the start of the message.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        Some(Self { data })
    }

    #[inline]
    #[allow(dead_code)]
    pub fn id(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    #[inline]
    pub fn is_query(&self) -> bool {
        (self.data[2] & 0x80) == 0
    }

    #[inline]
    #[allow(dead_code)]
    pub fn rd(&self) -> bool {
        (self.data[2] & 0x01) != 0
    }

    #[inline]
    pub fn qdcount(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    #[inline]
    pub fn arcount(&self) -> u16 {
        u16::from_be_bytes([self.data[10], self.data[11]])
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
    pub fn qtype(&self) -> u16 {
        self.qtype
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
    pub fn labels(&self) -> WireLabelIter<'a> {
        WireLabelIter {
            data: &self.data[12..self.qname_end],
            pos: 0,
        }
    }
}

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
pub struct WireOptScanner {
    /// The maximum message size the requester can handle.
    pub max_payload: u16,
}

impl WireOptScanner {
    /// Attempts to locate an OPT record (EDNS) without the cost of a full parse.
    /// Optimized for the common case: 1 question and 0 other records.
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
    /// Constructs a minimal error response (REFUSED, FORMERR, etc) without a full parse.
    pub fn write_error_response(
        query_data: &[u8],
        question: &WireQuestion,
        rcode: u8,
        edns: Option<&WireOptScanner>,
        ra: bool,
    ) -> Vec<u8> {
        // max: 12 (header) + question.data + 11 (OPT record)
        let capacity = 12 + question.data.len() + 11;
        let mut resp = Vec::with_capacity(capacity); // hint correto evita realloc

        // 1. Header (copy ID, alter flags)
        let mut h = [0u8; 12];
        h.copy_from_slice(&query_data[0..12]);
        h[2] |= 0x80; // QR = 1 (Response)
        if ra {
            h[3] |= 0x80; // RA = 1 (Recursion Available)
        }
        h[3] &= 0xF0; // Clear RCODE
        h[3] |= rcode & 0x0F;
        h[6..12].fill(0); // AN/NS/AR count reset to zero by default
        if edns.is_some() {
            h[11] = 1; // ARCOUNT = 1 (for OPT)
        }
        resp.extend_from_slice(&h);

        // 2. Question section (exact copy)
        resp.extend_from_slice(question.data);

        // 3. EDNS OPT record if present
        if let Some(opt) = edns {
            resp.push(0); // Root Name
            resp.extend_from_slice(&41u16.to_be_bytes()); // Type 41 (OPT)
            resp.extend_from_slice(&opt.max_payload.to_be_bytes()); // Class (Max Payload)
            resp.extend_from_slice(&[0, 0, 0, 0]); // TTL (V=0, Ext RCODE=0, Flags=0)
            resp.extend_from_slice(&[0, 0]); // RDLEN = 0
        }

        resp
    }
}
