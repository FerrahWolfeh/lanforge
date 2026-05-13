//! Zero-allocation DNS wire parser for hot-path routing.
//!
//! Replaces full Hickory Message parsing for local/upstream routing decisions.
//! Optimized for performance by avoiding UTF-8 validation and heap allocations.

use lanforge_core::types::{
    DnsClass, DnsHeader, DnsMessage, DnsQuestion, DnsRData, DnsRecord, DnsRecordType,
    DnsResponseCode,
};
use std::net::IpAddr;
use std::sync::Arc;

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
    pub fn ancount(&self) -> u16 {
        u16::from_be_bytes([self.data[6], self.data[7]])
    }

    #[inline]
    #[must_use]
    pub fn nscount(&self) -> u16 {
        u16::from_be_bytes([self.data[8], self.data[9]])
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

    /// Converts the wire header into an owned DnsHeader.
    #[must_use]
    pub fn to_owned(&self) -> DnsHeader {
        DnsHeader {
            id: self.id(),
            qr: !self.is_query(),
            opcode: (self.data[2] & 0x78) >> 3,
            aa: (self.data[2] & 0x04) != 0,
            tc: self.tc(),
            rd: self.rd(),
            ra: (self.data[3] & 0x80) != 0,
            z: (self.data[3] & 0x40) != 0,
            ad: (self.data[3] & 0x20) != 0,
            cd: (self.data[3] & 0x10) != 0,
            rcode: DnsResponseCode::from(self.data[3] & 0x0F),
            qdcount: self.qdcount(),
            ancount: self.ancount(),
            nscount: self.nscount(),
            arcount: self.arcount(),
        }
    }
}

/// Helper to skip a DNS name in the wire format without decompressing.
pub fn skip_name(data: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= data.len() {
            return None;
        }
        let len = data[pos];
        if len == 0 {
            return Some(pos + 1);
        }
        if (len & 0xC0) == 0xC0 {
            // Pointer (2 bytes)
            if pos + 2 > data.len() {
                return None;
            }
            return Some(pos + 2);
        }
        if (len & 0xC0) != 0 {
            // Reserved label type
            return None;
        }
        pos += 1 + (len as usize);
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
                // Unsupported in the zero-alloc fast path.
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

    /// Converts the wire question into an owned DnsQuestion.
    #[must_use]
    pub fn to_owned(&self) -> DnsQuestion {
        let mut decoder = WireDecoder::new(self.data);
        decoder.pos = 12;
        let name = decoder.decode_name().unwrap_or_else(|| Arc::from(""));
        DnsQuestion {
            name,
            qtype: DnsRecordType::from(self.qtype),
            qclass: DnsClass::from(self.qclass()),
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

/// Scans a DNS response to identify TTL field offsets for cache scrubbing.
pub struct WireResponseScanner<'a> {
    data: &'a [u8],
}

impl<'a> WireResponseScanner<'a> {
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Identifies all TTL field offsets in the response (Answers, Authorities, and Additionals).
    /// Returns (offsets, min_ttl).
    #[must_use]
    pub fn scan_ttls(&self) -> (Vec<usize>, u32) {
        let Some(header) = WireHeader::parse(self.data) else {
            return (Vec::new(), 0);
        };

        let mut pos = 12; // Start after header

        // Skip Questions
        for _ in 0..header.qdcount() {
            pos = skip_name(self.data, pos).unwrap_or(self.data.len());
            pos += 4; // Type and Class
        }

        let mut offsets = Vec::new();
        let mut min_ttl = u32::MAX;

        let record_count =
            header.ancount() as usize + header.nscount() as usize + header.arcount() as usize;

        for _ in 0..record_count {
            if pos >= self.data.len() {
                break;
            }
            pos = skip_name(self.data, pos).unwrap_or(self.data.len());
            if pos + 10 > self.data.len() {
                break;
            }

            // TYPE(2), CLASS(2), TTL(4), RDLEN(2)
            let rtype = u16::from_be_bytes([self.data[pos], self.data[pos + 1]]);
            let ttl_offset = pos + 4;
            let mut ttl = u32::from_be_bytes([
                self.data[ttl_offset],
                self.data[ttl_offset + 1],
                self.data[ttl_offset + 2],
                self.data[ttl_offset + 3],
            ]);

            // RFC 2308: Negative caching TTL is the minimum of the SOA's TTL
            // and the SOA's 'minimum' field (last field in RDATA).
            if rtype == 6 {
                // SOA RDATA starts at pos + 10
                if let Some(mname_end) = skip_name(self.data, pos + 10)
                    && let Some(rname_end) = skip_name(self.data, mname_end)
                {
                    // Serial(4), Refresh(4), Retry(4), Expire(4) = 16 bytes before Minimum(4)
                    let minimum_offset = rname_end + 16;
                    if minimum_offset + 4 <= self.data.len() {
                        let minimum_ttl = u32::from_be_bytes([
                            self.data[minimum_offset],
                            self.data[minimum_offset + 1],
                            self.data[minimum_offset + 2],
                            self.data[minimum_offset + 3],
                        ]);
                        if minimum_ttl < ttl {
                            ttl = minimum_ttl;
                        }
                    }
                }
            }

            if ttl < min_ttl {
                min_ttl = ttl;
            }
            offsets.push(ttl_offset);

            let rdlen = u16::from_be_bytes([self.data[pos + 8], self.data[pos + 9]]) as usize;
            pos += 10 + rdlen;
        }

        if min_ttl == u32::MAX {
            min_ttl = 60;
        }
        (offsets, min_ttl)
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

/// Arguments for writing a PTR response.
#[derive(Clone, Copy)]
pub struct PtrResponseArgs<'a> {
    pub query_data: &'a [u8],
    pub question: &'a WireQuestion<'a>,
    pub host: &'a str,
    pub domain: &'a str,
    pub ttl: u32,
    pub edns: Option<WireOptScanner>,
    pub ra: bool,
}

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

        let ancount = u16::try_from(ips.len()).unwrap_or(u16::MAX);
        let an_bytes = ancount.to_be_bytes();
        h[6] = an_bytes[0];
        h[7] = an_bytes[1];
        h[8] = 0;
        h[9] = 0; // NSCOUNT = 0
        h[10] = 0;
        h[11] = u8::from(edns.is_some()); // ARCOUNT

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
            resp.extend_from_slice(&(u16::try_from(rd_len).unwrap_or(u16::MAX)).to_be_bytes());
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
    pub fn write_ptr_response(args: PtrResponseArgs, resp: &mut Vec<u8>) {
        resp.clear();
        let capacity = 12 + args.question.data.len() + 12 + args.host.len() + args.domain.len() + 4;
        if resp.capacity() < capacity {
            resp.reserve(capacity);
        }

        // 1. Header
        let mut h = [0u8; 12];
        h.copy_from_slice(&args.query_data[0..12]);
        h[2] |= 0x80; // QR = 1
        h[2] |= 0x04; // AA = 1
        if args.ra {
            h[3] |= 0x80;
        }
        h[3] &= 0xF0;
        h[6] = 0;
        h[7] = 1; // ANCOUNT = 1
        h[8] = 0;
        h[9] = 0;
        h[10] = 0;
        h[11] = u8::from(args.edns.is_some());
        resp.extend_from_slice(&h);

        // 2. Question
        resp.extend_from_slice(&args.question.data[12..]);

        // 3. Answer (PTR)
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&12u16.to_be_bytes()); // Type PTR (12)
        resp.extend_from_slice(&1u16.to_be_bytes()); // Class IN (1)
        resp.extend_from_slice(&args.ttl.to_be_bytes());

        // RDLEN and RDATA
        // Pre-calculate RDATA length to avoid extra Vec allocation
        let mut rdlen = 0u16;
        for label in args.host.split('.') {
            if label.is_empty() {
                continue;
            }
            rdlen += 1 + u16::try_from(label.len()).unwrap_or(u16::MAX);
        }
        for label in args.domain.split('.') {
            if label.is_empty() {
                continue;
            }
            rdlen += 1 + u16::try_from(label.len()).unwrap_or(u16::MAX);
        }
        rdlen += 1; // Null terminator

        resp.extend_from_slice(&rdlen.to_be_bytes());

        for label in args.host.split('.') {
            if label.is_empty() {
                continue;
            }
            resp.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
            resp.extend_from_slice(label.as_bytes());
        }
        for label in args.domain.split('.') {
            if label.is_empty() {
                continue;
            }
            resp.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
            resp.extend_from_slice(label.as_bytes());
        }
        resp.push(0); // Null terminator

        // 4. EDNS
        if let Some(opt) = args.edns {
            Self::write_opt(resp, opt);
        }
    }

    /// Writes a CNAME response into the buffer.
    pub fn write_cname_response(
        query_data: &[u8],
        question: &WireQuestion,
        target: &str,
        ttl: u32,
        edns: Option<WireOptScanner>,
        ra: bool,
        resp: &mut Vec<u8>,
    ) {
        resp.clear();
        let capacity = 12 + question.data.len() + 12 + target.len() + 2;
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
        h[11] = u8::from(edns.is_some());
        resp.extend_from_slice(&h);

        // 2. Question
        resp.extend_from_slice(&question.data[12..]);

        // 3. Answer (CNAME)
        resp.extend_from_slice(&[0xC0, 0x0C]);
        resp.extend_from_slice(&5u16.to_be_bytes()); // Type CNAME (5)
        resp.extend_from_slice(&1u16.to_be_bytes()); // Class IN (1)
        resp.extend_from_slice(&ttl.to_be_bytes());

        // RDLEN and RDATA
        let mut rdlen = 0u16;
        for label in target.split('.') {
            if label.is_empty() {
                continue;
            }
            rdlen += 1 + u16::try_from(label.len()).unwrap_or(u16::MAX);
        }
        rdlen += 1; // Null terminator
        resp.extend_from_slice(&rdlen.to_be_bytes());

        for label in target.split('.') {
            if label.is_empty() {
                continue;
            }
            resp.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
            resp.extend_from_slice(label.as_bytes());
        }
        resp.push(0);

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

/// Full-featured DNS wire decoder.
pub struct WireDecoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> WireDecoder<'a> {
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn set_pos(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// Decodes a domain name from the wire format, handling pointers (decompression).
    pub fn decode_name(&mut self) -> Option<Arc<str>> {
        let mut name = String::new();
        let mut pos = self.pos;
        let mut jumped = false;
        let mut first_label = true;
        let mut loop_count = 0;

        loop {
            loop_count += 1;
            if loop_count > 64 {
                return None;
            } // Loop protection (e.g. pointer cycles)

            if pos >= self.data.len() {
                return None;
            }
            let len = self.data[pos];

            if len == 0 {
                if !jumped {
                    self.pos = pos + 1;
                }
                break;
            }

            if (len & 0xC0) == 0xC0 {
                if pos + 1 >= self.data.len() {
                    return None;
                }
                let offset = (((len & 0x3F) as usize) << 8) | (self.data[pos + 1] as usize);
                if !jumped {
                    self.pos = pos + 2;
                }
                pos = offset;
                jumped = true;
                continue;
            }

            if !first_label {
                name.push('.');
            }
            let start = pos + 1;
            let end = start + (len as usize);
            if end > self.data.len() {
                return None;
            }
            name.push_str(std::str::from_utf8(&self.data[start..end]).ok()?);
            pos = end;
            first_label = false;
        }

        Some(Arc::from(name))
    }

    /// Decodes the full DNS message.
    pub fn decode_message(&mut self) -> Option<DnsMessage> {
        let header = WireHeader::parse(self.data)?.to_owned();
        self.pos = 12;

        let mut msg = DnsMessage {
            header: header.clone(),
            ..Default::default()
        };

        for _ in 0..header.qdcount {
            msg.questions.push(self.decode_question()?);
        }
        for _ in 0..header.ancount {
            msg.answers.push(self.decode_record()?);
        }
        for _ in 0..header.nscount {
            msg.authorities.push(self.decode_record()?);
        }
        for _ in 0..header.arcount {
            msg.additionals.push(self.decode_record()?);
        }

        Some(msg)
    }

    fn decode_question(&mut self) -> Option<DnsQuestion> {
        let name = self.decode_name()?;
        if self.pos + 4 > self.data.len() {
            return None;
        }
        let qtype = DnsRecordType::from(u16::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
        ]));
        let qclass = DnsClass::from(u16::from_be_bytes([
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]));
        self.pos += 4;
        Some(DnsQuestion {
            name,
            qtype,
            qclass,
        })
    }

    fn decode_record(&mut self) -> Option<DnsRecord> {
        let name = self.decode_name()?;
        if self.pos + 10 > self.data.len() {
            return None;
        }
        let rtype = DnsRecordType::from(u16::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
        ]));
        let rclass = DnsClass::from(u16::from_be_bytes([
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]));
        let ttl = u32::from_be_bytes([
            self.data[self.pos + 4],
            self.data[self.pos + 5],
            self.data[self.pos + 6],
            self.data[self.pos + 7],
        ]);
        let rdlen = u16::from_be_bytes([self.data[self.pos + 8], self.data[self.pos + 9]]) as usize;
        self.pos += 10;
        if self.pos + rdlen > self.data.len() {
            return None;
        }

        let rdata_end = self.pos + rdlen;
        let rdata = self.decode_rdata(rtype, rdlen)?;
        self.pos = rdata_end;

        Some(DnsRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata,
        })
    }

    fn decode_rdata(&mut self, rtype: DnsRecordType, rdlen: usize) -> Option<DnsRData> {
        let start = self.pos;
        match rtype {
            DnsRecordType::A => {
                if rdlen != 4 {
                    return None;
                }
                Some(DnsRData::A(std::net::Ipv4Addr::new(
                    self.data[start],
                    self.data[start + 1],
                    self.data[start + 2],
                    self.data[start + 3],
                )))
            }
            DnsRecordType::AAAA => {
                if rdlen != 16 {
                    return None;
                }
                let mut b = [0u8; 16];
                b.copy_from_slice(&self.data[start..start + 16]);
                Some(DnsRData::AAAA(std::net::Ipv6Addr::from(b)))
            }
            DnsRecordType::CNAME => Some(DnsRData::CNAME(self.decode_name()?)),
            DnsRecordType::PTR => Some(DnsRData::PTR(self.decode_name()?)),
            DnsRecordType::NS => Some(DnsRData::NS(self.decode_name()?)),
            DnsRecordType::SOA => {
                let mname = self.decode_name()?;
                let rname = self.decode_name()?;
                if self.pos + 20 > self.data.len() {
                    return None;
                }
                let serial = u32::from_be_bytes([
                    self.data[self.pos],
                    self.data[self.pos + 1],
                    self.data[self.pos + 2],
                    self.data[self.pos + 3],
                ]);
                let refresh = i32::from_be_bytes([
                    self.data[self.pos + 4],
                    self.data[self.pos + 5],
                    self.data[self.pos + 6],
                    self.data[self.pos + 7],
                ]);
                let retry = i32::from_be_bytes([
                    self.data[self.pos + 8],
                    self.data[self.pos + 9],
                    self.data[self.pos + 10],
                    self.data[self.pos + 11],
                ]);
                let expire = i32::from_be_bytes([
                    self.data[self.pos + 12],
                    self.data[self.pos + 13],
                    self.data[self.pos + 14],
                    self.data[self.pos + 15],
                ]);
                let minimum = u32::from_be_bytes([
                    self.data[self.pos + 16],
                    self.data[self.pos + 17],
                    self.data[self.pos + 18],
                    self.data[self.pos + 19],
                ]);
                self.pos += 20;
                Some(DnsRData::SOA {
                    mname,
                    rname,
                    serial,
                    refresh,
                    retry,
                    expire,
                    minimum,
                })
            }
            _ => Some(DnsRData::Unknown(self.data[start..start + rdlen].to_vec())),
        }
    }
}

/// Helper for encoding DNS messages into wire format.
#[derive(Default)]
pub struct WireEncoder {
    buf: Vec<u8>,
}

impl WireEncoder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: Vec::with_capacity(512),
        }
    }

    pub fn encode_name(&mut self, name: &str) {
        for label in name.split('.') {
            if label.is_empty() {
                continue;
            }
            self.buf.push(u8::try_from(label.len()).unwrap_or(u8::MAX));
            self.buf.extend_from_slice(label.as_bytes());
        }
        self.buf.push(0);
    }

    pub fn encode_header(&mut self, h: &DnsHeader) {
        self.buf.extend_from_slice(&h.id.to_be_bytes());
        let mut b2 = 0u8;
        if h.qr {
            b2 |= 0x80;
        }
        b2 |= (h.opcode & 0x0F) << 3;
        if h.aa {
            b2 |= 0x04;
        }
        if h.tc {
            b2 |= 0x02;
        }
        if h.rd {
            b2 |= 0x01;
        }
        self.buf.push(b2);

        let mut b3 = 0u8;
        if h.ra {
            b3 |= 0x80;
        }
        if h.z {
            b3 |= 0x40;
        }
        if h.ad {
            b3 |= 0x20;
        }
        if h.cd {
            b3 |= 0x10;
        }
        b3 |= u8::from(h.rcode) & 0x0F;
        self.buf.push(b3);

        self.buf.extend_from_slice(&h.qdcount.to_be_bytes());
        self.buf.extend_from_slice(&h.ancount.to_be_bytes());
        self.buf.extend_from_slice(&h.nscount.to_be_bytes());
        self.buf.extend_from_slice(&h.arcount.to_be_bytes());
    }

    pub fn encode_message(&mut self, msg: &DnsMessage) -> Vec<u8> {
        self.encode_header(&msg.header);
        for q in &msg.questions {
            self.encode_name(&q.name);
            self.buf
                .extend_from_slice(&u16::from(q.qtype).to_be_bytes());
            self.buf
                .extend_from_slice(&u16::from(q.qclass).to_be_bytes());
        }
        for r in &msg.answers {
            self.encode_record(r);
        }
        for r in &msg.authorities {
            self.encode_record(r);
        }
        for r in &msg.additionals {
            self.encode_record(r);
        }
        std::mem::take(&mut self.buf)
    }

    fn encode_record(&mut self, r: &DnsRecord) {
        self.encode_name(&r.name);
        self.buf
            .extend_from_slice(&u16::from(r.rtype).to_be_bytes());
        self.buf
            .extend_from_slice(&u16::from(r.rclass).to_be_bytes());
        self.buf.extend_from_slice(&r.ttl.to_be_bytes());

        let rdlen_pos = self.buf.len();
        self.buf.extend_from_slice(&[0, 0]); // Placeholder

        let rdata_start = self.buf.len();
        self.encode_rdata(&r.rdata);
        let rdlen = u16::try_from(self.buf.len() - rdata_start).unwrap_or(u16::MAX);
        let rdlen_bytes = rdlen.to_be_bytes();
        self.buf[rdlen_pos] = rdlen_bytes[0];
        self.buf[rdlen_pos + 1] = rdlen_bytes[1];
    }

    fn encode_rdata(&mut self, rdata: &DnsRData) {
        match rdata {
            DnsRData::A(ip) => self.buf.extend_from_slice(&ip.octets()),
            DnsRData::AAAA(ip) => self.buf.extend_from_slice(&ip.octets()),
            DnsRData::CNAME(name) => self.encode_name(name),
            DnsRData::PTR(name) => self.encode_name(name),
            DnsRData::NS(name) => self.encode_name(name),
            DnsRData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                self.encode_name(mname);
                self.encode_name(rname);
                self.buf.extend_from_slice(&serial.to_be_bytes());
                self.buf.extend_from_slice(&refresh.to_be_bytes());
                self.buf.extend_from_slice(&retry.to_be_bytes());
                self.buf.extend_from_slice(&expire.to_be_bytes());
                self.buf.extend_from_slice(&minimum.to_be_bytes());
            }
            DnsRData::OPT { options } => {
                for (code, data) in options {
                    self.buf.extend_from_slice(&code.to_be_bytes());
                    self.buf.extend_from_slice(
                        &(u16::try_from(data.len()).unwrap_or(u16::MAX)).to_be_bytes(),
                    );
                    self.buf.extend_from_slice(data);
                }
            }
            DnsRData::Unknown(data) => self.buf.extend_from_slice(data),
            _ => {}
        }
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

    #[test]
    fn test_name_decompression() {
        // "host.lan" at offset 12
        // pointer to offset 12 at offset 26
        let data = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04host\x03lan\x00\x00\x01\x00\x01\xC0\x0C\x00\x01\x00\x01";
        let mut decoder = WireDecoder::new(data);
        decoder.pos = 12;
        let name1 = decoder.decode_name().unwrap();
        assert_eq!(&*name1, "host.lan");

        decoder.pos = 26;
        let name2 = decoder.decode_name().unwrap();
        assert_eq!(&*name2, "host.lan");
    }

    #[test]
    fn test_full_message_decode_encode() {
        let query_data =
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x04host\x03lan\x00\x00\x01\x00\x01";
        let mut decoder = WireDecoder::new(query_data);
        let msg = decoder.decode_message().unwrap();

        assert_eq!(msg.header.id, 0x1234);
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(&*msg.questions[0].name, "host.lan");

        let mut encoder = WireEncoder::new();
        let encoded = encoder.encode_message(&msg);
        assert_eq!(encoded, query_data);
    }
}
