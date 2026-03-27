//! zero-alloc DNS wire parser for hot-path routing.
//!
//! Replaces full Hickory Message parsing for local/upstream routing decisions.

pub mod qtypes;

pub struct WireHeader<'a> {
    data: &'a [u8],
}

impl<'a> WireHeader<'a> {
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

pub struct WireQuestion<'a> {
    data: &'a [u8],
    qtype: u16,
    qname_end: usize,
}

impl<'a> WireQuestion<'a> {
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
                // Pointer ou tipo reservado na question: caímos para o path lento.
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

pub struct WireOptScanner {
    pub max_payload: u16,
}

impl WireOptScanner {
    /// Tenta localizar um registro OPT (EDNS) sem o custo do full-parse.
    /// Funciona apenas para queries com 1 pergunta e 0 outros registros (o padrão).
    pub fn scan(data: &[u8], header: &WireHeader, question: &WireQuestion) -> Option<Self> {
        if header.arcount() == 1 && header.qdcount() == 1 {
            let pos = question.data.len();
            if pos + 11 <= data.len() {
                // Um registro OPT tem: Name=0 (1 byte), Type=41 (2 bytes)
                if data[pos] == 0 && u16::from_be_bytes([data[pos + 1], data[pos + 2]]) == 41 {
                    let max_payload = u16::from_be_bytes([data[pos + 3], data[pos + 4]]);
                    return Some(Self { max_payload });
                }
            }
        }
        None
    }
}

pub struct WireResponseWriter;

impl WireResponseWriter {
    /// Constrói uma resposta mínima de erro (REFUSED, FORMERR, etc) sem parse completo.
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

        // 1. Header (copia ID, altera flags)
        let mut h = [0u8; 12];
        h.copy_from_slice(&query_data[0..12]);
        h[2] |= 0x80; // QR = 1 (Resposta)
        if ra {
            h[3] |= 0x80; // RA = 1 (Recursion Available)
        }
        h[3] &= 0xF0; // Limpa RCODE
        h[3] |= rcode & 0x0F;
        h[6..12].fill(0); // AN/NS/AR zerados por padrão
        if edns.is_some() {
            h[11] = 1; // ARCOUNT = 1
        }
        resp.extend_from_slice(&h);

        // 2. Question section (cópia exata)
        resp.extend_from_slice(question.data);

        // 3. EDNS OPT record se presente
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
