use lanforge_types::identifiers::MacAddr;

pub const ETH_P_PPP_DISC: u16 = 0x8863;

pub const CODE_PADI: u8 = 0x09;
pub const CODE_PADO: u8 = 0x07;
pub const CODE_PADR: u8 = 0x19;
pub const CODE_PADS: u8 = 0x65;
pub const CODE_PADT: u8 = 0xa7;

pub const TAG_SERVICE_NAME: u16 = 0x0101;
pub const TAG_AC_NAME: u16 = 0x0102;
pub const TAG_HOST_UNIQ: u16 = 0x0103;
pub const TAG_AC_COOKIE: u16 = 0x0104;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tag<'a> {
    pub tag_type: u16,
    pub value: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PppoeDiscoveryFrame<'a> {
    pub dst_mac: MacAddr,
    pub src_mac: MacAddr,
    pub code: u8,
    pub session_id: u16,
    pub tags: Vec<Tag<'a>>,
}

impl<'a> PppoeDiscoveryFrame<'a> {
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let total_tags_len: usize = self.tags.iter().map(|t| 4 + t.value.len()).sum();
        let mut packet = Vec::with_capacity(20 + total_tags_len);

        packet.extend_from_slice(&self.dst_mac.0);
        packet.extend_from_slice(&self.src_mac.0);
        packet.extend_from_slice(&ETH_P_PPP_DISC.to_be_bytes());
        packet.push(0x11); // Ver: 1, Type: 1
        packet.push(self.code);
        packet.extend_from_slice(&self.session_id.to_be_bytes());

        #[allow(clippy::cast_possible_truncation)]
        let payload_len = total_tags_len as u16;
        packet.extend_from_slice(&payload_len.to_be_bytes());

        for tag in &self.tags {
            packet.extend_from_slice(&tag.tag_type.to_be_bytes());
            #[allow(clippy::cast_possible_truncation)]
            let len = tag.value.len() as u16;
            packet.extend_from_slice(&len.to_be_bytes());
            packet.extend_from_slice(tag.value);
        }

        packet
    }

    #[must_use]
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 20 {
            return None;
        }

        let dst_mac = MacAddr(bytes[0..6].try_into().ok()?);
        let src_mac = MacAddr(bytes[6..12].try_into().ok()?);

        let ethertype = u16::from_be_bytes([bytes[12], bytes[13]]);
        if ethertype != ETH_P_PPP_DISC {
            return None;
        }

        let ver_type = bytes[14];
        if ver_type != 0x11 {
            return None;
        }

        let code = bytes[15];
        let session_id = u16::from_be_bytes([bytes[16], bytes[17]]);
        let payload_len = u16::from_be_bytes([bytes[18], bytes[19]]) as usize;

        if bytes.len() < 20 + payload_len {
            return None;
        }

        let mut tags = Vec::new();
        let mut offset = 20;
        let end = 20 + payload_len;

        while offset + 4 <= end {
            let tag_type = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            let tag_len = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
            offset += 4;

            if offset + tag_len > end {
                break;
            }

            let value = &bytes[offset..offset + tag_len];
            offset += tag_len;

            tags.push(Tag { tag_type, value });
        }

        Some(Self {
            dst_mac,
            src_mac,
            code,
            session_id,
            tags,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discovery_frame_encode_parse() {
        let frame = PppoeDiscoveryFrame {
            dst_mac: MacAddr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]),
            src_mac: MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
            code: CODE_PADI,
            session_id: 0,
            tags: vec![
                Tag {
                    tag_type: TAG_SERVICE_NAME,
                    value: &[],
                },
                Tag {
                    tag_type: TAG_HOST_UNIQ,
                    value: &[1, 2, 3, 4],
                },
            ],
        };

        let encoded = frame.encode();
        let parsed = PppoeDiscoveryFrame::parse(&encoded).expect("parse frame");

        assert_eq!(parsed.dst_mac, frame.dst_mac);
        assert_eq!(parsed.src_mac, frame.src_mac);
        assert_eq!(parsed.code, CODE_PADI);
        assert_eq!(parsed.session_id, 0);
        assert_eq!(parsed.tags.len(), 2);
        assert_eq!(parsed.tags[1].value, &[1, 2, 3, 4]);
    }
}
