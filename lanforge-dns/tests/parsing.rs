use lanforge_dns::wire::{WireDecoder, WireEncoder, WireHeader, WireQuestion};
use lanforge_types::network::dns::{DnsClass, DnsMessage, DnsQuestion, DnsRecordType};
use std::sync::Arc;

#[test]
fn parse_header_too_short() {
    let data = vec![0u8; 11];
    assert!(WireHeader::parse(&data).is_none());
}

#[test]
fn parse_question_too_short() {
    let data = vec![0u8; 12]; // Just header, no question
    assert!(WireQuestion::parse(&data).is_none());
}

#[test]
fn parse_malformed_label_length() {
    // Header(12) + Label length 10 + 2 bytes of data (invalid)
    let mut data = vec![0u8; 12];
    data.push(10);
    data.push(b'a');
    data.push(b'b');
    assert!(WireQuestion::parse(&data).is_none());
}

#[test]
fn name_decompression_circular_pointer() {
    // Header(12) + Pointer to 12 (itself)
    let mut data = vec![0u8; 12];
    data.push(0xC0);
    data.push(12);

    let mut decoder = WireDecoder::new(&data);
    decoder.set_pos(12); // Now public
    assert!(
        decoder.decode_name().is_none(),
        "Should detect circular pointer"
    );
}

#[test]
fn name_decompression_out_of_bounds() {
    // Header(12) + Pointer to 100
    let mut data = vec![0u8; 12];
    data.push(0xC0);
    data.push(100);

    let mut decoder = WireDecoder::new(&data);
    decoder.set_pos(12);
    assert!(decoder.decode_name().is_none(), "Should detect OOB pointer");
}

#[test]
fn name_decompression_complex() {
    // Build a message with decompression
    // name1: "abc.def.lan"
    // name2: "xyz.def.lan" (def.lan is a pointer to name1+4)

    let mut msg = DnsMessage::new();
    msg.questions.push(DnsQuestion {
        name: Arc::from("abc.def.lan"),
        qtype: DnsRecordType::A,
        qclass: DnsClass::IN,
    });

    let mut encoder = WireEncoder::new();
    let data = encoder.encode_message(&msg);

    // Now manually append a name with a pointer
    let mut data_with_ptr = data.clone();
    let start_of_new_name = data_with_ptr.len();
    data_with_ptr.push(3); // "xyz"
    data_with_ptr.extend_from_slice(b"xyz");
    data_with_ptr.push(0xC0);
    data_with_ptr.push(12 + 4); // Pointer to "def.lan" in the first question (after "abc" label)

    let mut decoder = WireDecoder::new(&data_with_ptr);
    decoder.set_pos(start_of_new_name);
    let decoded = decoder.decode_name().expect("Should decode complex name");
    assert_eq!(decoded.as_ref(), "xyz.def.lan");
}

#[test]
fn skip_name_malformed() {
    use lanforge_dns::wire::skip_name;
    let data = vec![0xC0]; // Too short for pointer
    assert!(skip_name(&data, 0).is_none());
}

#[test]
fn wire_label_iter_malformed() {
    // Question for label length 1 but missing null terminator or QTYPE/QCLASS
    let mut data = vec![0u8; 12];
    data.extend_from_slice(b"\x01a"); // Length 1, content 'a', missing \x00
    assert!(WireQuestion::parse(&data).is_none());
}

#[test]
fn wire_opt_scanner_multiple_additionals() {
    use lanforge_dns::wire::{WireHeader, WireOptScanner, WireQuestion};

    // Header with 2 additionals
    let mut data = vec![0u8; 12];
    data[11] = 2; // ARCOUNT = 2

    // Question: "test.lan" A IN
    data.extend_from_slice(b"\x04test\x03lan\x00\x00\x01\x00\x01");

    let header = WireHeader::parse(&data).unwrap();
    let question = WireQuestion::parse(&data).unwrap();

    // OPT record should be the first additional if we want scan to work (it's optimized for 1 question, 1 additional)
    // The current scanner only supports header.arcount() == 1
    assert!(
        WireOptScanner::scan(&data, &header, &question).is_none(),
        "Should not scan if ARCOUNT != 1"
    );
}
