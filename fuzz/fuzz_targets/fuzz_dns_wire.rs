#![no_main]
use lanforge_dns_wire::{WireDecoder, WireResponseScanner};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Testa a maquina de estado completa de decodificação e descompressão de ponteiros DNS
    let mut decoder = WireDecoder::new(data);
    if let Some(msg) = decoder.decode_message() {
        // Se o parse passou, force a alocação/extração de dados internos para expor pânicos ocultos
        let _ = msg.to_owned();
    }

    // 2. O Scanner de TTL roda em paralelo para garantir que ele não entra em loop infinito
    let scanner = WireResponseScanner::new(data);
    let _ = scanner.scan_ttls();
});
