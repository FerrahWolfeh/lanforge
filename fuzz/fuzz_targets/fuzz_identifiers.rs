#![no_main]

use lanforge_types::identifiers::{Duid, MacAddr};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Pula a barreira do FromStr! Cria o DUID direto com os bytes mutados do fuzzer
    let duid = Duid::new(data.to_vec());

    // 2. Martela as funções internas.
    // Como o DUID agora sempre é "válido" na construção, o fuzzer vai focar em ver se
    // o fatiamento interno de bytes ou a extração do MAC causa algum "index out of bounds" (panic).
    let _ = duid.to_string();
    let _ = duid.as_bytes();
    let _ = duid.duid_type();
    let _ = duid.extract_mac();

    // 3. Aproveita o mesmo array de bytes brutos para testar o parser de string do MAC
    // Mas usando a estratégia do lossy para nunca rejeitar o input
    let s = String::from_utf8_lossy(data);
    if let Some(mac) = MacAddr::parse(&s) {
        let _ = mac.to_string();
        let _ = mac.contains_str(&s);
        let _ = mac.eq_str(&s);
    }
});
