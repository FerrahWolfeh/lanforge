#![no_main]

use lanforge_tftp::config::TftpConfig;
use lanforge_tftp::{parse_rrq_options, sanitize_rrq_path};
use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    let root = Path::new("/var/tftpboot");

    // 1. Fuzz filename path sanitization and directory traversal prevention
    if let Ok((path, filename)) = sanitize_rrq_path(data, root) {
        // Invariant: Path MUST always start with the root directory and never escape
        assert!(
            path.starts_with(root),
            "Security vulnerability: Sanitized path {:?} escaped root {:?}",
            path,
            root
        );
        let _ = filename.len();
    }

    // 2. Fuzz null-delimited options parsing (RFC 2347, 2348, 2349)
    let cfg = TftpConfig {
        block_size: 1468,
        ..Default::default()
    };
    let parts = data.split(|&b| b == 0);
    let opts = parse_rrq_options(parts, &cfg);
    if let Some(bs) = opts.blksize {
        assert!(bs >= 512, "Block size must not be lower than 512");
        assert!(
            bs <= 1468,
            "Block size must not exceed configured max clamp"
        );
    }

    // 3. Fuzz full TFTP opcode and message slicing
    if data.len() >= 4 {
        let opcode = u16::from_be_bytes([data[0], data[1]]);
        if opcode == 1 {
            // RRQ format: [Opcode 2B] [Filename] \0 [Mode] \0 [Opt1 \0 Val1 \0 ...]
            let mut rrq_parts = data[2..].split(|&b| b == 0);
            if let Some(filename_bytes) = rrq_parts.next() {
                let _ = sanitize_rrq_path(filename_bytes, root);
                let _mode = rrq_parts.next();
                let _opts = parse_rrq_options(rrq_parts, &cfg);
            }
        }
    }
});
