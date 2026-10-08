use std::fmt::Write;
use std::path::Path;
use tracing::debug;

/// Parses `/sys/devices/system/cpu/online` or falls back to system thread count.
#[must_use]
pub fn detect_online_cpus() -> Vec<usize> {
    detect_online_cpus_from_path(Path::new("/sys/devices/system/cpu/online"))
}

pub fn detect_online_cpus_from_path(path: &Path) -> Vec<usize> {
    if let Ok(content) = std::fs::read_to_string(path)
        && let Some(cpus) = parse_cpu_range_list(&content)
        && !cpus.is_empty()
    {
        debug!(online_count = cpus.len(), "Detected online CPUs from sysfs");
        return cpus;
    }

    let fallback_count =
        std::thread::available_parallelism().map_or(4, std::num::NonZeroUsize::get);
    debug!(
        fallback_count,
        "Falling back to available parallelism for CPU count"
    );
    (0..fallback_count).collect()
}

/// Parses a standard Linux CPU list string like "0-7" or "0-3,5-7" into CPU indices.
#[must_use]
pub fn parse_cpu_range_list(content: &str) -> Option<Vec<usize>> {
    let mut cpus = Vec::new();
    for part in content.trim().split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start_s, end_s)) = part.split_once('-') {
            let start = start_s.trim().parse::<usize>().ok()?;
            let end = end_s.trim().parse::<usize>().ok()?;
            if start <= end {
                cpus.extend(start..=end);
            }
        } else {
            let cpu = part.parse::<usize>().ok()?;
            cpus.push(cpu);
        }
    }
    cpus.sort_unstable();
    cpus.dedup();
    Some(cpus)
}

/// Builds a Linux RPS/XPS hex bitmask from a list of CPU indices.
///
/// For $\le 32$ CPUs, returns a simple hex string like `"ff"` for 8 CPUs.
/// For $> 32$ CPUs, Linux requires comma-separated 32-bit hex values in reverse order
/// (e.g. `"ffffffff,ffffffff"` for 64 CPUs).
#[must_use]
pub fn format_cpu_mask(cpus: &[usize]) -> String {
    if cpus.is_empty() {
        return "1".to_string();
    }

    let max_cpu = *cpus.iter().max().unwrap_or(&0);
    let num_words = (max_cpu / 32) + 1;
    let mut words = vec![0u32; num_words];

    for &cpu in cpus {
        let word_idx = cpu / 32;
        let bit_idx = cpu % 32;
        words[word_idx] |= 1u32 << bit_idx;
    }

    if num_words == 1 {
        return format!("{:x}", words[0]);
    }

    // Linux prints most significant 32-bit chunk first, comma-separated.
    let mut out = String::with_capacity(num_words * 9);
    for (i, &w) in words.iter().rev().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(&mut out, "{w:x}");
    }
    out
}

/// Resolves the effective CPU mask string (either auto-detected or user configured).
#[must_use]
pub fn resolve_effective_cpu_mask(configured: &str) -> String {
    let trimmed = configured.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") {
        let online = detect_online_cpus();
        let mask = format_cpu_mask(&online);
        debug!(mask = %mask, "Calculated dynamic CPU affinity mask for RPS/XPS");
        mask
    } else {
        // Strip optional 0x prefix if user passed it
        let cleaned = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        cleaned.to_lowercase()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cpu_range_list() {
        assert_eq!(
            parse_cpu_range_list("0-7").unwrap(),
            vec![0, 1, 2, 3, 4, 5, 6, 7]
        );
        assert_eq!(
            parse_cpu_range_list("0-3,5-6").unwrap(),
            vec![0, 1, 2, 3, 5, 6]
        );
        assert_eq!(parse_cpu_range_list("0\n").unwrap(), vec![0]);
    }

    #[test]
    fn test_format_cpu_mask() {
        // 4 CPUs: 0,1,2,3 -> 0xf
        assert_eq!(format_cpu_mask(&[0, 1, 2, 3]), "f");
        // 8 CPUs: 0..7 -> 0xff
        assert_eq!(format_cpu_mask(&(0..8).collect::<Vec<_>>()), "ff");
        // 16 CPUs: 0..15 -> 0xffff
        assert_eq!(format_cpu_mask(&(0..16).collect::<Vec<_>>()), "ffff");
        // 32 CPUs -> 0xffffffff
        assert_eq!(format_cpu_mask(&(0..32).collect::<Vec<_>>()), "ffffffff");
        // 33 CPUs -> "1,ffffffff"
        assert_eq!(format_cpu_mask(&(0..33).collect::<Vec<_>>()), "1,ffffffff");
    }

    #[test]
    fn test_resolve_effective_cpu_mask() {
        assert_eq!(resolve_effective_cpu_mask("0xff"), "ff");
        assert_eq!(resolve_effective_cpu_mask("FF"), "ff");
        assert_eq!(resolve_effective_cpu_mask("0x1f"), "1f");
        assert_ne!(resolve_effective_cpu_mask("auto"), "");
    }
}
