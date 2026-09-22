use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn try_compile_bpf(bpf_c: &Path, bpf_o: &Path) -> Result<(), String> {
    // Check if clang is present
    let clang_test = Command::new("clang").arg("--version").output();
    if clang_test.is_err() {
        return Err("clang not found in PATH".into());
    }

    // Resolve include paths for vmlinux.h and bpf_helpers.h.
    let (vmlinux_inc, libbpf_inc) = if let Ok(ksrc) = env::var("KERNEL_SRC") {
        let libbpf = format!("{ksrc}/tools/bpf/resolve_btfids/libbpf/include");
        (ksrc, libbpf)
    } else {
        let release = match Command::new("uname").arg("-r").output() {
            Ok(out) => String::from_utf8_lossy(&out.stdout).trim().to_string(),
            Err(_) => return Err("failed to execute uname -r".into()),
        };

        let candidates = [
            format!("/usr/src/kernels/{release}"),
            format!("/usr/src/linux-headers-{release}"),
            format!("/lib/modules/{release}/build"),
        ];

        let ksrc = candidates
            .iter()
            .find(|p| PathBuf::from(p).join("vmlinux.h").exists())
            .cloned();

        let Some(ksrc) = ksrc else {
            return Err(format!("vmlinux.h not found for kernel {release}"));
        };

        let libbpf = format!("{ksrc}/tools/bpf/resolve_btfids/libbpf/include");
        (ksrc, libbpf)
    };

    let status = Command::new("clang")
        .args([
            "-target",
            "bpf",
            "-O2",
            "-g",
            "-Wall",
            "-Wno-missing-declarations",
            &format!("-I{vmlinux_inc}"),
            &format!("-I{libbpf_inc}"),
            "-c",
            bpf_c.to_str().unwrap(),
            "-o",
            bpf_o.to_str().unwrap(),
        ])
        .status();

    match status {
        Ok(s) if s.success() => Ok(()),
        Ok(s) => Err(format!("clang exited with status {s}")),
        Err(e) => Err(format!("failed to execute clang: {e}")),
    }
}

fn main() {
    if env::var("CARGO_FEATURE_EBPF").is_err() {
        return;
    }

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let bpf_c = manifest_dir.join("bpf/pppoe_fastpath.bpf.c");
    let bundled_bpf_o = manifest_dir.join("bpf/pppoe_fastpath.bpf.o");

    println!("cargo:rerun-if-changed={}", bpf_c.display());
    println!("cargo:rerun-if-changed={}", bundled_bpf_o.display());

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let bpf_o = out_dir.join("pppoe_fastpath.bpf.o");

    match try_compile_bpf(&bpf_c, &bpf_o) {
        Ok(()) => {
            // Update the bundled copy in the crate source tree if possible
            let _ = std::fs::copy(&bpf_o, &bundled_bpf_o);
        }
        Err(err) => {
            if bundled_bpf_o.exists() {
                println!(
                    "cargo:warning=Using pre-compiled PPPoE eBPF bytecode ({err})."
                );
                std::fs::copy(&bundled_bpf_o, &bpf_o)
                    .expect("failed to copy pre-compiled bpf.o to OUT_DIR");
            } else {
                panic!(
                    "Failed to compile eBPF PPPoE fastpath bytecode and no pre-compiled bytecode found: {err}\n\
                     On Fedora/RHEL: dnf install kernel-devel clang\n\
                     On Debian/RPiOS: apt install linux-headers-generic clang\n\
                     Or set KERNEL_SRC=/path/to/kernel-build-tree"
                );
            }
        }
    }

    // Emit a hash of the compiled bytecode as a rustc-env variable.
    let bytecode = std::fs::read(&bpf_o).expect("failed to read compiled .o for hashing");
    let hash = bytecode.iter().fold(0u64, |acc, &b| {
        acc.wrapping_mul(6364136223846793005).wrapping_add(b as u64)
    });
    println!("cargo:rustc-env=PPPOE_BPF_HASH={hash:016x}");
}
