#!/usr/bin/env python3
"""Build and run isolated core workloads; never connects to a Lanforge instance."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess

SCENARIOS = ["new", "renew", "arp", "ndp", "batch", "lookup", "snapshot",
             "held-snapshot", "contended", "renumber", "dns", "dns-busy", "dhcp"]
MODES = {"native": "dns,dhcp", "timing": "dns,dhcp,hotpath",
         "alloc-bytes": "dns,dhcp,hotpath-alloc", "alloc-count": "dns,dhcp,hotpath-alloc"}


def command(args):
    return subprocess.check_output(args, text=True).strip()


def build(output, mode, env):
    # Byte/count collection uses the same executable, with a different report metric.
    binary = output / "binaries" / mode
    if mode == "alloc-count":
        shutil.copy2(output / "binaries" / "alloc-bytes", binary)
        return binary
    print(f"Building {mode}", flush=True)
    with (output / f"build-{mode}.log").open("w") as log:
        result = subprocess.run(["cargo", "build", "-p", "lanforge", "--bench", "core_baseline",
                                 "--profile", "perf-release", "--no-default-features", "--features",
                                 MODES[mode], "--message-format=json"], env=env,
                                stdout=subprocess.PIPE, stderr=log, text=True, check=True)
    artifacts = [json.loads(line) for line in result.stdout.splitlines()]
    source = next(row["executable"] for row in artifacts if row.get("executable")
                  and row.get("target", {}).get("name") == "core_baseline")
    shutil.copy2(source, binary)
    return binary


def summarize(rows):
    result = []
    for size in sorted({row["devices"] for row in rows}):
        for scenario in SCENARIOS:
            cases = [r for r in rows if r["mode"] == "native" and r["devices"] == size
                     and r["scenario_cli"] == scenario]
            if not cases:
                continue
            first = cases[0]["measurements"]
            paths = list(first) if scenario in ("contended", "dns", "dns-busy", "dhcp") else [None]
            for path in paths:
                sample = first if path is None else first[path]
                if not isinstance(sample, dict) or "p50_ns" not in sample:
                    continue
                values = [r["measurements"] if path is None else r["measurements"][path] for r in cases]
                result.append({"devices": size, "scenario": scenario, "path": path,
                               "repetitions": len(cases),
                               **{key: statistics.median(v[key] for v in values)
                                  for key in ("p50_ns", "p95_ns", "p99_ns", "mean_ns")}})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--devices", nargs="+", type=int, default=[50, 500, 5000])
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument("--repetitions", type=int, default=5)
    parser.add_argument("--modes", nargs="+", choices=list(MODES), default=list(MODES))
    parser.add_argument("--scenarios", nargs="+", choices=SCENARIOS, default=SCENARIOS)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    (output / "binaries").mkdir()
    (output / "profiles").mkdir()
    root = Path(__file__).resolve().parent.parent
    os.chdir(root)
    env = {k: v for k, v in os.environ.items() if not k.startswith("HOTPATH_")}
    env["CARGO_INCREMENTAL"] = "0"
    env["HOTPATH_METRICS_SERVER_OFF"] = "1"
    env["HOTPATH_FUNCTIONS_NAME_DEPTH"] = "0"
    cpu = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")), "unknown")
    metadata = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "commit": command(["git", "rev-parse", "HEAD"]),
                "tracked_diff_sha256": hashlib.sha256(command(["git", "diff", "HEAD"]).encode()).hexdigest(),
                "rustc": command(["rustc", "-vV"]), "platform": platform.platform(), "cpu": cpu,
                "cpu_affinity": sorted(os.sched_getaffinity(0)), "profile": "perf-release",
                "workload": "fixed sequential identities; production randomized HashMaps",
                "arguments": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()}}
    (output / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    rows = []
    for mode in args.modes:
        if mode == "alloc-count" and not (output / "binaries" / "alloc-bytes").exists():
            build(output, "alloc-bytes", env)
        binary = build(output, mode, env)
        for size in args.devices:
            for scenario in args.scenarios:
                for repetition in range(args.repetitions if mode == "native" else 1):
                    label = f"{mode}-{size}-{scenario}-{repetition}"
                    print(label, flush=True)
                    run_env = dict(env)
                    profile = output / "profiles" / f"{label}.json"
                    if mode != "native":
                        run_env.update(HOTPATH_OUTPUT_FORMAT="json", HOTPATH_OUTPUT_PATH=str(profile),
                                       HOTPATH_ALLOC_METRIC="count" if mode == "alloc-count" else "bytes",
                                       HOTPATH_ALLOC_CUMULATIVE="1")
                    with (output / f"{label}.stderr").open("w") as log:
                        run = subprocess.run([str(binary), "--devices", str(size), "--scenario", scenario,
                                              "--iterations", str(args.iterations), "--warmup", str(args.warmup)],
                                             env=run_env, stdout=subprocess.PIPE, stderr=log, text=True,
                                             timeout=120, check=True)
                    row = json.loads(run.stdout)
                    row.update(mode=mode, scenario_cli=scenario, repetition=repetition)
                    if mode != "native":
                        report = json.loads(profile.read_text())
                        key = "functions_alloc" if mode.startswith("alloc") else "functions_timing"
                        if not report.get(key, {}).get("data"):
                            raise RuntimeError(f"empty profiler report: {label}")
                    rows.append(row)
                    with (output / "runs.jsonl").open("a") as stream:
                        stream.write(json.dumps(row) + "\n")
    summary = {"metadata": metadata, "native_medians": summarize(rows)}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"Results: {output / 'summary.json'}")


if __name__ == "__main__":
    main()
