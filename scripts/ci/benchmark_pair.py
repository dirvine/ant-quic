#!/usr/bin/env python3
"""Disposable, single-pair benchmark diagnostic. Never retry a measurement."""

import argparse
import hashlib
import io
import json
import math
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import time

import criterion_report


SOURCES = {
    "baseline": "f2f1934f4cd7e9b6d36c9677c10c21a87086f1e1",
    "current": "e67ab23c98ae76840f1e155ae569463683db4a78",
}
LOCK_SHA = "4067f167050d2c0a1dae2da2228274d05d2d1b71d63d0c2fd52b5119c6141b2b"
BENCHES = {
    "nat_traversal_performance": "current-nat",
    "connection_management": "current-conn",
}
COMPARABLE = ("Cargo.lock", "Cargo.toml", ".cargo/config.toml",
              "benches/nat_traversal_performance.rs", "benches/connection_management.rs")
ACTIVE = None


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, allow_nan=False) + "\n")


def exclusive(path):
    path.mkdir(mode=0o700, parents=False, exist_ok=False)
    return path


def file_inventory(root):
    return {str(p.relative_to(root)): sha(p)
            for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()}


def environment():
    result = {key: os.environ.get(key) for key in (
        "ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH", "CARGO_INCREMENTAL",
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_JOBS", "RUST_BACKTRACE",
    )}
    for name, command in (("cpu", ["lscpu", "--json"]), ("os", ["uname", "-srvmo"])):
        try:
            process = subprocess.run(command, capture_output=True, text=True)
            result[name] = {"exit": process.returncode, "stdout": process.stdout, "stderr": process.stderr}
        except OSError as error:
            result[name] = {"exit": None, "unavailable": str(error)}
    for name, path in (("load", Path("/proc/loadavg")),
                       ("governor", Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")),
                       ("frequency_khz", Path("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq"))):
        try:
            result[name] = path.read_text().strip()
        except OSError:
            result[name] = None
    result["affinity"] = sorted(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else None
    return result


def stop_owned(process):
    # A live/unreaped leader reserves its PID; never signal an already-reaped PGID.
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()


def interrupted(signum, _frame):
    if ACTIVE is not None:
        stop_owned(ACTIVE)
    raise InterruptedError(f"diagnostic interrupted by signal {signum}")


def command(argv, cwd, env, prefix, timeout=None):
    global ACTIVE
    started = time.monotonic()
    receipt = {"argv": list(map(str, argv)), "cwd": str(cwd), "timeout": timeout}
    with prefix.with_suffix(".stdout").open("wb") as stdout, prefix.with_suffix(".stderr").open("wb") as stderr:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
        ACTIVE = process
        try:
            receipt["exit"] = process.wait(timeout=timeout)
        except BaseException as error:
            stop_owned(process)
            receipt.update(exit=process.returncode, error=type(error).__name__)
            raise
        finally:
            receipt.update(elapsed_seconds=time.monotonic() - started, reaped=process.returncode is not None)
            ACTIVE = None
            save(prefix.with_suffix(".json"), receipt)
    if receipt["exit"] != 0:
        raise RuntimeError(f"command failed: {argv[0]} (exit {receipt['exit']})")


def package_id(metadata, source):
    matches = [p["id"] for p in metadata["packages"]
               if Path(p["manifest_path"]) == source / "Cargo.toml" and p["name"] == "ant-quic"]
    if len(matches) != 1:
        raise ValueError("root package metadata is ambiguous")
    return matches[0]


def artifacts(rows, source, target, package):
    selected = {}
    for row in rows:
        if row.get("reason") != "compiler-artifact" or row.get("package_id") != package:
            continue
        name = row["target"]["name"]
        wanted = name in BENCHES or (name == "ant_quic" and "lib" in row["target"]["kind"])
        if not wanted:
            continue
        if name in selected or row["fresh"] is not False or Path(row["manifest_path"]) != source / "Cargo.toml":
            raise ValueError("missing fresh, uniquely owned compiler artifact")
        paths = [Path(p) for p in row["filenames"]]
        if not paths or any(not p.resolve().is_relative_to(target.resolve()) or not p.is_file() for p in paths):
            raise ValueError("compiler artifact escaped its exclusive target")
        if name in BENCHES and ("bench" not in row["target"]["kind"] or row.get("executable") not in row["filenames"]):
            raise ValueError("benchmark executable not in compiler artifact")
        selected[name] = {"cargo": row, "files": {str(p): sha(p) for p in paths}}
    if set(selected) != {"ant_quic", *BENCHES}:
        raise ValueError("required library/benchmark compiler artifacts missing")
    return selected


def build(repo, root):
    exclusive(root)
    payload = exclusive(root / "payload")
    manifest = {"sources": SOURCES, "lock_sha256": LOCK_SHA, "variants": {}, "environment": environment()}
    toolchain = subprocess.check_output(["rustc", "-Vv"], text=True)
    if ("release: 1.98.1\n" not in toolchain
            or "commit-hash: 48a229ceaefd4985c50990b14116b6d856af0985\n" not in toolchain
            or "host: x86_64-unknown-linux-gnu\n" not in toolchain):
        raise ValueError("unexpected compiler")
    if any(os.environ.get(key) for key in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS")):
        raise ValueError("unexpected compiler flags")
    manifest["rustc"] = toolchain
    manifest["cargo"] = subprocess.check_output(["cargo", "-V"], text=True)
    for label, revision in SOURCES.items():
        source = exclusive(root / f"source-{label}")
        target = exclusive(root / f"target-{label}")
        output = exclusive(payload / label)
        archive = subprocess.check_output(["git", "archive", revision], cwd=repo)
        with tarfile.open(fileobj=io.BytesIO(archive)) as bundle:
            bundle.extractall(source, filter="data")
        before = file_inventory(source)
        if before["Cargo.lock"] != LOCK_SHA:
            raise ValueError("unexpected source lock")
        env = {**os.environ, "CARGO_TARGET_DIR": str(target), "CARGO_INCREMENTAL": "0"}
        command(["cargo", "metadata", "--locked", "--format-version", "1"], source, env, output / "metadata")
        metadata = json.loads((output / "metadata.stdout").read_text())
        command(["cargo", "bench", "--locked", "--no-run", "--bench", "nat_traversal_performance",
                 "--bench", "connection_management", "--message-format=json"], source, env, output / "build")
        rows = [json.loads(line) for line in (output / "build.stdout").read_text().splitlines() if line]
        emitted = artifacts(rows, source, target, package_id(metadata, source))
        if file_inventory(source) != before:
            raise ValueError("source or lock changed during build")
        executables = {}
        for name in BENCHES:
            original = Path(emitted[name]["cargo"]["executable"])
            destination = output / name
            shutil.copyfile(original, destination)
            destination.chmod(0o700)
            if sha(destination) != emitted[name]["files"][str(original)]:
                raise ValueError("executable snapshot changed")
            executables[name] = {"relative_path": str(destination.relative_to(payload)), "sha256": sha(destination)}
        manifest["variants"][label] = {
            "commit": revision, "tree": subprocess.check_output(["git", "rev-parse", revision + "^{tree}"], cwd=repo, text=True).strip(),
            "source": str(source), "target": str(target), "source_files": before,
            "archive_sha256": hashlib.sha256(archive).hexdigest(), "artifacts": emitted, "executables": executables,
        }
    left, right = (manifest["variants"][key] for key in SOURCES)
    if left["target"] == right["target"] or left["source"] == right["source"]:
        raise ValueError("variants share build roots")
    if any(left["source_files"][name] != right["source_files"][name] for name in COMPARABLE):
        raise ValueError("measured source/config is not identical")
    save(payload / "manifest.json", manifest)
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write(f"manifest_sha256={sha(payload / 'manifest.json')}\n")


def verify_payload(payload, expected):
    if sha(payload / "manifest.json") != expected:
        raise ValueError("build manifest digest mismatch")
    manifest = json.loads((payload / "manifest.json").read_text())
    if manifest["sources"] != SOURCES or manifest["lock_sha256"] != LOCK_SHA:
        raise ValueError("unexpected source/lock custody")
    roots = [manifest["variants"][key]["target"] for key in SOURCES]
    if len(set(roots)) != 2:
        raise ValueError("variants share build targets")
    for label in SOURCES:
        variant = manifest["variants"][label]
        if variant["commit"] != SOURCES[label] or variant["source_files"]["Cargo.lock"] != LOCK_SHA:
            raise ValueError("variant custody mismatch")
        for name in BENCHES:
            item = variant["executables"][name]
            path = payload / item["relative_path"]
            if item["relative_path"] != f"{label}/{name}" or sha(path) != item["sha256"]:
                raise ValueError("executable digest/path mismatch")
            path.chmod(0o700)  # upload/download-artifact does not retain executable mode.
    return manifest


def measure(repo, payload, expected, root, outer_deadline):
    exclusive(root)
    started = time.monotonic()
    terminal = {"phase": "admission", "exit": None}
    try:
        if not math.isfinite(outer_deadline) or outer_deadline - started < 24 * 60:
            raise TimeoutError("insufficient outer-clock reserve for full 24-minute measurement")
        deadline = min(started + 24 * 60, outer_deadline)
        terminal.update(outer_deadline_monotonic=outer_deadline, measurement_deadline_monotonic=deadline,
                        outer_seconds_remaining_at_admission=outer_deadline - started)
        manifest = verify_payload(payload, expected)
        save(root / "build-manifest.json", manifest)
        save(root / "host.json", environment())
        for label in SOURCES:
            home = exclusive(root / label)
            env = {**os.environ, "CRITERION_HOME": str(home), "RUST_BACKTRACE": "1"}
            for name, baseline_label in BENCHES.items():
                terminal["phase"] = f"{label}/{name}"
                save(home / f"{name}-before.json", environment())
                executable = payload / manifest["variants"][label]["executables"][name]["relative_path"]
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("total measurement deadline reached")
                command([str(executable), "--bench", "--save-baseline", baseline_label],
                        home, env, home / f"{name}-command", timeout=remaining)
                save(home / f"{name}-after.json", environment())
            criterion_report.write_records(home / "benchmark-results.json", criterion_report.convert(home))
        verify_payload(payload, expected)
        terminal["phase"] = "comparison"
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("total measurement deadline reached before comparison")
        command([sys.executable, str(repo / ".github/scripts/compare-benchmarks.py"),
                 str(root / "baseline/benchmark-results.json"), str(root / "current/benchmark-results.json")],
                root, os.environ.copy(), root / "comparison", timeout=remaining)
        report = (root / "comparison.stdout").read_text()
        terminal.update(exit=1 if "REGRESSION" in report else 0, measurements_per_variant=54,
                        threshold_percent=10, complete=True)
    except BaseException as error:
        terminal.update(exit=1, error=f"{type(error).__name__}: {error}", complete=False)
        raise
    finally:
        terminal["elapsed_seconds"] = time.monotonic() - started
        save(root / "terminal.json", terminal)
    return terminal["exit"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("build", "measure"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--payload", type=Path)
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--outer-deadline", type=float)
    args = parser.parse_args()
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    repo = Path(__file__).resolve().parents[2]
    if args.phase == "build":
        build(repo, args.root)
        return 0
    if args.payload is None or args.manifest_sha256 is None or args.outer_deadline is None:
        parser.error("measure requires --payload, --manifest-sha256 and --outer-deadline")
    return measure(repo, args.payload, args.manifest_sha256, args.root, args.outer_deadline)


if __name__ == "__main__":
    sys.exit(main())
