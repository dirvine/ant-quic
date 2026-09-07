"""Offline custody and orchestration controls; no Rust executable is run."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import benchmark_pair as pair
import test_criterion_report


class PairTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.payload = pair.exclusive(self.root / "payload")
        self.manifest = {"sources": pair.SOURCES, "lock_sha256": pair.LOCK_SHA, "variants": {}}
        for label, revision in pair.SOURCES.items():
            output = pair.exclusive(self.payload / label)
            executables = {}
            for name in pair.BENCHES:
                path = output / name
                path.write_bytes(b"identical inert executable fixture; never executed")
                executables[name] = {"relative_path": f"{label}/{name}", "sha256": pair.sha(path)}
            self.manifest["variants"][label] = {
                "commit": revision, "source_files": {"Cargo.lock": pair.LOCK_SHA},
                "target": f"/owned/target-{label}", "executables": executables,
            }
        self.digest = self.write_manifest()

    def write_manifest(self):
        pair.save(self.payload / "manifest.json", self.manifest)
        return pair.sha(self.payload / "manifest.json")

    def test_equal_binary_hashes_allowed_with_separate_roots(self):
        pair.verify_payload(self.payload, self.digest)
        for name in pair.BENCHES:
            self.assertEqual(pair.sha(self.payload / "baseline" / name), pair.sha(self.payload / "current" / name))

    def test_manifest_and_executable_tampering_fail(self):
        with self.assertRaisesRegex(ValueError, "manifest digest"):
            pair.verify_payload(self.payload, "0" * 64)
        (self.payload / "current/nat_traversal_performance").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "executable digest"):
            pair.verify_payload(self.payload, self.digest)

    def test_shared_target_rejected_even_with_valid_manifest_hash(self):
        self.manifest["variants"]["current"]["target"] = self.manifest["variants"]["baseline"]["target"]
        with self.assertRaisesRegex(ValueError, "share build targets"):
            pair.verify_payload(self.payload, self.write_manifest())

    def test_wrong_lock_and_source_rejected(self):
        self.manifest["lock_sha256"] = "wrong"
        with self.assertRaisesRegex(ValueError, "source/lock"):
            pair.verify_payload(self.payload, self.write_manifest())

    def test_executable_path_escape_rejected(self):
        self.manifest["variants"]["current"]["executables"]["nat_traversal_performance"]["relative_path"] = "../foreign"
        with self.assertRaisesRegex(ValueError, "executable digest/path"):
            pair.verify_payload(self.payload, self.write_manifest())

    def test_preexisting_output_is_not_reused(self):
        with self.assertRaises(FileExistsError):
            pair.exclusive(self.payload)

    def rows(self):
        source = self.root / "source"
        target = pair.exclusive(self.root / "target")
        rows = []
        for name in ("ant_quic", *pair.BENCHES):
            file = target / name
            file.write_bytes(b"fixture")
            rows.append({
                "reason": "compiler-artifact", "package_id": "owned-package", "manifest_path": str(source / "Cargo.toml"),
                "target": {"name": name, "kind": ["lib" if name == "ant_quic" else "bench"]},
                "filenames": [str(file)], "executable": None if name == "ant_quic" else str(file), "fresh": False,
            })
        return rows, source, target

    def test_actual_artifact_selector_requires_owned_fresh_rows(self):
        rows, source, target = self.rows()
        self.assertEqual(set(pair.artifacts(rows, source, target, "owned-package")), {"ant_quic", *pair.BENCHES})
        for index in range(3):
            changed = copy.deepcopy(rows)
            changed[index]["fresh"] = True
            with self.assertRaisesRegex(ValueError, "fresh"):
                pair.artifacts(changed, source, target, "owned-package")
        with self.assertRaisesRegex(ValueError, "missing"):
            pair.artifacts(rows[:-1], source, target, "owned-package")

    def test_foreign_emitted_path_and_manifest_rejected(self):
        rows, source, target = self.rows()
        foreign = self.root / "foreign"
        foreign.write_bytes(b"fixture")
        rows[0]["filenames"] = [str(foreign)]
        with self.assertRaisesRegex(ValueError, "escaped"):
            pair.artifacts(rows, source, target, "owned-package")
        rows[0]["manifest_path"] = str(self.root / "wrong/Cargo.toml")
        with self.assertRaisesRegex(ValueError, "owned"):
            pair.artifacts(rows, source, target, "owned-package")

    def simulate_pair(self, current_mean=100, fail_phase=None):
        calls = []
        original = pair.command

        def fake(argv, cwd, env, prefix, timeout=None):
            if argv[0] == sys.executable:
                return original(argv, cwd, env, prefix, timeout)
            label = Path(argv[0]).parent.name
            name = Path(argv[0]).name
            calls.append((label, name, list(argv[1:])))
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 24 * 60)
            if (label, name) == fail_phase:
                raise RuntimeError("synthetic benchmark failure")
            if name == "connection_management":
                test_criterion_report.fixture(cwd, current_mean if label == "current" else 100)

        measurement = self.root / "measurement"
        with mock.patch.object(pair, "command", side_effect=fake), mock.patch.object(pair, "environment", return_value={"fixture": True}):
            result = pair.measure(Path(__file__).resolve().parents[2], self.payload, self.digest, measurement, pair.time.monotonic() + 1500)
        return result, calls, json.loads((measurement / "terminal.json").read_text())

    def test_exact_four_phase_order_and_real_comparator_stable(self):
        result, calls, terminal = self.simulate_pair()
        self.assertEqual(result, 0)
        self.assertTrue(terminal["complete"])
        self.assertEqual(terminal["measurements_per_variant"], 54)
        self.assertEqual(calls, [(label, name, ["--bench", "--save-baseline", baseline])
                                 for label in pair.SOURCES for name, baseline in pair.BENCHES.items()])

    def test_real_comparator_preserves_ten_percent_failure(self):
        result, _, terminal = self.simulate_pair(current_mean=120)
        self.assertEqual(result, 1)
        self.assertTrue(terminal["complete"])
        self.assertEqual(terminal["threshold_percent"], 10)

    def test_phase_failure_writes_terminal_without_comparison(self):
        with self.assertRaisesRegex(RuntimeError, "synthetic"):
            self.simulate_pair(fail_phase=("baseline", "nat_traversal_performance"))
        terminal = json.loads((self.root / "measurement/terminal.json").read_text())
        self.assertFalse(terminal["complete"])
        self.assertEqual(terminal["phase"], "baseline/nat_traversal_performance")
        self.assertFalse((self.root / "measurement/comparison.stdout").exists())

    def test_reaped_process_is_never_signaled(self):
        process = mock.Mock()
        process.poll.return_value = 0
        with mock.patch.object(pair.os, "killpg") as kill:
            pair.stop_owned(process)
            kill.assert_not_called()
            process.wait.assert_not_called()

    def test_total_deadline_prevents_starting_another_phase(self):
        output = self.root / "deadline"
        with mock.patch.object(pair, "environment", return_value={}), \
                mock.patch.object(pair.time, "monotonic", side_effect=[0, 1441, 1442]), \
                mock.patch.object(pair, "command") as command:
            with self.assertRaises(TimeoutError):
                pair.measure(Path(__file__).resolve().parents[2], self.payload, self.digest, output, 1500)
            command.assert_not_called()
        terminal = json.loads((output / "terminal.json").read_text())
        self.assertFalse(terminal["complete"])
        self.assertEqual(terminal["phase"], "baseline/nat_traversal_performance")

    def test_expired_budget_cannot_start_comparator_or_mark_complete(self):
        output = self.root / "expired-comparison"
        calls = []
        with mock.patch.object(pair.time, "monotonic", return_value=0) as clock:
            def fake(argv, cwd, env, prefix, timeout=None):
                self.assertNotEqual(argv[0], sys.executable, "comparator started after deadline")
                calls.append(argv)
                if Path(argv[0]).name == "connection_management":
                    test_criterion_report.fixture(cwd, 100)
                if len(calls) == 4:
                    clock.return_value = 1441
            with mock.patch.object(pair, "command", side_effect=fake), \
                    mock.patch.object(pair, "environment", return_value={}):
                with self.assertRaisesRegex(TimeoutError, "before comparison"):
                    pair.measure(self.root, self.payload, self.digest, output, 1500)
        self.assertEqual(len(calls), 4)
        terminal = json.loads((output / "terminal.json").read_text())
        self.assertFalse(terminal["complete"])
        self.assertEqual(terminal["phase"], "comparison")
        self.assertFalse((output / "comparison.stdout").exists())

    def test_setup_exhausting_reserve_fails_before_any_benchmark(self):
        for remaining in (1439, 0, -1, float("inf"), float("nan")):
            with self.subTest(remaining=remaining):
                output = self.root / f"reserve-{remaining}"
                with mock.patch.object(pair.time, "monotonic", return_value=100), \
                        mock.patch.object(pair, "verify_payload") as verify, \
                        mock.patch.object(pair, "command") as command:
                    with self.assertRaisesRegex(TimeoutError, "outer-clock reserve"):
                        pair.measure(self.root, self.payload, self.digest, output, 100 + remaining)
                    verify.assert_not_called()
                    command.assert_not_called()
                terminal = json.loads((output / "terminal.json").read_text())
                self.assertFalse(terminal["complete"])
                self.assertEqual(terminal["phase"], "admission")

    def test_exact_full_budget_is_admitted_without_shortening(self):
        output = self.root / "full-budget"
        with mock.patch.object(pair.time, "monotonic", return_value=100), \
                mock.patch.object(pair, "verify_payload", side_effect=RuntimeError("past timing admission")):
            with self.assertRaisesRegex(RuntimeError, "past timing admission"):
                pair.measure(self.root, self.payload, self.digest, output, 1540)
        terminal = json.loads((output / "terminal.json").read_text())
        self.assertEqual(terminal["measurement_deadline_monotonic"], 1540)
        self.assertEqual(terminal["outer_seconds_remaining_at_admission"], 1440)

    def test_timeout_records_failure_and_stops_only_retained_process(self):
        process = mock.Mock(pid=12345, returncode=0)
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired(["inert"], 1), 0]
        prefix = self.root / "timeout"
        with mock.patch.object(pair.subprocess, "Popen", return_value=process) as spawn, \
                mock.patch.object(pair.os, "killpg") as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                pair.command(["inert"], self.root, {}, prefix, timeout=1)
            self.assertEqual(spawn.call_count, 1)
            kill.assert_called_once_with(12345, pair.signal.SIGTERM)
        receipt = json.loads(prefix.with_suffix(".json").read_text())
        self.assertEqual(receipt["error"], "TimeoutExpired")
        self.assertTrue(receipt["reaped"])


if __name__ == "__main__":
    unittest.main()
