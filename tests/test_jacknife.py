"""JacKnife ladder, artifact rejection, and CLI checks."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["PATH"] = str(Path.home() / ".local" / "bin") + os.pathsep + os.environ.get("PATH", "")

from scripts.ladder_bridge import classify_many  # noqa: E402
from scripts.schema import dumps, sha256_bytes  # noqa: E402
from scripts.textsafe import escape_untrusted, has_hostile  # noqa: E402
from scripts.trigger_and_poll import (  # noqa: E402
    ApiError,
    default_transport,
    host_allowed,
    run_corroborates,
    trigger_and_poll,
)
from scripts.validate_artifact import ArtifactRejected, read_dir, read_zip, validate_files  # noqa: E402
from scripts.validate_workflow_inputs import sanitized  # noqa: E402
from scripts.verify_attestation import verify  # noqa: E402


def _base_evidence(**overrides):
    evidence = {
        "simulated": False,
        "rejected": False,
        "reproduced": True,
        "minimized": True,
        "artifact_verified": True,
        "workflow_corroborated": True,
        "attestation_verified": False,
        "sanitizer": "address",
        "crash_type": "heap-buffer-overflow",
        "input_hex": "abcd",
        "stack_trace": "#0 bug_heap_bind",
        "report_excerpt": "ERROR: AddressSanitizer: heap-buffer-overflow",
    }
    evidence.update(overrides)
    return evidence


class LadderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.labels = classify_many(
            [
                _base_evidence(),
                _base_evidence(simulated=True),
                _base_evidence(workflow_corroborated=False),
                _base_evidence(
                    sanitizer="undefined",
                    crash_type="undefined-behavior",
                    report_excerpt="SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior target/jkpacket.c:77:34",
                ),
                _base_evidence(
                    sanitizer="undefined",
                    crash_type="signed-integer-overflow",
                    workflow_corroborated=False,
                    report_excerpt=(
                        "runtime error: signed integer overflow: 2147483647 + 1 "
                        "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior"
                    ),
                ),
                _base_evidence(stack_trace="#0 \u202e hidden"),
                _base_evidence(reproduced=1),
                _base_evidence(minimized=False),
                _base_evidence(workflow_corroborated=False, attestation_verified=True),
                _base_evidence(report_excerpt="ERROR: AddressSanitizer: heap-buffer-overflow", stack_trace="no frame"),
            ]
        )

    def test_full_evidence_is_confirmed(self):
        self.assertEqual(self.labels[0], "Confirmed")

    def test_simulated_cannot_be_confirmed(self):
        self.assertEqual(self.labels[1], "Sample")

    def test_missing_workflow_stops_at_sanitizer(self):
        self.assertEqual(self.labels[2], "Sanitizer-classified (ASan)")

    def test_generic_ubsan_token_is_not_a_class(self):
        self.assertEqual(self.labels[3], "Minimized")

    def test_signed_overflow_sentence_is_ubsan(self):
        self.assertEqual(self.labels[4], "Sanitizer-classified (UBSan)")

    def test_bidi_is_rejected(self):
        self.assertEqual(self.labels[5], "Rejected")

    def test_integer_is_not_a_bool(self):
        self.assertEqual(self.labels[6], "Real crash captured")

    def test_not_minimized_stops_at_reproduced(self):
        self.assertEqual(self.labels[7], "Reproduced")

    def test_attested_without_workflow(self):
        self.assertEqual(self.labels[8], "Attested")

    def test_confirmed_needs_a_frame(self):
        self.assertEqual(self.labels[9], "Sanitizer-classified (ASan)")


class InputTests(unittest.TestCase):
    def _run(self, **env):
        base = {key: value for key, value in os.environ.items() if not key.startswith("JACKNIFE_")}
        base.update(env)
        proc = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "validate_workflow_inputs.py")],
            cwd=ROOT,
            env=base,
            text=True,
            capture_output=True,
            check=False,
        )
        return proc

    def test_accepts_uuid_like_run_id(self):
        proc = self._run(
            JACKNIFE_INPUT_RUN_ID="abc-1",
            JACKNIFE_INPUT_DURATION="90",
            JACKNIFE_INPUT_SEED="1",
            JACKNIFE_GITHUB_REPOSITORY="MPH04/JacKnife",
            JACKNIFE_GITHUB_SHA="a" * 40,
            JACKNIFE_GITHUB_RUN_ID="42",
            JACKNIFE_GITHUB_SERVER_URL="https://github.com",
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_rejects_newline_injection(self):
        proc = self._run(
            JACKNIFE_INPUT_RUN_ID="abc\nJACKNIFE_SEED=0",
            JACKNIFE_INPUT_DURATION="90",
            JACKNIFE_INPUT_SEED="1",
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn("JACKNIFE_SEED=0", proc.stdout)

    def test_rejects_shell_metacharacters(self):
        proc = self._run(JACKNIFE_INPUT_RUN_ID='abc";touch pwned', JACKNIFE_INPUT_DURATION="90", JACKNIFE_INPUT_SEED="1")
        self.assertNotEqual(proc.returncode, 0)

    def test_rejects_duration_overflow_and_junk(self):
        self.assertNotEqual(self._run(JACKNIFE_INPUT_RUN_ID="abc", JACKNIFE_INPUT_DURATION="999", JACKNIFE_INPUT_SEED="1").returncode, 0)
        self.assertNotEqual(self._run(JACKNIFE_INPUT_RUN_ID="abc", JACKNIFE_INPUT_DURATION="90\nEVIL=1", JACKNIFE_INPUT_SEED="1").returncode, 0)

    def test_rejects_other_repos_and_servers(self):
        self.assertNotEqual(
            self._run(
                JACKNIFE_INPUT_RUN_ID="abc",
                JACKNIFE_INPUT_DURATION="90",
                JACKNIFE_INPUT_SEED="1",
                JACKNIFE_GITHUB_REPOSITORY="evil/other",
            ).returncode,
            0,
        )
        self.assertNotEqual(
            self._run(
                JACKNIFE_INPUT_RUN_ID="abc",
                JACKNIFE_INPUT_DURATION="90",
                JACKNIFE_INPUT_SEED="1",
                JACKNIFE_GITHUB_SERVER_URL="https://github.com.evil.test",
            ).returncode,
            0,
        )

    def test_sanitized_helper_matches_allowlist(self):
        old = os.environ.copy()
        try:
            os.environ["JACKNIFE_INPUT_RUN_ID"] = "Run_1"
            os.environ["JACKNIFE_INPUT_DURATION"] = ""
            os.environ["JACKNIFE_INPUT_SEED"] = ""
            values = sanitized()
        finally:
            os.environ.clear()
            os.environ.update(old)
        self.assertEqual(values["JACKNIFE_DURATION"], "90")
        self.assertEqual(values["artifact_name"], "jacknife-Run_1")


class ArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.check_call(["bash", "scripts/build_fuzzer.sh"], cwd=ROOT)
        cls.tmp = tempfile.TemporaryDirectory()
        out = Path(cls.tmp.name) / "good"
        subprocess.check_call(
            [
                sys.executable,
                "scripts/collect_state.py",
                "--inputs",
                "target/corpus/seed_heap.bin",
                "target/corpus/seed_stack.bin",
                "target/corpus/seed_uaf.bin",
                "target/corpus/seed_ubsan.bin",
                "--out-dir",
                str(out),
                "--run-id",
                "unit",
                "--duration",
                "15",
                "--seed",
                "1",
                "--source",
                "local",
                "--commit-sha",
                "",
            ],
            cwd=ROOT,
            env={**os.environ, "PYTHONPATH": str(ROOT)},
        )
        cls.good = out
        cls.state = json.loads((out / "state.json").read_text())
        cls.manifest = json.loads((out / "manifest.json").read_text())

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_real_seeds_are_sanitizer_classified_and_not_confirmed(self):
        labels = {item["crash_type"]: item["classification"] for item in self.state["findings"]}
        self.assertEqual(labels["heap-buffer-overflow"], "Sanitizer-classified (ASan)")
        self.assertEqual(labels["stack-buffer-overflow"], "Sanitizer-classified (ASan)")
        self.assertEqual(labels["heap-use-after-free"], "Sanitizer-classified (ASan)")
        self.assertEqual(labels["signed-integer-overflow"], "Sanitizer-classified (UBSan)")
        self.assertNotIn("Confirmed", labels.values())
        self.assertTrue(all(item["minimized"] and item["reproducible"] for item in self.state["findings"]))
        validate_files(
            {"state.json": (self.good / "state.json").read_bytes(), "manifest.json": (self.good / "manifest.json").read_bytes()},
            check_targets=True,
            repo_root=ROOT,
        )

    def _zip(self, entries: list[tuple[str, bytes, int]]) -> Path:
        path = Path(self.tmp.name) / f"case-{len(list(Path(self.tmp.name).iterdir()))}.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data, mode in entries:
                info = zipfile.ZipInfo(filename=name)
                info.external_attr = (mode & 0xFFFF) << 16
                archive.writestr(info, data)
        return path

    def _good_entries(self) -> list[tuple[str, bytes, int]]:
        return [
            ("state.json", (self.good / "state.json").read_bytes(), 0o100644),
            ("manifest.json", (self.good / "manifest.json").read_bytes(), 0o100644),
        ]

    def test_good_zip_is_accepted(self):
        result = validate_files(read_zip(self._zip(self._good_entries())), check_targets=False, repo_root=ROOT)
        self.assertEqual(len(result["state"]["findings"]), 4)

    def test_zip_slip_symlink_and_absolute_names_are_rejected(self):
        good = self._good_entries()
        with self.assertRaises(ArtifactRejected):
            read_zip(self._zip(good + [("../evil", b"x", 0o100644)]))
        with self.assertRaises(ArtifactRejected):
            read_zip(self._zip([("/etc/passwd", b"x", 0o100644), good[1]]))
        with self.assertRaises(ArtifactRejected):
            read_zip(self._zip([("state.json", b"x", 0o120777), good[1]]))
        with self.assertRaises(ArtifactRejected):
            read_zip(self._zip(good + [("note.txt", b"x", 0o100644)]))

    def test_compression_bomb_is_rejected(self):
        bomb = b"A" * (2 * 1024 * 1024)
        path = self._zip([("state.json", bomb, 0o100644), ("manifest.json", b"{}", 0o100644)])
        with self.assertRaises(ArtifactRejected):
            read_zip(path)

    def test_duplicate_keys_and_confirmed_claim_are_rejected(self):
        raw = (self.good / "state.json").read_text().replace(
            '"classification": "Sanitizer-classified (ASan)"',
            '"classification": "Confirmed"',
            1,
        )
        files = {
            "state.json": raw.encode(),
            "manifest.json": (self.good / "manifest.json").read_bytes(),
        }
        with self.assertRaises(ArtifactRejected):
            validate_files(files, check_targets=False, repo_root=ROOT)
        dup = '{"a": 1, "a": 2}'
        files = {"state.json": dup.encode(), "manifest.json": b"{}"}
        with self.assertRaises(ArtifactRejected):
            validate_files(files, check_targets=False, repo_root=ROOT)

    def test_promotion_flag_inside_zip_is_rejected(self):
        state = json.loads((self.good / "state.json").read_text())
        state["findings"][0]["evidence"]["workflow_corroborated"] = True
        blob = dumps(state).encode()
        manifest = json.loads((self.good / "manifest.json").read_text())
        manifest["file_hashes"]["state.json"] = sha256_bytes(blob)
        files = {"state.json": blob, "manifest.json": dumps(manifest).encode()}
        with self.assertRaises(ArtifactRejected):
            validate_files(files, check_targets=False, repo_root=ROOT)

    def test_hash_mismatch_wrong_repo_and_hostile_text(self):
        state_bytes = (self.good / "state.json").read_bytes()
        manifest = json.loads((self.good / "manifest.json").read_text())
        manifest["repo"] = "evil/other"
        with self.assertRaises(ArtifactRejected):
            validate_files(
                {"state.json": state_bytes, "manifest.json": dumps(manifest).encode()},
                check_targets=False,
                repo_root=ROOT,
            )
        manifest = json.loads((self.good / "manifest.json").read_text())
        manifest["file_hashes"]["state.json"] = "sha256:" + "ab" * 32
        with self.assertRaises(ArtifactRejected):
            validate_files(
                {"state.json": state_bytes, "manifest.json": dumps(manifest).encode()},
                check_targets=False,
                repo_root=ROOT,
            )
        state = json.loads(state_bytes)
        state["findings"][0]["stack_trace"] = "#0 <script>"
        blob = dumps(state).encode()
        manifest = json.loads((self.good / "manifest.json").read_text())
        manifest["file_hashes"]["state.json"] = sha256_bytes(blob)
        with self.assertRaises(ArtifactRejected):
            validate_files(
                {"state.json": blob, "manifest.json": dumps(manifest).encode()},
                check_targets=False,
                repo_root=ROOT,
            )

    def test_json_unicode_bidi_is_hostile_after_decode(self):
        state = json.loads((self.good / "state.json").read_text())
        state["findings"][0]["stack_trace"] = "#0 " + "\u202e"
        self.assertTrue(has_hostile(state["findings"][0]["stack_trace"]))
        blob = dumps(state).encode()
        manifest = json.loads((self.good / "manifest.json").read_text())
        manifest["file_hashes"]["state.json"] = sha256_bytes(blob)
        with self.assertRaises(ArtifactRejected):
            validate_files(
                {"state.json": blob, "manifest.json": dumps(manifest).encode()},
                check_targets=False,
                repo_root=ROOT,
            )

    def test_directory_symlink_is_rejected(self):
        folder = Path(self.tmp.name) / "linked"
        folder.mkdir()
        (folder / "manifest.json").write_text("{}", encoding="utf-8")
        (folder / "state.json").symlink_to("/etc/passwd")
        with self.assertRaises(ArtifactRejected):
            read_dir(folder)

    def test_escape_neutralizes_ansi_html_and_bidi(self):
        raw = "\x1b[31m<script>\u202e\n"
        escaped = escape_untrusted(raw)
        self.assertFalse(has_hostile(escaped))
        self.assertNotIn("<", escaped)
        self.assertNotIn("\x1b", escaped)
        self.assertNotIn("\u202e", escaped)


class TriggerTests(unittest.TestCase):
    def test_host_allowlist(self):
        self.assertTrue(host_allowed("api.github.com"))
        self.assertTrue(host_allowed("objects.githubusercontent.com"))
        self.assertTrue(host_allowed("prod.blob.core.windows.net"))
        self.assertFalse(host_allowed("github.com.evil.test"))
        self.assertFalse(host_allowed("evilgithub.com"))
        self.assertFalse(host_allowed("api.github.com.attacker.test"))
        with self.assertRaises(ApiError):
            default_transport("GET", "https://evil.example/secret", None, {})
        with self.assertRaises(ApiError):
            default_transport("GET", "http://api.github.com/repos", None, {})

    def test_corroboration_rules(self):
        run = {
            "id": 99,
            "event": "workflow_dispatch",
            "path": ".github/workflows/fuzz.yml",
            "name": "fuzz-abc",
            "head_sha": "b" * 40,
            "status": "completed",
            "conclusion": "success",
            "html_url": "https://github.com/MPH04/JacKnife/actions/runs/99",
        }
        self.assertTrue(run_corroborates(run, repo="MPH04/JacKnife", run_id="abc", commit_sha="b" * 40)[0])
        stale = dict(run, path=".github/workflows/evil.yml")
        self.assertFalse(run_corroborates(stale, repo="MPH04/JacKnife", run_id="abc", commit_sha="b" * 40)[0])
        wrong = dict(run, html_url="https://github.com.evil.test/MPH04/JacKnife/actions/runs/99")
        self.assertFalse(run_corroborates(wrong, repo="MPH04/JacKnife", run_id="abc", commit_sha="b" * 40)[0])
        failed = dict(run, conclusion="failure")
        self.assertFalse(run_corroborates(failed, repo="MPH04/JacKnife", run_id="abc", commit_sha="b" * 40)[0])

    def test_cli_refuses_token_argument_and_other_repos(self):
        proc = subprocess.run(
            [sys.executable, "scripts/trigger_and_poll.py", "--token", "secret", "--run-id", "abc", "--out-zip", "x.zip"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("secret", proc.stdout)
        proc = subprocess.run(
            [sys.executable, "scripts/trigger_and_poll.py", "--repo", "evil/other", "--run-id", "abc", "--out-zip", "x.zip"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            env={**os.environ, "JACKNIFE_GITHUB_TOKEN": "super-secret-token"},
        )
        self.assertEqual(proc.returncode, 2)
        self.assertNotIn("super-secret-token", proc.stdout + proc.stderr)

    def test_trigger_redacts_token_and_rejects_bad_redirect_host(self):
        seen = {}

        def transport(method, url, body, headers):
            seen["auth"] = headers.get("Authorization", "")
            if "evil.example" in url:
                raise ApiError(0, "nope")
            if method == "POST":
                return 204, {}, b""
            raise ApiError(500, "leaked super-secret-token in body")

        with self.assertRaises(ApiError) as caught:
            trigger_and_poll(
                run_id="abc",
                duration=90,
                seed=1,
                out_zip=Path(tempfile.mkdtemp()) / "run.zip",
                out_dir=Path(tempfile.mkdtemp()),
                token="super-secret-token",
                transport=transport,
                sleep=lambda _seconds: None,
                now=datetime.now(timezone.utc),
            )
        self.assertNotIn("super-secret-token", str(caught.exception))
        self.assertIn("Bearer super-secret-token", seen["auth"])


class AttestationTests(unittest.TestCase):
    def test_missing_gh_fails_closed(self):
        with tempfile.NamedTemporaryFile() as handle:
            path = Path(handle.name)
            old = os.environ.get("PATH", "")
            try:
                os.environ["PATH"] = "/nonexistent"
                code = verify(path)
            finally:
                os.environ["PATH"] = old
            self.assertEqual(code, 1)

    def test_failing_gh_is_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            bindir = Path(tmp) / "bin"
            bindir.mkdir()
            fake = bindir / "gh"
            fake.write_text("#!/bin/sh\necho nope\nexit 1\n", encoding="utf-8")
            fake.chmod(0o755)
            artifact = Path(tmp) / "state.json"
            artifact.write_text("{}", encoding="utf-8")
            old = os.environ.get("PATH", "")
            try:
                os.environ["PATH"] = str(bindir)
                code = verify(artifact)
            finally:
                os.environ["PATH"] = old
            self.assertEqual(code, 1)

    def test_quiet_success_without_verified_phrase_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            bindir = Path(tmp) / "bin"
            bindir.mkdir()
            fake = bindir / "gh"
            fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            fake.chmod(0o755)
            artifact = Path(tmp) / "state.json"
            artifact.write_text("{}", encoding="utf-8")
            old = os.environ.get("PATH", "")
            try:
                os.environ["PATH"] = str(bindir)
                code = verify(artifact)
            finally:
                os.environ["PATH"] = old
            self.assertEqual(code, 1)


class TargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.check_call(["bash", "scripts/build_fuzzer.sh"], cwd=ROOT)

    def _replay(self, name: str) -> tuple[int, str]:
        proc = subprocess.run(
            ["bash", "scripts/reproduce_crash.sh", f"target/corpus/{name}"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        return proc.returncode, proc.stderr

    def test_valid_seed_does_not_crash(self):
        status, _err = self._replay("seed_valid.bin")
        self.assertEqual(status, 0)

    def test_seeded_bugs_match_real_sanitizer_output(self):
        status, err = self._replay("seed_heap.bin")
        self.assertNotEqual(status, 0)
        self.assertIn("ERROR: AddressSanitizer: heap-buffer-overflow", err)
        status, err = self._replay("seed_stack.bin")
        self.assertIn("ERROR: AddressSanitizer: stack-buffer-overflow", err)
        status, err = self._replay("seed_uaf.bin")
        self.assertIn("ERROR: AddressSanitizer: heap-use-after-free", err)
        status, err = self._replay("seed_ubsan.bin")
        self.assertIn("runtime error: signed integer overflow", err)
        self.assertIn("UndefinedBehaviorSanitizer", err)


class FallbackTests(unittest.TestCase):
    def test_fallback_directory_validates_and_is_not_confirmed(self):
        fallback = ROOT / "fallback"
        if not (fallback / "state.json").is_file():
            self.fail("fallback/state.json is missing")
        proc = subprocess.run(
            [sys.executable, "scripts/validate_artifact.py", "--dir", "fallback", "--check-targets"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        state = json.loads((fallback / "state.json").read_text())
        self.assertEqual(state["source"], "local")
        self.assertIsNone(state["workflow_url"])
        self.assertGreaterEqual(len(state["findings"]), 4)
        for finding in state["findings"]:
            self.assertNotIn(finding["classification"], ("Confirmed", "Attested"))
            self.assertFalse(finding["evidence"]["workflow_corroborated"])


if __name__ == "__main__":
    unittest.main()
