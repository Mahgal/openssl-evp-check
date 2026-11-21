#!/usr/bin/env python3
"""Tests for openssl_evp_check.py — stdlib unittest only, no network.

Run: python3 tests/run_tests.py  (exit 0 on success)
"""
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import openssl_evp_check as oec


def run_cli(*argv, **kw):
    return subprocess.run(
        [sys.executable, os.path.join(ROOT, "openssl_evp_check.py"), *argv],
        capture_output=True, text=True, timeout=30, cwd=ROOT, **kw)


class TestVersionParsing(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(oec.parse_version("4.1.0"), (4, 1, 0))
        self.assertEqual(oec.parse_version("3.5.9"), (3, 5, 9))

    def test_banner_form(self):
        self.assertEqual(
            oec.parse_version("OpenSSL 4.1.0 12 Aug 2026"), (4, 1, 0))
        self.assertEqual(
            oec.parse_version("OpenSSL 3.0.13 30 Jan 2024"), (3, 0, 13))

    def test_distro_suffix_ubuntu(self):
        self.assertEqual(oec.parse_version("4.0.3-1ubuntu1"), (4, 0, 3))

    def test_distro_suffix_fedora(self):
        self.assertEqual(oec.parse_version("4.0.3-1.fc45"), (4, 0, 3))

    def test_distro_suffix_arch(self):
        self.assertEqual(oec.parse_version("4.1.0-1"), (4, 1, 0))

    def test_letter_suffix(self):
        self.assertEqual(oec.parse_version("1.1.1w"), (1, 1, 1))
        self.assertEqual(oec.parse_version("3.0.16"), (3, 0, 16))

    def test_malformed_returns_none_not_crash(self):
        for bad in ("", "garbage", "OpenSSL", "4.1", "x.y.z", None, 123):
            self.assertIsNone(oec.parse_version(bad), msg=repr(bad))

    def test_two_digit_patch(self):
        self.assertEqual(oec.parse_version("3.0.16"), (3, 0, 16))
        self.assertEqual(oec.parse_version("4.0.10"), (4, 0, 10))


class TestVerdictBoundaries(unittest.TestCase):
    def test_400_vulnerable(self):
        self.assertEqual(oec.judge((4, 0, 0)), oec.VULNERABLE)

    def test_403_vulnerable(self):
        self.assertEqual(oec.judge((4, 0, 3)), oec.VULNERABLE)

    def test_404_patched(self):
        self.assertEqual(oec.judge((4, 0, 4)), oec.PATCHED)

    def test_4010_patched(self):
        self.assertEqual(oec.judge((4, 0, 10)), oec.PATCHED)

    def test_410_vulnerable(self):
        self.assertEqual(oec.judge((4, 1, 0)), oec.VULNERABLE)

    def test_411_patched(self):
        self.assertEqual(oec.judge((4, 1, 1)), oec.PATCHED)

    def test_420_patched_future_branch(self):
        self.assertEqual(oec.judge((4, 2, 0)), oec.PATCHED)

    def test_359_not_affected(self):
        self.assertEqual(oec.judge((3, 5, 9)), oec.NOT_AFFECTED)

    def test_3016_not_affected(self):
        self.assertEqual(oec.judge((3, 0, 16)), oec.NOT_AFFECTED)

    def test_111_not_affected(self):
        self.assertEqual(oec.judge((1, 1, 1)), oec.NOT_AFFECTED)

    def test_none_unknown(self):
        self.assertEqual(oec.judge(None), oec.UNKNOWN)

    def test_judge_version_string_end_to_end(self):
        _, v = oec.judge_version_string("4.0.3-1ubuntu1")
        self.assertEqual(v, oec.VULNERABLE)
        _, v = oec.judge_version_string("OpenSSL 4.1.0 12 Aug 2026")
        self.assertEqual(v, oec.VULNERABLE)
        _, v = oec.judge_version_string("garbage")
        self.assertEqual(v, oec.UNKNOWN)


class TestExitCodes(unittest.TestCase):
    def test_vulnerable_is_1(self):
        results = [{"verdict": oec.VULNERABLE}, {"verdict": oec.NOT_AFFECTED}]
        self.assertEqual(oec.exit_code_for(results), 1)

    def test_clean_is_0(self):
        results = [{"verdict": oec.NOT_AFFECTED}, {"verdict": oec.PATCHED}]
        self.assertEqual(oec.exit_code_for(results), 0)

    def test_all_unknown_is_3(self):
        results = [{"verdict": oec.UNKNOWN}, {"verdict": oec.UNKNOWN}]
        self.assertEqual(oec.exit_code_for(results), 3)

    def test_empty_is_3(self):
        self.assertEqual(oec.exit_code_for([]), 3)

    def test_mixed_unknown_and_clean_is_0(self):
        results = [{"verdict": oec.UNKNOWN}, {"verdict": oec.NOT_AFFECTED}]
        self.assertEqual(oec.exit_code_for(results), 0)

    def test_fail_on_never_suppresses_1(self):
        results = [{"verdict": oec.VULNERABLE}]
        self.assertEqual(oec.exit_code_for(results, fail_on="never"), 0)


class TestExplain(unittest.TestCase):
    def test_vulnerable_mentions_no_fixed_release(self):
        text = oec.explain((4, 1, 0), oec.VULNERABLE)
        self.assertIn("4.1.1", text)
        self.assertIn("not yet released", text)

    def test_unknown_explains(self):
        self.assertIn("could not parse", oec.explain(None, oec.UNKNOWN))

    def test_not_affected_names_scope(self):
        text = oec.explain((3, 5, 9), oec.NOT_AFFECTED)
        self.assertIn("not affected", text)


class TestCLI(unittest.TestCase):
    def test_demo_exit_1_and_all_verdicts(self):
        proc = run_cli("--demo")
        self.assertEqual(proc.returncode, 1)
        for verdict in (oec.VULNERABLE, oec.PATCHED, oec.NOT_AFFECTED):
            self.assertIn(verdict, proc.stdout)

    def test_demo_deterministic(self):
        a = run_cli("--demo")
        b = run_cli("--demo")
        self.assertEqual(a.stdout, b.stdout)
        self.assertEqual(a.returncode, b.returncode)

    def test_demo_says_no_fixed_release(self):
        proc = run_cli("--demo")
        self.assertIn("No fixed release exists yet", proc.stdout)
        self.assertIn("2026-12-01", proc.stdout)

    def test_version_string_vulnerable_exit_1(self):
        proc = run_cli("--version-string", "4.0.3-1ubuntu1")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("VULNERABLE", proc.stdout)

    def test_version_string_patched_exit_0(self):
        proc = run_cli("--version-string", "4.0.4")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("PATCHED", proc.stdout)

    def test_version_string_not_affected_exit_0(self):
        proc = run_cli("--version-string", "3.5.9")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("NOT_AFFECTED", proc.stdout)

    def test_version_string_unknown_exit_3(self):
        proc = run_cli("--version-string", "garbage")
        self.assertEqual(proc.returncode, 3)
        self.assertIn("UNKNOWN", proc.stdout)

    def test_fail_on_never_exit_0(self):
        proc = run_cli("--version-string", "4.1.0", "--fail-on", "never")
        self.assertEqual(proc.returncode, 0)

    def test_bad_flag_exit_2(self):
        proc = run_cli("--no-such-flag")
        self.assertEqual(proc.returncode, 2)

    def test_json_structure(self):
        proc = run_cli("--demo", "--json")
        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["cve"], "CVE-2026-121481")
        self.assertFalse(payload["fixed_release_available"])
        self.assertEqual(payload["fixed_release_scheduled"], "2026-12-01")
        self.assertEqual(payload["vulnerable_count"], 2)
        self.assertEqual(payload["exit_code"], 1)
        self.assertEqual(len(payload["results"]), 5)
        for row in payload["results"]:
            self.assertIn("source", row)
            self.assertIn("raw", row)
            self.assertIn("version", row)
            self.assertIn("verdict", row)
            self.assertIn(row["verdict"],
                          (oec.VULNERABLE, oec.PATCHED,
                           oec.NOT_AFFECTED, oec.UNKNOWN))

    def test_json_clean_exit_0(self):
        proc = run_cli("--version-string", "3.0.16", "--json")
        self.assertEqual(proc.returncode, 0)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["vulnerable_count"], 0)
        self.assertEqual(payload["exit_code"], 0)

    def test_live_run_finds_real_sources(self):
        # This box has a real openssl binary and Python ssl; both 3.x.
        proc = run_cli()
        self.assertEqual(proc.returncode, 0)
        self.assertIn("openssl binary", proc.stdout)
        self.assertIn("Python ssl", proc.stdout)
        self.assertIn("NOT_AFFECTED", proc.stdout)


class TestEmptyEnvironment(unittest.TestCase):
    def test_no_detectors_means_exit_3(self):
        # Pure-function level: nothing detected at all.
        self.assertEqual(oec.exit_code_for([]), 3)

    def test_missing_binaries_yield_none_not_crash(self):
        # Detectors must degrade to None, never raise, when tools are absent.
        import unittest.mock as mock
        with mock.patch.object(oec.shutil, "which", return_value=None):
            self.assertIsNone(oec.detect_openssl_binary())
            self.assertIsNone(oec.detect_distro_package())
            self.assertIsNone(oec.detect_node_bundled())

    def test_detector_exceptions_become_unknown(self):
        import unittest.mock as mock
        with mock.patch.object(oec, "detect_openssl_binary",
                               side_effect=RuntimeError("boom")):
            results = oec.collect_results()
            row = [r for r in results if r["source"] == "openssl binary"][0]
            self.assertEqual(row["verdict"], oec.UNKNOWN)


if __name__ == "__main__":
    unittest.main(verbosity=2)
