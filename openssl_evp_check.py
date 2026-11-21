#!/usr/bin/env python3
"""openssl-evp-check: is this box exposed to CVE-2026-121481?

CVE-2026-121481 (published 2026-11-18) is an integer overflow in
OpenSSL's EVP_EncodeBlock(), the one-shot base64 encoder. An input
length near INT_MAX (about 1.6 GB in a single call) overflows the
encoded-output-size calculation, so the encoder writes past the
caller-supplied buffer: a heap buffer overflow. The fix is
openssl/openssl PR #33652.

Affected: OpenSSL 4.0.0-4.0.3 and 4.1.0.
Fixed in:  4.0.4 and 4.1.1, scheduled for release 2026-12-01.
           No fixed release exists yet.
Not affected: OpenSSL 3.x and 1.1.1, per the CVE record.

Severity is disputed, and this tool says so plainly: NVD/CISA
enrichment scores it CVSS 3.1 9.8 Critical, while OpenSSL's own team
rates it Low. This checker reports which versions you have and lets
you decide; it does not pick a side.

Stdlib only, no network, no exploit code. It only reads version
strings from sources already on the box.

Exit codes:
    0  no VULNERABLE source found (or --fail-on never)
    1  at least one VULNERABLE source found
    2  usage error (argparse)
    3  every source UNKNOWN (nothing could be detected)
"""

import argparse
import json
import re
import shutil
import ssl
import subprocess
import sys

CVE_ID = "CVE-2026-121481"
FIX_DATE = "2026-12-01"
FIX_PR = "openssl/openssl#33652"

VULNERABLE = "VULNERABLE"
PATCHED = "PATCHED"
NOT_AFFECTED = "NOT_AFFECTED"
UNKNOWN = "UNKNOWN"

# (major, minor) branches affected, with the first fixed patch release.
# 4.0.x is vulnerable up to 4.0.3, fixed in 4.0.4.
# 4.1.x is vulnerable at 4.1.0, fixed in 4.1.1.
# Later 4.x branches ship with the fix already in.
AFFECTED_BRANCHES = {(4, 0): 4, (4, 1): 1}

_VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def parse_version(text):
    """Parse an OpenSSL version string into (major, minor, patch).

    Handles distro suffixes ("4.0.3-1ubuntu1", "4.0.3-1.fc45",
    "4.1.0-1"), letter suffixes ("1.1.1w", "3.0.16"), and the
    "OpenSSL 4.1.0 12 Aug 2026" banner form. Returns None when no
    x.y.z triple can be found.
    """
    if not text or not isinstance(text, str):
        return None
    match = _VERSION_RE.search(text)
    if not match:
        return None
    try:
        return tuple(int(g) for g in match.groups())
    except ValueError:
        return None


def version_str(version):
    return ".".join(str(n) for n in version)


def judge(version):
    """Return the verdict for a parsed (major, minor, patch) tuple.

    None (unparsable) maps to UNKNOWN, never to a crash.
    """
    if version is None:
        return UNKNOWN
    major, minor, patch = version
    if major != 4:
        # OpenSSL 3.x, 1.1.1 and older are not affected per the CVE record.
        return NOT_AFFECTED
    first_fixed = AFFECTED_BRANCHES.get((major, minor))
    if first_fixed is None:
        # A 4.x branch past 4.1 (e.g. 4.2.0) ships with the fix in.
        return PATCHED
    return VULNERABLE if patch < first_fixed else PATCHED


def judge_version_string(text):
    """Judge one raw version string; returns (parsed_tuple_or_None, verdict)."""
    parsed = parse_version(text)
    return parsed, judge(parsed)


def explain(version, verdict):
    """One-line reason for a verdict, for human-readable output."""
    if verdict == UNKNOWN:
        return "could not parse a version number from this source"
    major, minor, patch = version
    if verdict == VULNERABLE:
        fixed = AFFECTED_BRANCHES[(major, minor)]
        return (
            f"{CVE_ID}: OpenSSL {version_str(version)} is in the affected "
            f"range; fixed in {major}.{minor}.{fixed} "
            f"(scheduled {FIX_DATE}, not yet released)"
        )
    if verdict == PATCHED:
        return f"OpenSSL {version_str(version)} includes the fix for {CVE_ID}"
    return (
        f"OpenSSL {version_str(version)} is not affected per the CVE record "
        f"(3.x and 1.1.1 are out of scope)"
    )


def _run(cmd, timeout=10):
    """Run a command, return stripped stdout or None on any failure."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    out = (proc.stdout or "").strip()
    return out or None


def detect_openssl_binary():
    if not shutil.which("openssl"):
        return None
    return _run(["openssl", "version"])


def detect_distro_package():
    """Distro package version, e.g. 4.0.3-1ubuntu1 (Ubuntu) or 4.1.0-1 (Arch)."""
    if shutil.which("dpkg-query"):
        out = _run(["dpkg-query", "-W", "-f=${Version}", "openssl"])
        if out:
            return out
    if shutil.which("rpm"):
        out = _run(["rpm", "-q", "--queryformat", "%{VERSION}-%{RELEASE}", "openssl"])
        if out:
            return out
    if shutil.which("pacman"):
        out = _run(["pacman", "-Q", "openssl"])
        if out:
            # "openssl 4.1.0-1" -> take the version field
            parts = out.split()
            if len(parts) >= 2:
                return parts[1]
    if shutil.which("brew"):
        for formula in ("openssl@4", "openssl"):
            out = _run(["brew", "list", "--versions", formula])
            if out:
                parts = out.split()
                if len(parts) >= 2:
                    return parts[1]
    return None


def detect_node_bundled():
    if not shutil.which("node"):
        return None
    return _run(["node", "-p", "process.versions.openssl"])


def detect_python_ssl():
    try:
        return ssl.OPENSSL_VERSION
    except Exception:
        return None


DETECTORS = [
    ("openssl binary", "detect_openssl_binary"),
    ("distro package", "detect_distro_package"),
    ("Node.js bundled", "detect_node_bundled"),
    ("Python ssl", "detect_python_ssl"),
]

# Deterministic demo fixtures: every verdict, labelled as fixtures.
# The 4.0.4 row is a stand-in for the not-yet-released fixed build,
# included only to show what PATCHED looks like.
DEMO_FIXTURES = [
    ("openssl binary (fixture)", "OpenSSL 4.1.0 12 Aug 2026"),
    ("distro package (fixture)", "4.0.3-1ubuntu1"),
    ("Node.js bundled (fixture)", "3.5.9"),
    ("Python ssl (fixture)", "OpenSSL 3.0.16 30 Jan 2024"),
    ("future fixed build (fixture)", "OpenSSL 4.0.4 1 Dec 2026"),
]


def collect_results(demo=False):
    """Return a list of result dicts: source, raw, version, verdict."""
    results = []
    if demo:
        for source, raw in DEMO_FIXTURES:
            parsed, verdict = judge_version_string(raw)
            results.append({
                "source": source,
                "raw": raw,
                "version": version_str(parsed) if parsed else None,
                "verdict": verdict,
            })
        return results
    for source, detector_name in DETECTORS:
        detector = globals()[detector_name]
        try:
            raw = detector()
        except Exception:
            raw = None
        parsed, verdict = judge_version_string(raw)
        results.append({
            "source": source,
            "raw": raw,
            "version": version_str(parsed) if parsed else None,
            "verdict": verdict,
        })
    return results


def exit_code_for(results, fail_on="vulnerable"):
    """Map a result list to a process exit code."""
    if not results:
        return 3
    verdicts = [r["verdict"] for r in results]
    if all(v == UNKNOWN for v in verdicts):
        return 3
    if fail_on == "vulnerable" and VULNERABLE in verdicts:
        return 1
    return 0


def format_text(results):
    lines = [f"{CVE_ID} — OpenSSL EVP_EncodeBlock() integer overflow"]
    for r in results:
        shown = r["raw"] if r["raw"] else "(not detected)"
        lines.append(f"{r['source']}: {shown}")
        lines.append(f"  Verdict: {r['verdict']}")
        parsed = parse_version(r["raw"]) if r["raw"] else None
        lines.append(f"  {explain(parsed, r['verdict'])}")
    vuln = [r for r in results if r["verdict"] == VULNERABLE]
    if vuln:
        lines.append("")
        lines.append(
            f"Result: {len(vuln)} source(s) VULNERABLE. "
            f"No fixed release exists yet — 4.0.4 / 4.1.1 are "
            f"scheduled {FIX_DATE} (fix: {FIX_PR})."
        )
        lines.append(
            "Mitigation until then: cap EVP_EncodeBlock input in your own "
            "code (e.g. 64 MiB per call) and upgrade to 4.0.4 / 4.1.1 "
            "when released."
        )
    elif all(r["verdict"] == UNKNOWN for r in results):
        lines.append("")
        if any(r["raw"] for r in results):
            lines.append("Result: version string(s) present but could not be parsed.")
        else:
            lines.append("Result: no OpenSSL source could be detected on this box.")
    else:
        lines.append("")
        lines.append("Result: clean — no VULNERABLE OpenSSL found.")
    return "\n".join(lines) + "\n"


def format_json(results, fail_on="vulnerable"):
    payload = {
        "cve": CVE_ID,
        "fix_pr": FIX_PR,
        "fixed_release_scheduled": FIX_DATE,
        "fixed_release_available": False,
        "results": results,
        "vulnerable_count": sum(1 for r in results if r["verdict"] == VULNERABLE),
        "exit_code": exit_code_for(results, fail_on),
    }
    return json.dumps(payload, indent=2) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=f"Check this box for {CVE_ID} (OpenSSL EVP_EncodeBlock overflow).")
    parser.add_argument("--demo", action="store_true",
                        help="run against built-in labelled fixtures (deterministic)")
    parser.add_argument("--version-string", metavar="X",
                        help="judge a single version string instead of scanning")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON")
    parser.add_argument("--fail-on", choices=["vulnerable", "never"],
                        default="vulnerable",
                        help="exit 1 when a vulnerable version is found (default: vulnerable)")
    args = parser.parse_args(argv)

    if args.version_string is not None:
        parsed, verdict = judge_version_string(args.version_string)
        results = [{
            "source": "version string",
            "raw": args.version_string,
            "version": version_str(parsed) if parsed else None,
            "verdict": verdict,
        }]
    else:
        results = collect_results(demo=args.demo)

    code = exit_code_for(results, args.fail_on)
    if args.json:
        sys.stdout.write(format_json(results, args.fail_on))
    else:
        sys.stdout.write(format_text(results))
    return code


if __name__ == "__main__":
    sys.exit(main())
