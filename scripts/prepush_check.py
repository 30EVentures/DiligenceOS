#!/usr/bin/env python3
"""Pre-push hygiene: no secrets, no forbidden names, no credential files, only the public author identity.

    python3 scripts/prepush_check.py                        # the working tree (tracked + untracked, not ignored)
    python3 scripts/prepush_check.py --range origin/main..HEAD   # and every commit about to be pushed

Exit 0 when clean, 1 when anything is found. It prints the RULE and the PLACE of each finding and never the
text that matched, so running it cannot itself leak what it finds. The history check is the one that matters
before a push: a name or a token removed from the last commit is still in the one before it.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Written in pieces so this file passes its own scan.
_NAMES = ["analyst" + "os", "deposit" + "x", r"\bcon" + r"cord\b", "kp" + "mg", r"michael\s+" + "gord", r"gord\s+" + "holdings",
          "caleb" + "sol" + "way", r"\bsol" + r"way\b"]
BANNED = re.compile("|".join(_NAMES), re.I)
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@gmail\.com", re.I)
ALLOWED_EMAILS = {"30eventures@gmail.com"}
ALLOWED_AUTHOR_EMAILS = {"30eventures@gmail.com", "233154122+30eventures@users.noreply.github.com"}
ALLOWED_AUTHOR_NAMES = {"30E Ventures"}
# files that exist to state or test the rule itself
NAME_ALLOWLIST = {"CLAUDE.md", "tests/test_manifest.py"}

CREDENTIAL_FILES = [
    (re.compile(r"(^|/)\.env(\.(?!example$|sample$|template$)[^/]*)?$"), ".env file"),
    (re.compile(r"\.env$"), ".env file"),
    (re.compile(r"(^|/)\.flashy(/|$)"), "agent credentials directory"),
    (re.compile(r"\.(key|pem|p12|pfx)$"), "key file"),
    (re.compile(r"-agent-reporter\.ts$"), "generated agent reporter (holds a token reference)"),
    (re.compile(r"(^|/)id_(rsa|ed25519|ecdsa)$"), "ssh key"),
]

_SECRET_NAME = r"[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|ISSUER_?KEY|SESSION)[A-Za-z0-9_]*"
ASSIGN = re.compile(r"(?i)\b" + _SECRET_NAME + r"[\"']?\s*[:=]\s*[\"']?([^\s\"'#,;)}\]\[<>$]+)")
BEARER = re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{20,})")
CLAIM = re.compile(r"/claim/([A-Za-z0-9_-]{16,})")
PEM = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
PROVIDERS = [(re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), "provider token"), (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), "provider key"),
             (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "cloud key id"), (re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"), "chat token")]
PLACEHOLDER = re.compile(r"(?i)agt_test_|redacted|placeholder|example|your[-_]|changeme|xxxx|\.\.\.|<|>|\$\{?|dummy|not-a-real|fake")


def _looks_secret(value: str) -> bool:
    if len(value) < 20 or PLACEHOLDER.search(value) or re.fullmatch(r"0x[0-9a-fA-F]{40}", value):
        return False   # (an EVM contract address is public, even in a field called "token")
    return bool(re.search(r"[A-Za-z]", value) and re.search(r"[0-9]", value)) and bool(re.fullmatch(r"[A-Za-z0-9_\-+/=.:]+", value))


def scan_text(path: str, text: str) -> list[dict]:
    """Findings as {"rule", "path", "line"}; never the matched text."""
    out = []

    def add(rule, line):
        out.append({"rule": rule, "path": path, "line": line})

    for rx, label in CREDENTIAL_FILES:
        if rx.search(path):
            add(f"credential file: {label}", 0)
            break
    allow_names = path in NAME_ALLOWLIST
    for n, line in enumerate(text.splitlines(), 1):
        for m in ASSIGN.finditer(line):
            if _looks_secret(m.group(1)):
                add("secret: assigned token/key value", n)
                break
        if (m := BEARER.search(line)) and not PLACEHOLDER.search(m.group(1)):
            add("secret: bearer credential", n)
        if (m := CLAIM.search(line)) and not PLACEHOLDER.search(m.group(1)):
            add("secret: one-time claim link", n)
        if PEM.search(line):
            add("secret: private key block", n)
        for rx, label in PROVIDERS:
            if rx.search(line):
                add(f"secret: {label}", n)
        if not allow_names:
            if BANNED.search(line):
                add("banned name", n)
            if any(e.lower() not in ALLOWED_EMAILS for e in EMAIL.findall(line)):
                add("banned name: personal email", n)
    return out


def _tracked_and_untracked(root: Path):
    try:
        out = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=root, capture_output=True, check=True).stdout
        return [p for p in out.decode("utf-8", "replace").split("\0") if p]
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        skip = {".git", ".venv", "venv", "__pycache__", "node_modules", ".pytest_cache"}
        return [str(p.relative_to(root)) for p in root.rglob("*") if p.is_file() and not (set(p.relative_to(root).parts) & skip)]


def scan_tree(root) -> list[dict]:
    root, findings = Path(root), []
    for rel in sorted(_tracked_and_untracked(root)):
        p = root / rel
        try:
            if not p.is_file() or p.stat().st_size > 2_000_000:
                continue
            text = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            text = ""
        findings.extend(scan_text(rel, text))
    return findings


def scan_history(root, rev_range: str) -> list[dict]:
    """Every commit in the range: author identity, and every line it ADDED, even if a later commit removed it."""
    bad = [{"rule": "history: range could not be read", "path": "", "line": 0}]
    try:
        meta = subprocess.run(["git", "log", "--format=%H%x00%an%x00%ae%x00%cn%x00%ce", rev_range], cwd=root, capture_output=True, text=True, check=True).stdout
        patch = subprocess.run(["git", "log", "-p", "-U0", "--no-color", "--format=@@@COMMIT %H", rev_range], cwd=root, capture_output=True,
                               text=True, errors="replace", check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return bad
    out = []
    for row in meta.splitlines():
        sha, an, ae, cn, ce = (row.split("\0") + [""] * 5)[:5]
        if an not in ALLOWED_AUTHOR_NAMES or ae.lower() not in ALLOWED_AUTHOR_EMAILS or ce.lower() not in ALLOWED_AUTHOR_EMAILS | {"noreply@github.com"}:
            out.append({"rule": "history: commit author", "path": sha[:7], "line": 0})
    sha, path, added = "", "", {}
    for line in patch.splitlines():
        if line.startswith("@@@COMMIT "):
            sha, path = line.split()[1][:7], ""
        elif line.startswith("+++ b/"):
            path = line[6:]
        elif line.startswith("+") and not line.startswith("+++"):
            added.setdefault((sha, path), []).append(line[1:])
        elif line.startswith("--- ") or line.startswith("diff "):
            continue
    for (sha, path), lines in added.items():
        for f in scan_text(path, "\n".join(lines)):
            out.append({"rule": "history: " + f["rule"], "path": f"{sha}:{path}", "line": f["line"]})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    ap.add_argument("--range", help="a git range of commits about to be pushed, e.g. origin/main..HEAD")
    args = ap.parse_args(argv)
    findings = scan_tree(args.root) + (scan_history(args.root, args.range) if args.range else [])
    for f in findings:
        print(f"{f['rule']} | {f['path']}:{f['line']}")
    print("clean" if not findings else f"{len(findings)} finding(s): fix before pushing")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
