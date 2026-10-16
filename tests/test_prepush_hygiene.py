"""Repo hygiene as failing tests: no token-shaped strings, no banned names, no stray credential files, no foreign
commit authors. The scanner never prints what it matched, only the rule and the place."""

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("prepush_check", ROOT / "scripts" / "prepush_check.py")
pc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pc)

# built in pieces so that this file, which must name them to test for them, passes its own scan
SIBLING = "Analyst" + "OS"
OTHER = ["Deposit" + "X", "Con" + "cord", "KP" + "MG", "Michael " + "Gord", "Gord " + "Holdings"]
PERSONAL = "caleb" + "sol" + "way" + "@" + "gmail" + ".com"
TOKENISH = "".join(["q7Zk3VbN", "9xTr2LmW", "8aYc5HdP", "f1GjS4eU"])   # 32 random-looking characters: shape only, not a real credential


def git(cwd, *args, env=None):
    base = {"GIT_AUTHOR_NAME": "30E Ventures", "GIT_AUTHOR_EMAIL": "30eventures@gmail.com",
            "GIT_COMMITTER_NAME": "30E Ventures", "GIT_COMMITTER_EMAIL": "30eventures@gmail.com", "PATH": os.environ["PATH"], "HOME": str(cwd)}
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True, env={**base, **(env or {})}).stdout


class SecretShapes(unittest.TestCase):
    def hits(self, text, path="notes.md"):
        return [f["rule"] for f in pc.scan_text(path, text)]

    def test_each_of_these_is_flagged(self):
        cases = {
            "env assignment": f"FLASHYOS_AGENT_TOKEN={TOKENISH}\n",
            "env assignment, per-agent name": f"FLASHYOS_AGENT_TOKEN_DILIGENCEOS_AGENT='{TOKENISH}'\n",
            "export": f"export FLASHYOS_AGENT_TOKEN=\"{TOKENISH}\"\n",
            "bearer": f"Authorization: Bearer {TOKENISH}\n",
            "json token field": f'{{"token": "{TOKENISH}"}}\n',
            "python assignment": f'agent_token = "{TOKENISH}"\n',
            "claim link": f"https://app.flashyos.com/claim/{TOKENISH}\n",
            "pem block": "-----BEGIN " + "PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
            "private key as 64 hex": "issuer_key = '" + "ab12" * 16 + "'\n",
            "github token": "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" + "\n",
            "provider key": "sk-" + "ant-api03-" + "A1b2C3d4E5f6G7h8I9j0" + "\n",
            "aws key id": "AKIA" + "ABCDEFGHIJKLMNOP" + "\n",
        }
        for label, text in cases.items():
            with self.subTest(label):
                self.assertNotEqual(self.hits(text), [], label)

    def test_documented_placeholders_and_public_values_are_not(self):
        fine = [
            "FLASHYOS_AGENT_TOKEN=\n", "export FLASHYOS_AGENT_TOKEN='...'\n", "export FLASHYOS_AGENT_TOKEN='<paste here>'\n",
            "FLASHYOS_AGENT_TOKEN=$FLASHYOS_AGENT_TOKEN\n", "FLASHYOS_AGENT_TOKEN=agt_test_0123456789abcdef\n",
            "token = os.environ['FLASHYOS_AGENT_TOKEN']\n", "TOKEN = \"agt_test_0123456789abcdef\"\n",
            "issuer ed25519:" + "ab12" * 16 + "\n",                     # a public key
            "head_hash: sha256:" + "ab12" * 16 + "\n", "\"token\": \"[redacted]\"\n",
            "the token is shown once; do not paste it\n",
        ]
        for text in fine:
            with self.subTest(text=text):
                self.assertEqual(self.hits(text), [], text)

    def test_a_public_contract_address_in_a_field_called_token_is_not_a_secret(self):
        self.assertEqual(self.hits('"token": "0x' + "ab" * 20 + '"\n'), [])

    def test_a_finding_never_contains_the_matched_text(self):
        for finding in pc.scan_text("a.env", f"FLASHYOS_AGENT_TOKEN={TOKENISH}\nauthorization: bearer {TOKENISH}\n"):
            self.assertNotIn(TOKENISH, repr(finding))
            self.assertEqual(set(finding), {"rule", "path", "line"})

    def test_credential_files_are_flagged_by_name(self):
        for name in (".env", ".env.local", "prod.env", ".flashy/credentials", "issuer.key", "agent.key", "server.pem", "diligenceos-agent-agent-reporter.ts", "id_ed25519"):
            self.assertNotEqual([f["rule"] for f in pc.scan_text(name, "x")], [], name)
        for name in ("README.md", "diligenceos/keys.py", "tests/test_signing.py", "docs/keyboard.md", ".env.example"):
            self.assertEqual([f["rule"] for f in pc.scan_text(name, "x")], [], name)


class BannedNames(unittest.TestCase):
    def test_names_the_rule_forbids_are_flagged_in_any_case(self):
        for name in [SIBLING, SIBLING.lower(), SIBLING.upper(), *OTHER, *(o.lower() for o in OTHER), PERSONAL, "caleb" + "sol" + "way"]:
            self.assertNotEqual([f["rule"] for f in pc.scan_text("docs/x.md", f"see {name} for more")], [], name)

    def test_the_public_identity_is_allowed(self):
        for ok in ("30E Ventures", "30eventures@gmail.com", "233154122+30EVentures@users.noreply.github.com"):
            self.assertEqual(pc.scan_text("docs/x.md", f"contact {ok}"), [], ok)

    def test_other_gmail_addresses_are_flagged(self):
        self.assertNotEqual(pc.scan_text("docs/x.md", "mail someone.else" + "@" + "gmail.com"), [])

    def test_a_json_fixture_is_scanned_like_any_other_file(self):
        self.assertNotEqual(pc.scan_text("tests/flashy/fixtures/vectors.json", '{"seller": "' + SIBLING.lower() + '"}'), [])

    def test_the_findings_say_which_rule_and_where_but_not_the_name(self):
        f = pc.scan_text("docs/x.md", f"a\nb {SIBLING}\n")[0]
        self.assertEqual((f["path"], f["line"]), ("docs/x.md", 2))
        self.assertNotIn(SIBLING.lower(), repr(f).lower())


class ThisRepository(unittest.TestCase):
    def test_no_tracked_file_names_a_banned_person_or_product_or_holds_a_secret(self):
        findings = pc.scan_tree(ROOT)
        self.assertEqual(findings, [], "see the rule/path/line above; fix the file (the scanner never prints the match)")

    def test_gitignore_keeps_credential_files_out(self):
        text = (ROOT / ".gitignore").read_text()
        for needle in (".env", "*.key", "*.pem", ".flashy/"):
            self.assertIn(needle, text, needle)


class Commits(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        git(self.dir, "init", "-q", "-b", "main")
        (self.dir / "README.md").write_text("hello\n")
        git(self.dir, "add", "-A")
        git(self.dir, "commit", "-q", "-m", "base")
        self.base = git(self.dir, "rev-parse", "HEAD").strip()

    def tearDown(self):
        self._tmp.cleanup()

    def commit(self, name, content, author=("30E Ventures", "30eventures@gmail.com")):
        (self.dir / name).write_text(content)
        git(self.dir, "add", "-A")
        git(self.dir, "commit", "-q", "-m", "change", env={"GIT_AUTHOR_NAME": author[0], "GIT_AUTHOR_EMAIL": author[1]})

    def test_a_clean_range_passes(self):
        self.commit("a.txt", "fine\n")
        self.assertEqual(pc.scan_history(self.dir, f"{self.base}..HEAD"), [])

    def test_a_banned_name_in_history_is_found_even_after_it_was_removed(self):
        self.commit("a.md", f"powered by {SIBLING}\n")
        self.commit("a.md", "fine now\n")
        self.assertEqual(pc.scan_tree(self.dir), [])                       # the final tree is clean ...
        found = pc.scan_history(self.dir, f"{self.base}..HEAD")           # ... the history is not
        self.assertTrue(found and all(f["rule"].startswith(("banned", "history")) for f in found), found)

    def test_a_secret_in_history_is_found_even_after_it_was_removed(self):
        self.commit(".env", f"FLASHYOS_AGENT_TOKEN={TOKENISH}\n")
        git(self.dir, "rm", "-q", ".env")
        git(self.dir, "commit", "-q", "-m", "oops, remove")
        found = pc.scan_history(self.dir, f"{self.base}..HEAD")
        self.assertNotEqual(found, [])
        self.assertNotIn(TOKENISH, repr(found))

    def test_a_foreign_author_is_found(self):
        self.commit("a.txt", "fine\n", author=("Someone Else", "someone@example.com"))
        self.assertIn("history: commit author", [f["rule"] for f in pc.scan_history(self.dir, f"{self.base}..HEAD")])

    def test_the_right_email_under_another_name_is_found(self):
        self.commit("a.txt", "fine\n", author=("Someone Else", "30eventures@gmail.com"))
        self.assertIn("history: commit author", [f["rule"] for f in pc.scan_history(self.dir, f"{self.base}..HEAD")])

    def test_the_noreply_form_of_the_public_identity_is_accepted(self):
        self.commit("a.txt", "fine\n", author=("30E Ventures", "233154122+30EVentures@users.noreply.github.com"))
        self.assertEqual(pc.scan_history(self.dir, f"{self.base}..HEAD"), [])

    def test_an_unknown_range_is_a_failure_not_a_pass(self):
        found = pc.scan_history(self.dir, "no-such-ref..HEAD")
        self.assertEqual([f["rule"] for f in found], ["history: range could not be read"])

    def test_the_command_exits_nonzero_on_a_finding_and_prints_no_secret(self):
        self.commit("a.md", f"{SIBLING}\nFLASHYOS_AGENT_TOKEN={TOKENISH}\n")
        done = subprocess.run(["python3", str(ROOT / "scripts" / "prepush_check.py"), "--root", str(self.dir), "--range", f"{self.base}..HEAD"],
                              capture_output=True, text=True)
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn(TOKENISH, done.stdout + done.stderr)
        self.assertNotIn(SIBLING.lower(), (done.stdout + done.stderr).lower())
        ok = subprocess.run(["python3", str(ROOT / "scripts" / "prepush_check.py"), "--root", str(ROOT)], capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)


if __name__ == "__main__":
    unittest.main()
