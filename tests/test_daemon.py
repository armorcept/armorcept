"""Unit tests for the ArmorCept Python engine (python/daemon.py).

Run with: python3 -I -m unittest discover -s tests -p 'test_*.py'

Fake credentials are assembled at test time from a prefix plus filler so that
no complete token-shaped string appears in the repository.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))

import daemon  # noqa: E402


def fake(prefix: str, n: int, alphabet: str = "Ab3") -> str:
    return prefix + (alphabet * (n // len(alphabet) + 1))[:n]


def categories(engine: daemon.WarmPromptArmorEngine, text: str) -> set[str]:
    return {c for c, _risk, _conf, _rx in engine._scan_local_dlp(text)}


class BuiltinPatternTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = daemon.WarmPromptArmorEngine()

    def assertHit(self, text: str, category: str) -> None:
        self.assertIn(category, categories(self.engine, text), msg=f"expected {category}")

    def assertMiss(self, text: str, category: str) -> None:
        self.assertNotIn(category, categories(self.engine, text), msg=f"unexpected {category}")

    def test_anthropic_keys(self) -> None:
        for kind in ("oat01", "api03", "admin01"):
            token = fake(f"sk-ant-{kind}-", 40, "aB3_-x")
            self.assertHit(f"export CLAUDE_CODE_OAUTH_TOKEN={token}", "SECRET_LEAK_ANTHROPIC_KEY")
        # Near misses: too short, and the documented placeholder form
        self.assertMiss(fake("sk-ant-oat01-", 10), "SECRET_LEAK_ANTHROPIC_KEY")
        self.assertMiss("sk-ant-oat01-...", "SECRET_LEAK_ANTHROPIC_KEY")
        self.assertMiss("task-ant-oat01-" + "a" * 40, "SECRET_LEAK_ANTHROPIC_KEY")

    def test_token_ending_in_dash_or_underscore(self) -> None:
        self.assertHit(fake("sk-ant-oat01-", 40) + "-_", "SECRET_LEAK_ANTHROPIC_KEY")
        self.assertHit(fake("sk-proj-", 30) + "_", "SECRET_LEAK_API_KEY")

    def test_generic_sk_keys_still_match(self) -> None:
        self.assertHit(fake("sk-", 40), "SECRET_LEAK_API_KEY")
        self.assertHit(fake("sk-proj-", 30, "aB-_"), "SECRET_LEAK_API_KEY")
        self.assertMiss(fake("sk-", 20), "SECRET_LEAK_API_KEY")

    def test_github_tokens(self) -> None:
        for prefix in ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"):
            self.assertHit(fake(prefix, 36), "SECRET_LEAK_GITHUB_TOKEN")
        self.assertHit(fake("github_pat_", 30, "aB3_"), "SECRET_LEAK_GITHUB_TOKEN")
        self.assertMiss(fake("ghx_", 36), "SECRET_LEAK_GITHUB_TOKEN")
        self.assertMiss(fake("gho_", 20), "SECRET_LEAK_GITHUB_TOKEN")

    def test_slack_tokens(self) -> None:
        for kind in "abprs":
            token = f"xox{kind}-" + "1234567890" + "-" + "0987654321" + "-" + fake("", 24)
            self.assertHit(token, "SECRET_LEAK_SLACK_TOKEN")
        self.assertMiss("xoxz-1234567890-0987654321-abcdabcd", "SECRET_LEAK_SLACK_TOKEN")
        self.assertMiss("xoxb-", "SECRET_LEAK_SLACK_TOKEN")
        self.assertMiss("xoxb-1234567890", "SECRET_LEAK_SLACK_TOKEN")

    def test_stripe_live_keys(self) -> None:
        self.assertHit(fake("sk_" + "live_", 30), "SECRET_LEAK_STRIPE_KEY")
        self.assertHit(fake("rk_" + "live_", 30), "SECRET_LEAK_STRIPE_KEY")
        self.assertMiss(fake("sk_" + "test_", 30), "SECRET_LEAK_STRIPE_KEY")
        self.assertMiss(fake("pk_" + "live_", 30), "SECRET_LEAK_STRIPE_KEY")

    def test_npm_tokens(self) -> None:
        self.assertHit(fake("npm_", 36), "SECRET_LEAK_NPM_TOKEN")
        self.assertMiss(fake("npm_", 20), "SECRET_LEAK_NPM_TOKEN")
        self.assertMiss("npm_config_registry", "SECRET_LEAK_NPM_TOKEN")

    def test_private_keys(self) -> None:
        dashes = "-" * 5
        for label in ("", "RSA ", "EC ", "OPENSSH ", "ENCRYPTED "):
            pem = f"{dashes}BEGIN {label}PRIVATE KEY{dashes}\nMIIE...\n"
            self.assertHit(pem, "SECRET_LEAK_PRIVATE_KEY")
        self.assertMiss(f"{dashes}BEGIN PUBLIC KEY{dashes}", "SECRET_LEAK_PRIVATE_KEY")
        self.assertMiss(f"{dashes}BEGIN CERTIFICATE{dashes}", "SECRET_LEAK_PRIVATE_KEY")

    def test_service_account_json_regression(self) -> None:
        dashes = "-" * 5
        key = f"{dashes}BEGIN PRIVATE KEY{dashes}\nMIIEvQIBADANBg\n{dashes}END PRIVATE KEY{dashes}\n"
        sa = json.dumps({"type": "service_account", "private_key_id": "abc", "private_key": key})
        self.assertIn("\\n", sa)  # newlines are escaped in the serialized JSON
        self.assertHit(sa, "SECRET_LEAK_PRIVATE_KEY")
        # Tool arguments are serialized again, which double-escapes the newlines
        self.assertHit(json.dumps({"content": sa}), "SECRET_LEAK_PRIVATE_KEY")

    def test_existing_patterns_unchanged(self) -> None:
        self.assertHit(fake("AKIA", 16, "ABC7"), "SECRET_LEAK_AWS_ACCESS_KEY")
        self.assertHit(fake("AIza", 35, "aB_-"), "SECRET_LEAK_GCP_API_KEY")
        self.assertHit("ssn 123-45-6789", "DLP_US_SSN")
        self.assertMiss("ssn 000-45-6789", "DLP_US_SSN")

    def test_clean_text(self) -> None:
        self.assertEqual(categories(self.engine, "npm install && git push origin main"), set())


def load_shared_cases() -> list[dict]:
    """Reads tests/fixtures/dlpCases.ts, whose exported value is plain JSON."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "dlpCases.ts")
    with open(path, encoding="utf-8") as fh:
        source = fh.read()
    body = source.split("export const DLP_CASES = ", 1)[1].rsplit(";", 1)[0]
    return json.loads(body)


def build_case(case: dict) -> str:
    return case["prefix"] + fake("", case["n"], case["alphabet"]) + case.get("suffix", "")


class SharedFixtureTests(unittest.TestCase):
    """The same fixtures run against hooks/dlp.ts in tests/register.test.ts."""

    def test_shared_dlp_cases(self) -> None:
        engine = daemon.WarmPromptArmorEngine()
        cases = load_shared_cases()
        self.assertGreater(len(cases), 20)
        for case in cases:
            text = build_case(case)
            with self.subTest(prefix=case["prefix"], hit=case["hit"]):
                found = case["category"] in categories(engine, text)
                self.assertEqual(found, case["hit"])

    def test_every_builtin_category_has_a_shared_case(self) -> None:
        covered = {c["category"] for c in load_shared_cases() if c["hit"]}
        self.assertEqual(covered, {p.category for p in daemon.BUILTIN_DLP_PATTERNS})


class SpanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.engine = daemon.WarmPromptArmorEngine()

    @staticmethod
    def utf16_slice(text: str, start: int, end: int) -> str:
        return text.encode("utf-16-le")[start * 2 : end * 2].decode("utf-16-le")

    def test_spans_cover_every_match_in_utf16_offsets(self) -> None:
        key = fake("AKIA", 16, "ABC7")
        text = f"\U0001F6E1 deploy {key} then \U0001F680 ssn 123-45-6789 and {key}"
        spans = self.engine.find_dlp_spans(text)
        self.assertEqual(len(spans), 3)
        for category, start, end in spans:
            matched = self.utf16_slice(text, start, end)
            if category == "DLP_US_SSN":
                self.assertEqual(matched, "123-45-6789")
            else:
                self.assertEqual(matched, key)

    def test_analyze_reports_spans(self) -> None:
        key = fake("AKIA", 16, "ABC7")
        result = self.engine.analyze(f"x {key}")
        self.assertEqual(result["dlp_spans"], [["SECRET_LEAK_AWS_ACCESS_KEY", 2, 22]])
        self.assertEqual(self.engine.analyze("clean")["dlp_spans"], [])


class PrivateKeySpanTests(unittest.TestCase):
    """A private-key match covers only the PEM header, so it must get no span."""

    def test_private_key_is_reported_without_a_span(self) -> None:
        engine = daemon.WarmPromptArmorEngine()
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCfaketestbody0123456789"
        pem = "-----BEGIN " + "PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----"
        for text in (pem, '{"private_key": "' + pem.replace("\n", "\\n") + '"}'):
            result = engine.analyze("cat key\n" + text)
            self.assertIn("SECRET_LEAK_PRIVATE_KEY", result["dlp_categories"])
            self.assertFalse(
                any(s[0] == "SECRET_LEAK_PRIVATE_KEY" for s in result["dlp_spans"]),
                result["dlp_spans"],
            )


class ExtraPatternTests(unittest.TestCase):
    def write(self, content: object) -> str:
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content if isinstance(content, str) else json.dumps(content))
        self.addCleanup(os.unlink, path)
        return path

    def test_loads_list_and_object_forms(self) -> None:
        entry = {"name": "ACME_TOKEN", "regex": r"\bacme_[a-f0-9]{32}\b", "risk": 0.9}
        for content in ([entry], {"patterns": [entry]}):
            patterns = daemon.load_extra_patterns(self.write(content))
            self.assertEqual([p.category for p in patterns], ["CUSTOM_ACME_TOKEN"])
            self.assertEqual(patterns[0].risk, 0.9)

    def test_custom_pattern_blocks(self) -> None:
        path = self.write([{"name": "ACME_TOKEN", "regex": r"\bacme_[a-f0-9]{32}\b"}])
        engine = daemon.WarmPromptArmorEngine(extra_patterns=daemon.load_extra_patterns(path))
        result = engine.analyze("token acme_" + "ab12" * 8)
        self.assertEqual(result["decision"], "BLOCK")
        self.assertIn("CUSTOM_ACME_TOKEN", result["dlp_categories"])
        self.assertEqual(engine.analyze("token acme_short")["decision"], "ALLOW")

    def test_rejects_bad_files(self) -> None:
        bad = {
            "invalid regex": [{"name": "BAD_ONE", "regex": "(unclosed"}],
            "name must be": [{"name": "lower", "regex": "x"}],
            "duplicate name": [{"name": "DUP", "regex": "a"}, {"name": "DUP", "regex": "b"}],
            "empty string": [{"name": "EMPTY", "regex": "a*"}],
            "nested quantifier": [{"name": "REDOS", "regex": "(x+)+y"}],
            "redactable must be": [{"name": "FLAG", "regex": "x", "redactable": "yes"}],
            "risk must be": [{"name": "RISKY", "regex": "x", "risk": 2}],
            "expected a JSON list": {"nope": []},
            "invalid JSON": "{not json",
        }
        for expected, content in bad.items():
            with self.subTest(expected=expected):
                with self.assertRaisesRegex(daemon.PatternConfigError, expected):
                    daemon.load_extra_patterns(self.write(content))
        with self.assertRaisesRegex(daemon.PatternConfigError, "file not found"):
            daemon.load_extra_patterns("/nonexistent/armorcept-patterns.json")

    def test_error_message_does_not_echo_regex(self) -> None:
        secretish = "(hunter2-literal"
        with self.assertRaises(daemon.PatternConfigError) as ctx:
            daemon.load_extra_patterns(self.write([{"name": "LEAKY", "regex": secretish}]))
        self.assertNotIn("hunter2", str(ctx.exception))

    def test_config_error_engine_fails_closed(self) -> None:
        engine = daemon.WarmPromptArmorEngine(config_error="invalid ARMORCEPT_EXTRA_PATTERNS: x")
        result = engine.analyze("perfectly clean text")
        self.assertEqual(result["decision"], "BLOCK")
        self.assertTrue(result["categories"][0].startswith("ARMORCEPT_CONFIG_ERROR"))


if __name__ == "__main__":
    unittest.main()
