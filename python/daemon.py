#!/usr/bin/env python3
"""
ArmorCept Local Prompt-Armor Worker Daemon.

Keeps the prompt-armor pipeline warm in memory (with council.enabled = False)
to avoid per-event Python cold-start overhead.

Supports two transport modes:
1. stdio (default): Reads newline-delimited JSON requests from stdin and writes JSON responses to stdout.
2. http: Starts a local HTTP server listening on 127.0.0.1:<port>/analyze (supports --port 0 for ephemeral port assignment
   and optional ARMORCEPT_DAEMON_TOKEN authentication via the X-ArmorCept-Token header).
"""

from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from dataclasses import dataclass
from typing import Any, Dict, List

# Avoid slow outbound HuggingFace Hub checks during local offline startup
os.environ.setdefault("HF_HUB_OFFLINE", "1")


@dataclass(frozen=True)
class DlpPattern:
    category: str
    regex: "re.Pattern[str]"
    risk: float
    confidence: float
    # False when a match doesn't cover the whole secret (the private-key
    # pattern matches only the PEM header). Such matches get no span, so a
    # tool result holding one is withheld whole, never redacted.
    redactable: bool = True


# Token bodies often end in "-" or "_", where \b does not hold, so the end of a
# token is "not followed by another token character" instead.
_TOKEN_END = r"(?![A-Za-z0-9_\-])"


def _builtin(
    regex: str, category: str, risk: float, confidence: float, redactable: bool = True
) -> DlpPattern:
    # re.ASCII so \b, \d and \w mean what they mean in the TypeScript copy
    # (hooks/dlp.ts) and the two can't disagree on non-ASCII neighbours.
    return DlpPattern(category, re.compile(regex, re.ASCII), risk, confidence, redactable)


BUILTIN_DLP_PATTERNS: List[DlpPattern] = [
    _builtin(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "SECRET_LEAK_AWS_ACCESS_KEY", 0.96, 0.98),
    _builtin(
        r"\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b",
        "SECRET_LEAK_GITHUB_TOKEN",
        0.97,
        0.98,
    ),
    # Anthropic API keys (sk-ant-api03-), OAuth tokens (sk-ant-oat01-, used by
    # CLAUDE_CODE_OAUTH_TOKEN) and admin keys (sk-ant-admin01-).
    _builtin(
        r"\bsk-ant-[a-z]{3,5}\d{2}-[A-Za-z0-9_\-]{20,}" + _TOKEN_END,
        "SECRET_LEAK_ANTHROPIC_KEY",
        0.97,
        0.98,
    ),
    _builtin(
        r"\bsk-(proj-[A-Za-z0-9_\-]{20,}|[A-Za-z0-9]{32,})" + _TOKEN_END,
        "SECRET_LEAK_API_KEY",
        0.96,
        0.98,
    ),
    _builtin(r"\bAIza[0-9A-Za-z_\-]{35}" + _TOKEN_END, "SECRET_LEAK_GCP_API_KEY", 0.95, 0.97),
    _builtin(
        r"\bxox[abprs]-[A-Za-z0-9]{8,}(-[A-Za-z0-9]{4,})+" + _TOKEN_END,
        "SECRET_LEAK_SLACK_TOKEN",
        0.96,
        0.98,
    ),
    _builtin(r"\b[rs]k_live_[A-Za-z0-9]{24,}\b", "SECRET_LEAK_STRIPE_KEY", 0.97, 0.98),
    _builtin(r"\bnpm_[A-Za-z0-9]{36}\b", "SECRET_LEAK_NPM_TOKEN", 0.96, 0.98),
    # Matches the header line only, so it also catches keys embedded in JSON
    # (service-account files) where the newlines are escaped as \n.
    _builtin(
        r"-----BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED |PRIVATE )?PRIVATE KEY-----",
        "SECRET_LEAK_PRIVATE_KEY",
        0.98,
        0.99,
        redactable=False,
    ),
    _builtin(
        r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", "DLP_US_SSN", 0.91, 0.93
    ),
]

MAX_SPANS = 1000


def _to_utf16_offsets(text: str, spans: List[List[Any]]) -> List[List[Any]]:
    if not spans or all(ord(ch) < 0x10000 for ch in text):
        return spans
    # extra[i] = number of astral characters in text[:i]
    extra = [0] * (len(text) + 1)
    for i, ch in enumerate(text):
        extra[i + 1] = extra[i] + (1 if ord(ch) >= 0x10000 else 0)
    return [[cat, start + extra[start], end + extra[end]] for cat, start, end in spans]


MAX_EXTRA_PATTERNS = 200
MAX_EXTRA_REGEX_CHARS = 1000
_EXTRA_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
# A quantified group that itself holds a quantifier, such as (a+)+ or (\w*x)*:
# the usual shape of catastrophic backtracking. Python's re has no timeout,
# so these are refused up front. It is a heuristic, not a proof of safety.
_NESTED_QUANTIFIER_RE = re.compile(r"\((?:[^()\\]|\\.)*(?<!\\)[+*}](?:[^()\\]|\\.)*\)[+*{]")


class PatternConfigError(ValueError):
    """Raised when the ARMORCEPT_EXTRA_PATTERNS file cannot be used."""


def load_extra_patterns(path: str) -> List[DlpPattern]:
    """Loads and validates a JSON list of {name, regex, risk[, confidence]} entries.

    The file may be a bare list or an object with a "patterns" list. Any problem
    raises PatternConfigError naming the entry; the regex text is never echoed.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError as exc:
        raise PatternConfigError(f"file not found: {path}") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise PatternConfigError(f"cannot read {path}: {exc.__class__.__name__}") from exc
    except json.JSONDecodeError as exc:
        raise PatternConfigError(f"invalid JSON in {path} (line {exc.lineno})") from exc

    entries = raw.get("patterns") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise PatternConfigError('expected a JSON list or {"patterns": [...]}')
    if len(entries) > MAX_EXTRA_PATTERNS:
        raise PatternConfigError(f"too many patterns ({len(entries)} > {MAX_EXTRA_PATTERNS})")

    patterns: List[DlpPattern] = []
    seen: set[str] = set()
    for idx, entry in enumerate(entries):
        label = f"entry {idx}"
        if not isinstance(entry, dict):
            raise PatternConfigError(f"{label}: expected an object")
        name = entry.get("name")
        if not isinstance(name, str) or not _EXTRA_NAME_RE.match(name):
            raise PatternConfigError(
                f"{label}: name must be 3-64 chars of A-Z, 0-9 and _, starting with a letter"
            )
        label = f'entry {idx} ("{name}")'
        if name in seen:
            raise PatternConfigError(f"{label}: duplicate name")
        seen.add(name)
        regex = entry.get("regex")
        if not isinstance(regex, str) or not regex:
            raise PatternConfigError(f"{label}: regex must be a non-empty string")
        if len(regex) > MAX_EXTRA_REGEX_CHARS:
            raise PatternConfigError(f"{label}: regex longer than {MAX_EXTRA_REGEX_CHARS} chars")
        if _NESTED_QUANTIFIER_RE.search(regex):
            raise PatternConfigError(
                f"{label}: nested quantifier (e.g. (a+)+) can backtrack catastrophically"
            )
        try:
            compiled = re.compile(regex)
        except re.error as exc:
            raise PatternConfigError(f"{label}: invalid regex ({exc.msg})") from exc
        if compiled.search(""):
            raise PatternConfigError(f"{label}: regex matches the empty string")
        risk = entry.get("risk", 0.95)
        confidence = entry.get("confidence", 0.95)
        for field, value in (("risk", risk), ("confidence", confidence)):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 1:
                raise PatternConfigError(f"{label}: {field} must be a number in (0, 1]")
        redactable = entry.get("redactable", False)
        if not isinstance(redactable, bool):
            raise PatternConfigError(f"{label}: redactable must be true or false")
        patterns.append(
            DlpPattern(f"CUSTOM_{name}", compiled, float(risk), float(confidence), redactable)
        )
    return patterns


class WarmPromptArmorEngine:
    """Wrapper around prompt-armor with council fallback explicitly disabled."""

    def __init__(
        self,
        extra_patterns: List[DlpPattern] | None = None,
        config_error: str | None = None,
    ) -> None:
        self.dlp_patterns: List[DlpPattern] = BUILTIN_DLP_PATTERNS + list(extra_patterns or [])
        # A broken ARMORCEPT_EXTRA_PATTERNS file blocks every scan (fail closed,
        # whatever ARMORCEPT_FAIL_OPEN says) instead of silently dropping rules.
        self.config_error = config_error
        self._native_analyze = None
        self._native_armor = None
        self.is_native_loaded = False
        self._load_engine()

    def _load_engine(self) -> None:
        try:
            import prompt_armor  # type: ignore

            # Prevent L2ClassifierLayer from attempting to download the removed
            # upstream HuggingFace repo (aldenb/scout-prompt-injection-classifier-22m)
            try:
                from prompt_armor.layers.l2_classifier import L2ClassifierLayer  # type: ignore

                L2ClassifierLayer._try_download_model = staticmethod(  # type: ignore[method-assign]
                    lambda *_args, **_kwargs: None
                )
            except Exception:  # noqa: BLE001
                pass

            # Disable the internal Ollama council fallback so ArmorCept controls escalation
            if hasattr(prompt_armor, "council"):
                council_mod = getattr(prompt_armor, "council")
                if hasattr(council_mod, "enabled"):
                    setattr(council_mod, "enabled", False)

            if hasattr(prompt_armor, "PromptArmor"):
                cls = getattr(prompt_armor, "PromptArmor")
                try:
                    self._native_armor = cls(council={"enabled": False})
                except TypeError:
                    self._native_armor = cls()
                    if hasattr(self._native_armor, "council") and hasattr(
                        self._native_armor.council, "enabled"
                    ):
                        self._native_armor.council.enabled = False
                self.is_native_loaded = True
            elif hasattr(prompt_armor, "analyze"):
                self._native_analyze = getattr(prompt_armor, "analyze")
                self.is_native_loaded = True
        except ImportError:
            # Fallback lightweight heuristic when prompt_armor wheel/models are not installed locally
            self._native_analyze = None
            self._native_armor = None
            self.is_native_loaded = False

    def analyze(self, text: str) -> Dict[str, Any]:
        start_ns = time.perf_counter_ns()

        if self.config_error is not None:
            return {
                "risk_score": 1.0,
                "confidence": 1.0,
                "decision": "BLOCK",
                "categories": [f"ARMORCEPT_CONFIG_ERROR: {self.config_error}"],
                "dlp_categories": [],
                "evidence": {},
                "latency_ms": 0.0,
                "council_enabled": False,
                "engine_mode": "full" if self.is_native_loaded else "lightweight_fallback",
            }

        if self._native_armor is not None and hasattr(self._native_armor, "analyze"):
            raw = self._native_armor.analyze(text)
            return self._merge_local_dlp(self._normalize_result(raw, start_ns), text)

        if self._native_analyze is not None:
            try:
                raw = self._native_analyze(text, council={"enabled": False})
            except TypeError:
                raw = self._native_analyze(text)
            return self._merge_local_dlp(self._normalize_result(raw, start_ns), text)

        return self._fallback_analyze(text, start_ns)

    def _scan_local_dlp(self, text: str) -> List[tuple[str, float, float, str]]:
        """Scans for high-confidence local secrets/DLP patterns."""
        matches: List[tuple[str, float, float, str]] = []
        for pattern in self.dlp_patterns:
            if pattern.regex.search(text):
                matches.append(
                    (pattern.category, pattern.risk, pattern.confidence, pattern.regex.pattern)
                )
        return matches

    def find_dlp_spans(self, text: str) -> List[List[Any]]:
        """Returns [category, start, end] for every DLP match, as UTF-16 offsets.

        The hooks run in JavaScript, whose string offsets count UTF-16 code
        units, so offsets past an astral character are shifted to match.
        """
        spans: List[List[Any]] = []
        for pattern in self.dlp_patterns:
            if not pattern.redactable:
                continue
            for m in pattern.regex.finditer(text):
                if m.end() > m.start():
                    spans.append([pattern.category, m.start(), m.end()])
                if len(spans) >= MAX_SPANS:
                    break
            if len(spans) >= MAX_SPANS:
                break
        return _to_utf16_offsets(text, spans)

    def _merge_local_dlp(self, result: Dict[str, Any], text: str) -> Dict[str, Any]:
        dlp_hits = self._scan_local_dlp(text)
        if not dlp_hits:
            result["dlp_categories"] = []
            result["dlp_spans"] = []
            return result
        result["dlp_spans"] = self.find_dlp_spans(text)
        categories = list(result.get("categories", []))
        dlp_categories: List[str] = []
        max_risk = float(result.get("risk_score", 0.0))
        confidence = float(result.get("confidence", 1.0))
        for category, risk, conf, _ in dlp_hits:
            if category not in dlp_categories:
                dlp_categories.append(category)
            if category not in categories:
                categories.append(category)
            if risk > max_risk:
                max_risk = risk
                confidence = conf
        result["categories"] = categories
        result["dlp_categories"] = dlp_categories
        result["risk_score"] = max_risk
        result["confidence"] = confidence
        if max_risk >= 0.75:
            result["decision"] = "BLOCK"
        return result

    def _normalize_result(self, raw: Any, start_ns: int) -> Dict[str, Any]:
        elapsed_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000, 2)
        if isinstance(raw, dict):
            return {
                "risk_score": float(raw.get("risk_score", 0.0)),
                "confidence": float(raw.get("confidence", 1.0)),
                "decision": str(raw.get("decision", "ALLOW")).replace("Decision.", ""),
                "categories": [
                    str(c).replace("Category.", "") for c in raw.get("categories", [])
                ],
                "dlp_categories": [],
                "evidence": raw.get("evidence", {}),
                "latency_ms": float(raw.get("latency_ms", elapsed_ms)),
                "council_enabled": False,
                "engine_mode": "full",
            }

        categories_raw = getattr(raw, "categories", []) or []
        categories: List[str] = [
            getattr(c, "name", str(c)).replace("Category.", "") for c in categories_raw
        ]
        decision_raw = getattr(raw, "decision", "ALLOW")
        decision = getattr(decision_raw, "name", str(decision_raw)).replace(
            "Decision.", ""
        )
        evidence_raw = getattr(raw, "evidence", {})
        if (
            not isinstance(evidence_raw, (dict, list, str, int, float, bool))
            and evidence_raw is not None
        ):
            evidence_raw = str(evidence_raw)

        return {
            "risk_score": float(getattr(raw, "risk_score", 0.0)),
            "confidence": float(getattr(raw, "confidence", 1.0)),
            "decision": decision,
            "categories": categories,
            "dlp_categories": [],
            "evidence": evidence_raw or {},
            "latency_ms": float(getattr(raw, "latency_ms", elapsed_ms)),
            "council_enabled": False,
            "engine_mode": "full",
        }

    def _fallback_analyze(self, text: str, start_ns: int) -> Dict[str, Any]:
        """Deterministic fast local regex/semantic fallback when prompt-armor package is unavailable."""
        injection_patterns = [
            (
                r"(?i)\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|system)\s+(instructions|prompts|rules|directives)",
                "PROMPT_INJECTION",
                0.92,
                0.95,
            ),
            (
                r"(?i)\b(you\s+are\s+now\s+DAN|do\s+anything\s+now|developer\s+mode\s+enabled|jailbreak|bypass\s+safety\s+rules)",
                "JAILBREAK",
                0.95,
                0.96,
            ),
            (
                r"(?i)\b(system\s+override|reveal\s+(your\s+)?system\s+prompt|print\s+hidden\s+instructions)",
                "SYSTEM_PROMPT_LEAK",
                0.88,
                0.90,
            ),
        ]

        matched_categories: List[str] = []
        matched_rules: List[str] = []
        max_risk = 0.05
        confidence = 0.94

        for regex, category, risk, conf in injection_patterns:
            if re.search(regex, text):
                matched_categories.append(category)
                matched_rules.append(regex)
                if risk > max_risk:
                    max_risk = risk
                    confidence = conf

        dlp_hits = self._scan_local_dlp(text)
        dlp_categories: List[str] = []
        for category, risk, conf, regex in dlp_hits:
            if category not in dlp_categories:
                dlp_categories.append(category)
            if category not in matched_categories:
                matched_categories.append(category)
            matched_rules.append(regex)
            if risk > max_risk:
                max_risk = risk
                confidence = conf

        elapsed_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000, 2)
        decision = "BLOCK" if max_risk >= 0.75 else "ALLOW"

        return {
            "risk_score": max_risk,
            "confidence": confidence,
            "decision": decision,
            "categories": matched_categories,
            "dlp_categories": dlp_categories,
            "dlp_spans": self.find_dlp_spans(text) if dlp_hits else [],
            "evidence": {
                "layer": "regex_fast_path",
                "matched_rules": matched_rules,
            },
            "latency_ms": elapsed_ms,
            "council_enabled": False,
            "engine_mode": "lightweight_fallback",
            "warning": "running in lightweight local test mode, for full mode install prompt-armor",
        }


def run_stdio_daemon(engine: WarmPromptArmorEngine) -> None:
    """Line-delimited JSON-RPC over stdio."""
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        req_id = None
        try:
            payload = json.loads(line)
            req_id = payload.get("id")
            text = payload.get("text", "")
            if not isinstance(text, str):
                text = json.dumps(text)
            result = engine.analyze(text)
            if req_id is not None:
                result["id"] = req_id
            sys.stdout.write(json.dumps(result) + "\n")
            sys.stdout.flush()
        except Exception as exc:  # noqa: BLE001
            err_resp: Dict[str, Any] = {
                "error": str(exc),
            }
            if req_id is not None:
                err_resp["id"] = req_id
            sys.stdout.write(json.dumps(err_resp) + "\n")
            sys.stdout.flush()


def run_http_daemon(engine: WarmPromptArmorEngine, host: str, port: int) -> None:
    """Lightweight HTTP server for PROMPT_ARMOR_ENDPOINT=http://127.0.0.1:<port>/analyze."""
    expected_token = os.environ.get("ARMORCEPT_DAEMON_TOKEN", "").strip()

    class AnalyzeHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            if self.path not in ("/analyze", "/"):
                self.send_response(404)
                self.end_headers()
                return

            if expected_token:
                provided = self.headers.get("X-ArmorCept-Token", "")
                if not hmac.compare_digest(provided, expected_token):
                    err_bytes = json.dumps({"error": "Unauthorized daemon request"}).encode(
                        "utf-8"
                    )
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(err_bytes)))
                    self.end_headers()
                    self.wfile.write(err_bytes)
                    return

            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length).decode("utf-8")
            try:
                payload = json.loads(raw_body) if raw_body else {}
                text = payload.get("text", "")
                if not isinstance(text, str):
                    text = json.dumps(text)
                result = engine.analyze(text)
                body_bytes = json.dumps(result).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body_bytes)))
                self.end_headers()
                self.wfile.write(body_bytes)
            except Exception as exc:  # noqa: BLE001
                err_bytes = json.dumps({"error": str(exc)}).encode("utf-8")
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(err_bytes)))
                self.end_headers()
                self.wfile.write(err_bytes)

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            # Silence standard HTTP request logs to keep daemon output clean
            return

    # Pre-warm the pipeline on daemon startup before advertising readiness
    warmup = engine.analyze("warmup")
    mode_label = warmup.get("engine_mode", "full")

    server = HTTPServer((host, port), AnalyzeHandler)
    actual_port = int(server.server_port)

    ready_msg = {
        "ready": True,
        "host": host,
        "port": actual_port,
        "engine_mode": mode_label,
    }
    sys.stdout.write(json.dumps(ready_msg) + "\n")
    sys.stdout.flush()

    sys.stderr.write(
        f"🛡️ ArmorCept Warm Prompt-Armor Daemon listening on http://{host}:{actual_port}/analyze (engine_mode={mode_label})\n"
    )
    sys.stderr.flush()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="ArmorCept Warm Prompt-Armor Daemon")
    parser.add_argument(
        "--mode",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport mode: stdio (default) or http",
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind host")
    parser.add_argument(
        "--port",
        type=int,
        default=8443,
        help="HTTP bind port (pass 0 for an OS-assigned ephemeral port)",
    )
    parser.add_argument(
        "--extra-patterns",
        default="",
        help="Path to a JSON file of custom DLP patterns (ARMORCEPT_EXTRA_PATTERNS)",
    )
    args = parser.parse_args()

    extra: List[DlpPattern] = []
    config_error: str | None = None
    if args.extra_patterns:
        try:
            extra = load_extra_patterns(args.extra_patterns)
        except PatternConfigError as exc:
            config_error = f"invalid ARMORCEPT_EXTRA_PATTERNS: {exc}"
            sys.stderr.write(f"🛡️ ArmorCept: {config_error}\n")
            sys.stderr.flush()

    engine = WarmPromptArmorEngine(extra_patterns=extra, config_error=config_error)
    if args.mode == "http":
        run_http_daemon(engine, args.host, args.port)
    else:
        run_stdio_daemon(engine)


if __name__ == "__main__":
    main()
