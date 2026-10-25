#!/usr/bin/env python3
"""
ArmorCept Local Prompt-Armor Worker Daemon.

Keeps the prompt-armor 5-layer pipeline warm in memory (with council.enabled = False)
to achieve < 30ms local evaluation latency without Python cold-start overhead.

Supports two transport modes:
1. stdio (default): Reads newline-delimited JSON requests from stdin and writes JSON responses to stdout.
2. http: Starts a lightweight local HTTP server listening on 127.0.0.1:8443/analyze.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List

# Avoid slow outbound HuggingFace Hub checks during local offline startup
os.environ.setdefault("HF_HUB_OFFLINE", "1")


class WarmPromptArmorEngine:
    """Wrapper around prompt-armor with council fallback explicitly disabled."""

    def __init__(self) -> None:
        self._native_analyze = None
        self._native_armor = None
        self.is_native_loaded = False
        self._load_engine()

    def _load_engine(self) -> None:
        try:
            import prompt_armor  # type: ignore

            # Prevent L2ClassifierLayer from attempting to download the removed
            # private HuggingFace repo (aldenb/scout-prompt-injection-classifier-22m)
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
        dlp_patterns = [
            (
                r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
                "SECRET_LEAK_AWS_ACCESS_KEY",
                0.96,
                0.98,
            ),
            (
                r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b",
                "SECRET_LEAK_GITHUB_TOKEN",
                0.97,
                0.98,
            ),
            (
                r"\bsk-(ant-api03-[A-Za-z0-9\-_]{20,}|proj-[A-Za-z0-9\-_]{20,}|[A-Za-z0-9]{32,})\b",
                "SECRET_LEAK_API_KEY",
                0.96,
                0.98,
            ),
            (
                r"\bAIza[0-9A-Za-z\-_]{35}\b",
                "SECRET_LEAK_GCP_API_KEY",
                0.95,
                0.97,
            ),
            (
                r"-----BEGIN (RSA |EC |OPENSSH |DSA |PRIVATE )?PRIVATE KEY-----",
                "SECRET_LEAK_PRIVATE_KEY",
                0.98,
                0.99,
            ),
            (
                r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
                "DLP_US_SSN",
                0.91,
                0.93,
            ),
        ]
        matches: List[tuple[str, float, float, str]] = []
        for regex, category, risk, conf in dlp_patterns:
            if re.search(regex, text):
                matches.append((category, risk, conf, regex))
        return matches

    def _merge_local_dlp(self, result: Dict[str, Any], text: str) -> Dict[str, Any]:
        dlp_hits = self._scan_local_dlp(text)
        if not dlp_hits:
            return result
        categories = list(result.get("categories", []))
        max_risk = float(result.get("risk_score", 0.0))
        confidence = float(result.get("confidence", 1.0))
        for category, risk, conf, _ in dlp_hits:
            if category not in categories:
                categories.append(category)
            if risk > max_risk:
                max_risk = risk
                confidence = conf
        result["categories"] = categories
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
        if not isinstance(evidence_raw, (dict, list, str, int, float, bool)) and evidence_raw is not None:
            evidence_raw = str(evidence_raw)

        return {
            "risk_score": float(getattr(raw, "risk_score", 0.0)),
            "confidence": float(getattr(raw, "confidence", 1.0)),
            "decision": decision,
            "categories": categories,
            "evidence": evidence_raw or {},
            "latency_ms": float(getattr(raw, "latency_ms", elapsed_ms)),
            "council_enabled": False,
            "engine_mode": "full",
        }

    def _fallback_analyze(self, text: str, start_ns: int) -> Dict[str, Any]:
        """Deterministic fast local regex/semantic fallback when prompt-armor package is unavailable."""
        patterns = [
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
            (
                r"\b(AKIA|ASIA)[0-9A-Z]{16}\b",
                "SECRET_LEAK_AWS_ACCESS_KEY",
                0.96,
                0.98,
            ),
            (
                r"\b(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\b",
                "SECRET_LEAK_GITHUB_TOKEN",
                0.97,
                0.98,
            ),
            (
                r"\bsk-(ant-api03-[A-Za-z0-9\-_]{20,}|proj-[A-Za-z0-9\-_]{20,}|[A-Za-z0-9]{32,})\b",
                "SECRET_LEAK_API_KEY",
                0.96,
                0.98,
            ),
            (
                r"\bAIza[0-9A-Za-z\-_]{35}\b",
                "SECRET_LEAK_GCP_API_KEY",
                0.95,
                0.97,
            ),
            (
                r"-----BEGIN (RSA |EC |OPENSSH |DSA |PRIVATE )?PRIVATE KEY-----",
                "SECRET_LEAK_PRIVATE_KEY",
                0.98,
                0.99,
            ),
            (
                r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
                "DLP_US_SSN",
                0.91,
                0.93,
            ),
        ]

        matched_categories: List[str] = []
        matched_rules: List[str] = []
        max_risk = 0.05
        confidence = 0.94

        for regex, category, risk, conf in patterns:
            if re.search(regex, text):
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
    """Lightweight HTTP server for PROMPT_ARMOR_ENDPOINT=http://127.0.0.1:8443/analyze."""

    class AnalyzeHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            if self.path not in ("/analyze", "/"):
                self.send_response(404)
                self.end_headers()
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

    # Pre-warm the 5-layer pipeline on daemon startup so the first HTTP request is sub-25ms
    warmup = engine.analyze("warmup")
    mode_label = warmup.get("engine_mode", "full")
    sys.stderr.write(
        f"🛡️ ArmorCept Warm Prompt-Armor Daemon listening on http://{host}:{port}/analyze (engine_mode={mode_label})\n"
    )
    sys.stderr.flush()

    server = HTTPServer((host, port), AnalyzeHandler)
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
    parser.add_argument("--port", type=int, default=8443, help="HTTP bind port")
    args = parser.parse_args()

    engine = WarmPromptArmorEngine()
    if args.mode == "http":
        run_http_daemon(engine, args.host, args.port)
    else:
        run_stdio_daemon(engine)


if __name__ == "__main__":
    main()
