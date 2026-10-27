# ArmorCept — Claude Code Security Mod

**ArmorCept** is a deterministic client-side Data Loss Prevention (DLP) and prompt injection security mod for Claude Code (CLI, Desktop App, and VS Code). It intercepts outbound conversational prompts (`prompt.submit`) and tool execution payloads (`tool.call`) before they reach the model or execute on the host machine, and can optionally inspect tool outputs before they are returned to the model (`ARMORCEPT_SCAN_TOOL_RESULTS=true`).

## Architecture & Operating Modes

ArmorCept combines a local open-source analysis engine ([prompt-armor](https://github.com/prompt-armor/prompt-armor)) with enterprise cloud DLP and safety scanning ([Google Cloud Model Armor](https://cloud.google.com/security-command-center/docs/model-armor-overview)):

- **`LOCAL`**: Routes all intercepted payloads strictly to a local `prompt-armor` worker. At `session.start`, ArmorCept automatically spawns a persistent localhost HTTP worker on an ephemeral port (`127.0.0.1:0`) authenticated with a per-session secret token (`X-ArmorCept-Token`), achieving `< 30ms` warm scan latency. If the warm worker is unavailable, ArmorCept automatically falls back to one-shot `stdio` execution (~1.5–4s cold start).
- **`CLOUD`**: Routes all intercepted payloads directly to the Google Cloud Model Armor `sanitizeUserPrompt` REST API using cached OAuth2 service account tokens.
- **`WATERFALL`** *(Default when `GOOGLE_CLOUD_PROJECT` and `MODEL_ARMOR_TEMPLATE_ID` are set; otherwise defaults to `LOCAL`)*:
  1. **Tier 1 (Local Fast-Path)**: Runs `prompt-armor` locally first (`council.enabled = False`). High-confidence threats (`risk_score >= WATERFALL_BLOCK_ABOVE` and `confidence >= WATERFALL_MIN_CONFIDENCE`, or `decision == BLOCK`) are blocked immediately on the client without making a cloud API call.
  2. **Tier 2 (Cloud Escalation & Enterprise DLP)**: Ambiguous payloads (`WARN`, `ESCALATE`, intermediate risk scores, or low confidence) are escalated to Google Cloud Model Armor. When `WATERFALL_ALWAYS_RUN_CLOUD_DLP=true` (default), locally-cleared payloads are also verified by Google Cloud Model Armor's Sensitive Data Protection (SDP/DLP) templates. Set `WATERFALL_ALWAYS_RUN_CLOUD_DLP=false` if you only want uncertain payloads sent to Google Cloud.

## Data Privacy & Network Flows

Because ArmorCept inspects user prompts, tool arguments, and (optionally) tool outputs, understand what data leaves the machine in each mode:

| Mode / Setting | Outbound Network Traffic |
| :--- | :--- |
| **`LOCAL`** | **Zero runtime telemetry or cloud API calls.** All prompts, tool arguments, and (when `ARMORCEPT_SCAN_TOOL_RESULTS=true`) tool outputs remain on `127.0.0.1`. The local daemon runs offline (`HF_HUB_OFFLINE=1`) with `prompt-armor` 0.9.1's five layers (L1 regex, L2 classifier, L3 similarity, L4 structural, L5 negative selection) plus ArmorCept's deterministic DLP/secret patterns. L2 runs in its keyword-heuristic mode: its ONNX model `aldenb/scout-prompt-injection-classifier-22m` is no longer published, so `python/daemon.py` disables the download and `prompt-armor` falls back to keywords. |
| **`WATERFALL`** (`WATERFALL_ALWAYS_RUN_CLOUD_DLP=false`) | Locally blocked (`BLOCK`) and locally cleared (`ALLOW`) payloads stay on the host. Only uncertain (`WARN` / `ESCALATE`) prompts, tool arguments, and (when `ARMORCEPT_SCAN_TOOL_RESULTS=true`) tool outputs are sent to your configured Google Cloud project's regional Model Armor endpoint (`https://modelarmor.<location>.rep.googleapis.com`). |
| **`WATERFALL`** (`WATERFALL_ALWAYS_RUN_CLOUD_DLP=true`, default) | Locally blocked (`BLOCK`) payloads stay on the host. All other non-exempt prompts, tool arguments, and (when `ARMORCEPT_SCAN_TOOL_RESULTS=true`) tool outputs are sent to your Google Cloud project's regional Model Armor endpoint for SDP/DLP and safety inspection. |
| **`CLOUD`** | All non-exempt prompts, tool arguments, and (when `ARMORCEPT_SCAN_TOOL_RESULTS=true`) tool outputs are sent to your Google Cloud project's regional Model Armor endpoint. |

## What ArmorCept Accesses

- **Hooks**: `session.start`, `prompt.submit` and `tool.call`. It can block a prompt or tool call, and withholds tool output when `ARMORCEPT_SCAN_TOOL_RESULTS=true`.
- **Processes**: starts `python/daemon.py` (a localhost-only HTTP worker, or one-shot `stdio`). In `CLOUD`/`WATERFALL` mode it runs `scripts/mint-token.mjs` with `node` to mint an OAuth2 access token, which calls `gcloud` only when `ARMORCEPT_ALLOW_GCLOUD_ADC=true`.
- **Network**: `127.0.0.1` for the local worker. In `CLOUD`/`WATERFALL` mode it also contacts your regional Model Armor endpoint and Google OAuth (see [Data Privacy & Network Flows](#data-privacy--network-flows)).
- **Files and settings**: reads its own environment variables, the settings files, and the service account key at `GOOGLE_APPLICATION_CREDENTIALS`. It writes nothing outside the plugin directory.

## Requirements

- Claude Code with function hooks (tested on 2.1.311, where they are on by default and `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS` is not needed). If your build ships with function hooks turned off, set `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1`.
- Python 3 on `PATH`. Without `prompt-armor` installed, ArmorCept uses its built-in regex and heuristic engine.

## Installation

### Option 1: Install via Claude Code Plugin Marketplace (Recommended)

```bash
claude plugin install armorcept --marketplace armorcept/armorcept
```

Or inside an interactive Claude Code session:

```text
/plugin marketplace add armorcept/armorcept
/plugin install armorcept
```

A marketplace install does not create the Python environment, so scans use the built-in engine. To enable the full `prompt-armor` engine, create the virtual environment inside the installed plugin folder:

```bash
cd ~/.claude/plugins/cache/armorcept/armorcept/0.2.1
python3 -m venv .venv
.venv/bin/pip install -r python/requirements.txt
```

The folder is versioned, so repeat this after updating the plugin.

### Option 2: Load from a Local Clone (`--plugin-dir` or `CLAUDE_CODE_PLUGIN_DIRS`)

```bash
git clone https://github.com/armorcept/armorcept.git
cd armorcept
python3 -m venv .venv
.venv/bin/pip install -r python/requirements.txt

# Per-session load:
claude --plugin-dir ./armorcept

# Or persistent load via environment variable:
export CLAUDE_CODE_PLUGIN_DIRS="/absolute/path/to/armorcept"
```

> **Note on Local Python Environment**: When `.venv` is present inside the plugin directory (`.venv/bin/python` on macOS/Linux or `.venv/Scripts/python.exe` on Windows), ArmorCept runs `prompt-armor`'s five local layers (L1 regex, L2 classifier in keyword mode because its ONNX model is no longer published, L3 similarity, L4 structural, L5 negative selection) plus ArmorCept's deterministic DLP regex rules. Local scans run in overlapping 8 KiB chunks because `prompt-armor`'s L1 layer has a 0.1 s per-rule budget and skips rules on larger inputs; cloud scans run in 32 KiB chunks. Payloads above 512 KiB fail closed. The warm daemon is awaited for at most 3.5 s per session; a slower start is adopted once ready, and calls in the meantime use one-shot execution. If `prompt-armor` is not installed, `python/daemon.py` falls back to its built-in deterministic regex + heuristic engine and displays a status notice.

## Configuration (`.claude/settings.json`)

Configure ArmorCept in `.claude/settings.json` (or enterprise managed policy settings, which take precedence over user settings):

```json
{
  "env": {
    "ARMORCEPT_MODE": "WATERFALL",
    "ARMORCEPT_FAIL_OPEN": "false",
    "ARMORCEPT_LOCAL_DLP_ACTION": "block",
    "ARMORCEPT_SCAN_TOOL_RESULTS": "false",
    "ARMORCEPT_INTERACTIVE_OVERRIDE": "false",
    "ARMORCEPT_EXEMPT_TOOLS": "",
    "ARMORCEPT_ALLOWLIST_PATHS": "",
    "WATERFALL_ALLOW_BELOW": "0.30",
    "WATERFALL_BLOCK_ABOVE": "0.75",
    "WATERFALL_MIN_CONFIDENCE": "0.80",
    "WATERFALL_ALWAYS_RUN_CLOUD_DLP": "true",
    "GOOGLE_APPLICATION_CREDENTIALS": "/path/to/gcp-service-account.json",
    "GOOGLE_CLOUD_PROJECT": "enterprise-sec-project",
    "GOOGLE_CLOUD_LOCATION": "us-central1",
    "MODEL_ARMOR_TEMPLATE_ID": "claude-code-dlp-template"
  }
}
```

### Environment Variables Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `ARMORCEPT_MODE` | `WATERFALL` (with GCP config) or `LOCAL` | Execution mode: `LOCAL`, `CLOUD`, or `WATERFALL`. |
| `ARMORCEPT_FAIL_OPEN` | `false` | When `false` (default), engine timeouts, crashes, or malformed responses block execution (fail-closed), including via `.catch` handlers on gating hooks. |
| `ARMORCEPT_LOCAL_DLP_ACTION` | `block` | Action for pure local DLP regex matches (e.g., `DLP_US_SSN`, `SECRET_LEAK_AWS_ACCESS_KEY`) in `LOCAL` mode: `block`, `warn`, or `allow`. |
| `ARMORCEPT_SCAN_TOOL_RESULTS` | `false` | When `true`, scans tool output after execution and withholds poisoned/sensitive results from the model (`{ deny }`). |
| `ARMORCEPT_INTERACTIVE_OVERRIDE` | `false` | When `true` in `LOCAL` mode (or when explicitly enabled in enterprise managed policy), prompts the user via `$.ui.ask` to allow a blocked action once. |
| `ARMORCEPT_EXEMPT_TOOLS` | `""` | Comma-separated list of tool names to exempt from scanning (e.g., `Glob,LS`). |
| `ARMORCEPT_ALLOWLIST_PATHS` | `""` | Comma-separated glob patterns for file paths exempt from tool scanning (e.g., `docs/public/**,*.md`). Dot segments are resolved before matching. A pattern without a leading `/` matches that path anywhere on disk; start it with `/` to anchor it. Symlinks are not resolved. |
| `ARMORCEPT_ALLOW_GCLOUD_ADC` | `false` | Set to `true` to permit ambient `~/.config/gcloud/application_default_credentials.json` or `gcloud auth application-default print-access-token` fallback when `GOOGLE_APPLICATION_CREDENTIALS` is unset. |
| `PROMPT_ARMOR_ENDPOINT` | `stdio` | Set to an explicit `http://127.0.0.1:<port>/analyze` URL to use an externally managed daemon instead of the auto-spawned warm daemon. |
| `PROMPT_ARMOR_TIMEOUT_MS` | `5000` | Timeout in milliseconds for local `prompt-armor` requests. |
| `WATERFALL_ALLOW_BELOW` | `0.30` | Local risk score below which a payload is considered low-risk (`[0, 1]`, must be `< WATERFALL_BLOCK_ABOVE`). |
| `WATERFALL_BLOCK_ABOVE` | `0.75` | Local risk score at or above which a payload is immediately blocked (`[0, 1]`). |
| `WATERFALL_MIN_CONFIDENCE` | `0.80` | Minimum local confidence required to take a Tier 1 fast-path decision in `WATERFALL` mode (`[0, 1]`). |
| `WATERFALL_ALWAYS_RUN_CLOUD_DLP` | `true` | Whether locally cleared payloads in `WATERFALL` mode are still sent to Google Cloud Model Armor for enterprise SDP/DLP inspection. |
| `GOOGLE_APPLICATION_CREDENTIALS` | *(unset)* | Path to a Google Cloud Service Account JSON key file (supports `~/` and session-relative paths). |
| `GOOGLE_CLOUD_ACCESS_TOKEN` | *(unset)* | Optional pre-minted OAuth2 access token (`ya29...`). |
| `GOOGLE_CLOUD_PROJECT` | *(unset)* | Google Cloud Project ID hosting the Model Armor template. |
| `GOOGLE_CLOUD_LOCATION` | `us-central1` | Google Cloud region for Model Armor (`us-central1`, `europe-west1`, etc.). |
| `MODEL_ARMOR_TEMPLATE_ID` | *(unset)* | Model Armor template ID configured with your SDP/DLP, PI/Jailbreak, and RAI filters. |
| `MODEL_ARMOR_TIMEOUT_MS` | `5000` | Timeout in milliseconds for Google Cloud Model Armor requests. |

## Development & Verification

```bash
# Install devDependencies
npm install

# Type-check against both Claude Code sandbox types and project tsconfig
npm run typecheck

# Validate plugin manifest, hook registrations, and .catch guards
npm run validate

# Run the Claude Code plugin test suite
npm test
```

## Acknowledgments

- **[prompt-armor](https://github.com/prompt-armor/prompt-armor)** ([PyPI](https://pypi.org/project/prompt-armor/), `Apache-2.0`) by the prompt-armor contributors — powers ArmorCept's local prompt injection and jailbreak analysis pipeline.
- **[Google Cloud Model Armor](https://cloud.google.com/security-command-center/docs/model-armor-overview)** — powers ArmorCept's enterprise cloud sanitization, Responsible AI (RAI), and Sensitive Data Protection (SDP/DLP) enforcement.

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
