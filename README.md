# ArmorCept — Claude Code Security Mod

**ArmorCept** is a deterministic client-side Data Loss Prevention (DLP) and prompt injection security mod for Claude Code (CLI, Desktop App, and VS Code). It intercepts outbound conversational prompts (`prompt` / `UserPromptSubmit`) and tool execution payloads (`tool.call` / `PreToolUse`) before they reach the model or execute on the host machine.

## Architecture & Modes

ArmorCept combines a fast local open-source analysis engine ([prompt-armor](https://github.com/prompt-armor/prompt-armor), `< 30ms` inference with Ollama council disabled) with enterprise cloud DLP and safety scanning ([Google Cloud Model Armor](https://cloud.google.com/security-command-center/docs/model-armor-overview)):

- **`LOCAL`**: Routes all intercepted payloads strictly to a local warm `prompt-armor` worker. Zero API cost, offline-capable, `< 30ms` latency.
- **`CLOUD`**: Routes all intercepted payloads directly to the Google Cloud Model Armor `sanitizeUserPrompt` REST API.
- **`WATERFALL`** *(Default)*: Executes `prompt-armor` locally first (`council.enabled = False`), immediately blocking obvious attacks (`risk_score >= WATERFALL_BLOCK_ABOVE`), escalating uncertain payloads (`WATERFALL_ALLOW_BELOW <= risk_score < WATERFALL_BLOCK_ABOVE` or `confidence < WATERFALL_MIN_CONFIDENCE`) to Google Cloud Model Armor, and optionally enforcing cloud DLP on locally-cleared payloads (`WATERFALL_ALWAYS_RUN_CLOUD_DLP=true`).

## Configuration (`.claude/settings.json`)

```json
{
  "env": {
    "ARMORCEPT_MODE": "WATERFALL",
    "ARMORCEPT_FAIL_OPEN": "false",
    "PROMPT_ARMOR_ENDPOINT": "stdio",
    "WATERFALL_ALLOW_BELOW": "0.30",
    "WATERFALL_BLOCK_ABOVE": "0.75",
    "WATERFALL_MIN_CONFIDENCE": "0.80",
    "WATERFALL_ALWAYS_RUN_CLOUD_DLP": "true",
    "GOOGLE_APPLICATION_CREDENTIALS": "/path/to/gcp-key.json",
    "GOOGLE_CLOUD_PROJECT": "enterprise-sec-project",
    "GOOGLE_CLOUD_LOCATION": "us-central1",
    "MODEL_ARMOR_TEMPLATE_ID": "claude-code-dlp-template"
  }
}
```

## Development & Testing

```bash
# Install Node dependencies
npm install

# Install Python prompt-armor daemon dependencies (optional for local neural layers)
pip install -r python/requirements.txt

# Build TypeScript to ./dist
npm run build

# Run automated unit and integration tests
npm test
```

## Acknowledgments

- **[prompt-armor](https://github.com/prompt-armor/prompt-armor)** ([PyPI](https://pypi.org/project/prompt-armor/), `Apache-2.0`) by the prompt-armor contributors — powers ArmorCept's local 5-layer prompt injection and jailbreak analysis pipeline.
- **[Google Cloud Model Armor](https://cloud.google.com/security-command-center/docs/model-armor-overview)** — powers ArmorCept's enterprise cloud sanitization, Responsible AI (RAI), and Sensitive Data Protection (SDP/DLP) enforcement.

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).

