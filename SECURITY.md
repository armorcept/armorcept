# Security Policy

ArmorCept is a security control, so a way to get a prompt, tool call or tool output past it is a vulnerability. Please report it privately.

## Reporting a Vulnerability

Use GitHub's private vulnerability reporting: open the [Security tab](https://github.com/armorcept/armorcept/security) and choose **Report a vulnerability**. Please do not open a public issue or pull request for a vulnerability.

Useful details to include:

- ArmorCept version, Claude Code version and platform
- `ARMORCEPT_MODE` and any non-default `ARMORCEPT_*` or `WATERFALL_*` settings
- Whether `prompt-armor` was installed (the full engine) or the built-in engine was used
- The smallest payload or steps that reproduce the issue

Do not include real secrets or personal data in reports. Use test values such as AWS's documented example key `AKIAIOSFODNN7EXAMPLE`.

## In Scope

- Payloads that bypass detection or blocking in any mode
- Fail-open behavior when `ARMORCEPT_FAIL_OPEN=false`
- Data sent off the host contrary to the [Data Privacy & Network Flows](README.md#data-privacy--network-flows) table
- Weaknesses in the local worker, such as token handling or binding beyond `127.0.0.1`
- Credential exposure in the Google Cloud token flow

Detection gaps that belong to `prompt-armor` itself or Google Cloud Model Armor should also be reported to those projects.

## Supported Versions

Only the latest release receives fixes.
