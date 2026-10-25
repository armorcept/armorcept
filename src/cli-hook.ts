#!/usr/bin/env node
import * as fs from 'node:fs';
import {
  createArmorCeptRouter,
  extractPromptText,
  extractToolCallPayload,
} from './register.js';
import {
  formatSecurityAlertBanner,
  formatSyntheticToolBlockError,
} from './ui/feedback.js';

/**
 * CLI Hook entrypoint for Claude Code `UserPromptSubmit` and `PreToolUse` command hooks.
 * Reads the hook payload JSON from stdin, runs ArmorCept evaluation, and outputs
 * Claude Code hook decision JSON (or exits with code 2 to block).
 */
async function main(): Promise<void> {
  const rawInput = fs.readFileSync(0, 'utf-8').trim();
  const payload = rawInput ? JSON.parse(rawInput) : {};

  const hookEventName: string =
    process.argv[2] ?? payload.hook_event_name ?? 'UserPromptSubmit';

  const router = createArmorCeptRouter();

  if (hookEventName === 'PreToolUse' || payload.tool_name || payload.tool_input) {
    const { toolName, serializedPayload } = extractToolCallPayload(payload);
    const verdict = await router.evaluatePayload(serializedPayload, 'tool', {
      toolName,
    });

    if (verdict.decision === 'BLOCK') {
      const syntheticError = formatSyntheticToolBlockError(verdict, toolName);
      const alertBanner = formatSecurityAlertBanner(verdict, toolName);
      process.stderr.write(`${alertBanner}\n`);
      process.stdout.write(
        JSON.stringify({
          decision: 'block',
          reason: syntheticError,
          hookSpecificOutput: {
            hookEventName: 'PreToolUse',
            permissionDecision: 'deny',
            permissionDecisionReason: syntheticError,
          },
        }) + '\n'
      );
      process.exit(2);
    }
    process.exit(0);
  } else {
    const promptText = extractPromptText(payload);
    const verdict = await router.evaluatePayload(promptText, 'prompt');

    if (verdict.decision === 'BLOCK') {
      const alertBanner = formatSecurityAlertBanner(verdict);
      process.stderr.write(`${alertBanner}\n`);
      process.stdout.write(
        JSON.stringify({
          decision: 'block',
          reason: alertBanner,
        }) + '\n'
      );
      process.exit(2);
    }
    process.exit(0);
  }
}

main().catch((err) => {
  const message = err instanceof Error ? err.message : String(err);
  process.stderr.write(`🛡️ [ArmorCept Error] ${message}\n`);
  if ((process.env.ARMORCEPT_FAIL_OPEN ?? 'false').toLowerCase() === 'true') {
    process.exit(0);
  }
  process.exit(2);
});
