/**
 * ArmorCept — Claude Code Security Mod Hooks Module
 *
 * Enforces client-side DLP and Prompt Injection protection across:
 *   - LOCAL mode (prompt-armor local daemon via warm HTTP worker or stdio fallback)
 *   - CLOUD mode (Google Cloud Model Armor REST API)
 *   - WATERFALL mode (Tier 1 local fast-path + Tier 2 cloud deep escalation)
 */

import type { EngineInterface, On, Register } from 'claude-code';
import {
  getLastKnownFailOpen,
  readRuntimeConfig,
  resetRuntimeConfigCache,
} from './config';
import {
  getWarmDaemonEngineMode,
  resetEngineState,
  resolvePythonBinary,
  startWarmDaemon,
} from './engines';
import {
  extractToolPayload,
  formatAlertBanner,
  formatToolDenyMessage,
  formatToolResultWithheldMessage,
  getStatusBadge,
  isToolCallExempt,
  safeUi,
} from './format';
import {
  buildDecisionRecord,
  flushDecisionLog,
  getSessionId,
  isAuditBypassed,
  recordDecision,
  resetDecisionLogState,
  type DecisionAction,
  type DecisionHook,
} from './decisions';
import { evaluateArmorCept } from './orchestrator';
import { isRedactable, redactText } from './redact';
import { getLoadedExactSecretNames } from './secrets';
import type { EvaluationVerdict, RuntimeConfig } from './types';

async function maybeAskInteractiveOverride(
  $: EngineInterface,
  cfg: RuntimeConfig | undefined,
  verdict: EvaluationVerdict,
  targetLabel: string
): Promise<boolean> {
  if (!cfg?.interactiveOverride) {
    return false;
  }
  // Never allow interactive override on fail-closed engine/config errors
  if (verdict.source === 'ArmorCept') {
    return false;
  }

  try {
    const choice = await $.ui.ask(
      `🛡️ ArmorCept blocked ${targetLabel} (${verdict.reason}). Override security block?`,
      {
        header: 'ArmorCept',
        options: ['Block (Recommended)', 'Allow Once'],
      }
    );
    if (choice === 'Allow Once') {
      safeUi(() =>
        $.ui.log(
          `🛡️ [ArmorCept Override] User allowed ${targetLabel} once despite ${verdict.source} finding: ${verdict.reason}`,
          { to: 'transcript' }
        )
      );
      return true;
    }
  } catch {
    // Dialog dismissed or headless (-p) run: always treat rejection as a block
  }
  return false;
}

type RedactResult =
  | { kind: 'redacted'; toolResult: Record<string, unknown>; categories: string[] }
  | { kind: 'withhold'; verdict: EvaluationVerdict };

/**
 * Redacts every model-visible field of a tool result. The field that was
 * scanned reuses its verdict; the other one (when a result has both `text`
 * and `result`) is scanned on its own. Any field that can't be redacted
 * withholds the whole result.
 */
async function redactToolResult(
  $: EngineInterface,
  record: Record<string, unknown>,
  scannedField: 'text' | 'result',
  scannedVerdict: EvaluationVerdict
): Promise<RedactResult> {
  const next: Record<string, unknown> = { ...record };
  const categories = new Set<string>();
  for (const field of ['text', 'result'] as const) {
    const value = record[field];
    if (value === undefined || (field === 'text' && typeof value !== 'string')) {
      continue;
    }
    const asText = typeof value === 'string' ? value : JSON.stringify(value);
    const verdict =
      field === scannedField ? scannedVerdict : await evaluateArmorCept($, asText);
    if (verdict.decision !== 'BLOCK') continue;
    const outcome = await redactText($, asText, verdict);
    if (outcome.kind === 'withhold') {
      return outcome;
    }
    outcome.categories.forEach((c) => categories.add(c));
    if (typeof value === 'string') {
      next[field] = outcome.text;
    } else {
      try {
        next[field] = JSON.parse(outcome.text) as unknown;
      } catch {
        // A match spanned JSON structure; there's no safe partial result
        return { kind: 'withhold', verdict };
      }
    }
  }
  return { kind: 'redacted', toolResult: next, categories: [...categories] };
}

async function logDecision(
  $: EngineInterface,
  cfg: RuntimeConfig | undefined,
  hook: DecisionHook,
  verdict: EvaluationVerdict,
  action: DecisionAction,
  latencyMs: number,
  tool?: string
): Promise<void> {
  if (!cfg?.decisionLogPath) return;
  try {
    const session = await getSessionId($);
    recordDecision(
      $,
      cfg,
      buildDecisionRecord(cfg, { hook, tool, verdict, action, latencyMs, session })
    );
  } catch {
    // Logging must never affect the security decision
  }
}

function announceAudit(
  $: EngineInterface,
  verdict: EvaluationVerdict,
  toolName?: string
): void {
  const banner = formatAlertBanner(verdict, toolName, { audit: true });
  safeUi(() => $.ui.toast(banner, { timeoutMs: 5000 }));
}

export const register: Register = (on: On): void => {
  resetRuntimeConfigCache();
  resetEngineState();
  resetDecisionLogState();

  on('session.start', async ($, e, next) => {
    try {
      resetRuntimeConfigCache();
      const cfg = await readRuntimeConfig($, true);
      const loadedSecrets = getLoadedExactSecretNames();
      const skippedSecrets = cfg.secretEnvVars.filter(
        (name) => !loadedSecrets.includes(name)
      );
      if (skippedSecrets.length > 0) {
        safeUi(() =>
          $.ui.toast(
            `⚠️ ArmorCept: not matching ${skippedSecrets.join(', ')} (unset or shorter than 16 characters)`,
            { timeoutMs: 6000 }
          )
        );
      }
      if (cfg.mode !== 'CLOUD') {
        const { hasVenv } = await resolvePythonBinary($);
        if (
          !cfg.promptArmorEndpoint.startsWith('http://') &&
          !cfg.promptArmorEndpoint.startsWith('https://')
        ) {
          void startWarmDaemon($, cfg);
        }
        if (!hasVenv && cfg.promptArmorEndpoint === 'stdio') {
          safeUi(() =>
            $.ui.toast(
              '⚠️ ArmorCept: running in lightweight local test mode, for full mode install prompt-armor',
              { timeoutMs: 6000 }
            )
          );
          safeUi(() =>
            $.ui.status(getStatusBadge(cfg.mode, 'lightweight_fallback'))
          );
          return next(e);
        }
      }
      safeUi(() =>
        $.ui.status(
          getStatusBadge(cfg.mode, getWarmDaemonEngineMode() ?? 'full')
        )
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      safeUi(() =>
        $.ui.toast(`⚠️ ArmorCept configuration error: ${msg}`, {
          timeoutMs: 6000,
        })
      );
      safeUi(() => $.ui.status('🛡️ ArmorCept: Config Error'));
    }
    return next(e);
  });

  on('prompt.submit', async ($, e, next) => {
    const promptRecord = e as unknown as Record<string, unknown>;
    const promptText =
      typeof promptRecord['text'] === 'string'
        ? promptRecord['text']
        : typeof promptRecord['prompt'] === 'string'
          ? promptRecord['prompt']
          : '';

    let cfg: RuntimeConfig | undefined;
    try {
      cfg = await readRuntimeConfig($);
    } catch {
      // evaluateArmorCept will handle and report configuration errors according to failOpen
    }

    const started = Date.now();
    const verdict = await evaluateArmorCept($, promptText);
    const latencyMs = Date.now() - started;

    if (verdict.decision === 'BLOCK') {
      if (isAuditBypassed(cfg, verdict)) {
        announceAudit($, verdict);
        await logDecision($, cfg, 'prompt.submit', verdict, 'audited', latencyMs);
      } else {
        const overridden = await maybeAskInteractiveOverride(
          $,
          cfg,
          verdict,
          'prompt submission'
        );
        if (!overridden) {
          const banner = formatAlertBanner(verdict);
          safeUi(() => $.ui.status(`🛡️ ArmorCept: Blocked (${verdict.source})`));
          safeUi(() => $.ui.toast(banner, { timeoutMs: 6000 }));
          await logDecision($, cfg, 'prompt.submit', verdict, 'blocked', latencyMs);
          return { drop: banner };
        }
        await logDecision($, cfg, 'prompt.submit', verdict, 'overridden', latencyMs);
      }
    } else {
      if (verdict.decision === 'WARN') {
        const warnBanner = formatAlertBanner(verdict);
        safeUi(() => $.ui.toast(warnBanner, { timeoutMs: 5000 }));
      }
      await logDecision(
        $,
        cfg,
        'prompt.submit',
        verdict,
        verdict.decision === 'WARN' ? 'warned' : 'allowed',
        latencyMs
      );
    }

    safeUi(() =>
      $.ui.status(getStatusBadge(verdict.mode, verdict.engineMode))
    );
    return next(e);
  }).catch(($, e, next) => {
    if (next.called) {
      return next(e);
    }
    if (getLastKnownFailOpen()) {
      return next(e);
    }
    const reason = `🛡️ [ArmorCept Blocked] Source: ArmorCept | Reason: Fail-closed security block on unhandled hook error (${next.error.kind}): ${next.error.message}`;
    safeUi(() => $.ui.status('🛡️ ArmorCept: Blocked (Hook Error)'));
    safeUi(() => $.ui.toast(reason, { timeoutMs: 6000 }));
    return { drop: reason };
  });

  on('tool.call', async ($, e, next) => {
    const eventRecord = (e ?? {}) as unknown as Record<string, unknown>;
    const { toolName, serializedPayload, filePath } =
      extractToolPayload(eventRecord);

    let cfg: RuntimeConfig | undefined;
    try {
      cfg = await readRuntimeConfig($);
    } catch {
      // evaluateArmorCept will handle and report configuration errors according to failOpen
    }

    const exempt = cfg ? isToolCallExempt(toolName, filePath, cfg) : false;

    if (!exempt) {
      const started = Date.now();
      const verdict = await evaluateArmorCept($, serializedPayload);
      const latencyMs = Date.now() - started;
      let action: DecisionAction =
        verdict.decision === 'WARN' ? 'warned' : 'allowed';

      if (verdict.decision === 'BLOCK' && isAuditBypassed(cfg, verdict)) {
        announceAudit($, verdict, toolName);
        action = 'audited';
      } else if (verdict.decision === 'BLOCK') {
        const overridden = await maybeAskInteractiveOverride(
          $,
          cfg,
          verdict,
          `tool "${toolName}"`
        );
        action = overridden ? 'overridden' : 'blocked';
        if (!overridden) {
          const banner = formatAlertBanner(verdict, toolName);
          const denyMessage = formatToolDenyMessage(verdict, toolName);
          safeUi(() =>
            $.ui.status(`🛡️ ArmorCept: Blocked (${verdict.source})`)
          );
          safeUi(() => $.ui.toast(banner, { timeoutMs: 6000 }));
          const toolUseId = eventRecord['tool_use_id'];
          if (typeof toolUseId === 'string' && toolUseId !== '') {
            safeUi(() => $.ui.notice(toolUseId, banner));
          }
          await logDecision($, cfg, 'tool.call', verdict, 'blocked', latencyMs, toolName);
          return { deny: denyMessage };
        }
      }

      if (verdict.decision === 'WARN') {
        const warnBanner = formatAlertBanner(verdict, toolName);
        safeUi(() => $.ui.toast(warnBanner, { timeoutMs: 5000 }));
      }
      await logDecision($, cfg, 'tool.call', verdict, action, latencyMs, toolName);

      safeUi(() =>
        $.ui.status(getStatusBadge(verdict.mode, verdict.engineMode))
      );
    }

    const toolResult = await next(e);

    // Optional post-execution tool result scanning (ARMORCEPT_SCAN_TOOL_RESULTS=true)
    if (
      cfg?.scanToolResults &&
      !exempt &&
      toolResult &&
      typeof toolResult === 'object' &&
      !('deny' in toolResult && toolResult.deny)
    ) {
      const resultRecord = toolResult as Record<string, unknown>;
      const scannedField: 'text' | 'result' =
        typeof resultRecord['text'] === 'string' ? 'text' : 'result';
      const resultText =
        typeof resultRecord['text'] === 'string'
          ? resultRecord['text']
          : resultRecord['result'] !== undefined
            ? typeof resultRecord['result'] === 'string'
              ? resultRecord['result']
              : JSON.stringify(resultRecord['result'])
            : '';
      if (resultText.trim().length > 0) {
        const started = Date.now();
        const resultVerdict = await evaluateArmorCept($, resultText);
        const latencyMs = Date.now() - started;
        if (
          resultVerdict.decision === 'BLOCK' &&
          isAuditBypassed(cfg, resultVerdict)
        ) {
          announceAudit($, resultVerdict, `${toolName} output`);
          await logDecision($, cfg, 'tool.result', resultVerdict, 'audited', latencyMs, toolName);
          return toolResult;
        }
        if (
          resultVerdict.decision === 'BLOCK' &&
          cfg.toolResultAction === 'redact' &&
          isRedactable(resultVerdict)
        ) {
          const redaction = await redactToolResult(
            $,
            resultRecord,
            scannedField,
            resultVerdict
          );
          if (redaction.kind === 'redacted') {
            const note = `🛡️ [ArmorCept Redacted] Tool (${toolName}) output — ${redaction.categories.join(', ')}`;
            safeUi(() => $.ui.status(`🛡️ ArmorCept: Redacted (${resultVerdict.source})`));
            safeUi(() => $.ui.toast(note, { timeoutMs: 5000 }));
            await logDecision($, cfg, 'tool.result', resultVerdict, 'redacted', Date.now() - started, toolName);
            return redaction.toolResult as typeof toolResult;
          }
          const withheldBy = redaction.verdict;
          const banner = formatAlertBanner(withheldBy, `${toolName} output`);
          safeUi(() => $.ui.status(`🛡️ ArmorCept: Withheld (${withheldBy.source})`));
          safeUi(() => $.ui.toast(banner, { timeoutMs: 6000 }));
          await logDecision($, cfg, 'tool.result', withheldBy, 'withheld', Date.now() - started, toolName);
          return { deny: formatToolResultWithheldMessage(withheldBy, toolName) };
        }
        if (resultVerdict.decision === 'BLOCK') {
          const banner = formatAlertBanner(
            resultVerdict,
            `${toolName} output`
          );
          const withholdMsg = formatToolResultWithheldMessage(
            resultVerdict,
            toolName
          );
          safeUi(() =>
            $.ui.status(`🛡️ ArmorCept: Withheld (${resultVerdict.source})`)
          );
          safeUi(() => $.ui.toast(banner, { timeoutMs: 6000 }));
          await logDecision($, cfg, 'tool.result', resultVerdict, 'withheld', latencyMs, toolName);
          return { deny: withholdMsg };
        }
        await logDecision(
          $,
          cfg,
          'tool.result',
          resultVerdict,
          resultVerdict.decision === 'WARN' ? 'warned' : 'allowed',
          latencyMs,
          toolName
        );
      }
    }

    return toolResult;
  }).catch(($, e, next) => {
    if (next.called) {
      return next(e);
    }
    if (getLastKnownFailOpen()) {
      return next(e);
    }
    const eventRecord = (e ?? {}) as unknown as Record<string, unknown>;
    const toolName = String(
      eventRecord['tool'] ?? eventRecord['tool_name'] ?? 'UnknownTool'
    );
    const denyMessage = `Tool execution blocked by ArmorCept fail-closed handler for tool "${toolName}" (${next.error.kind}): ${next.error.message}`;
    safeUi(() => $.ui.status('🛡️ ArmorCept: Blocked (Hook Error)'));
    safeUi(() => $.ui.toast(denyMessage, { timeoutMs: 6000 }));
    return { deny: denyMessage };
  });

  on('session.end', async ($, e, next) => {
    try {
      await flushDecisionLog();
    } catch {
      // Never hold up shutdown
    }
    return next(e);
  });
};

export default register;
