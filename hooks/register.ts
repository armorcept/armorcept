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
import { evaluateArmorCept } from './orchestrator';
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

export const register: Register = (on: On): void => {
  resetRuntimeConfigCache();
  resetEngineState();

  on('session.start', async ($, e, next) => {
    try {
      resetRuntimeConfigCache();
      const cfg = await readRuntimeConfig($, true);
      if (cfg.mode !== 'CLOUD') {
        const { hasVenv } = await resolvePythonBinary($);
        if (
          !cfg.promptArmorEndpoint.startsWith('http://') &&
          !cfg.promptArmorEndpoint.startsWith('https://')
        ) {
          void startWarmDaemon($);
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

    const verdict = await evaluateArmorCept($, promptText);

    if (verdict.decision === 'BLOCK') {
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
        return { drop: banner };
      }
    }

    if (verdict.decision === 'WARN') {
      const warnBanner = formatAlertBanner(verdict);
      safeUi(() => $.ui.toast(warnBanner, { timeoutMs: 5000 }));
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
      const verdict = await evaluateArmorCept($, serializedPayload);

      if (verdict.decision === 'BLOCK') {
        const overridden = await maybeAskInteractiveOverride(
          $,
          cfg,
          verdict,
          `tool "${toolName}"`
        );
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
          return { deny: denyMessage };
        }
      }

      if (verdict.decision === 'WARN') {
        const warnBanner = formatAlertBanner(verdict, toolName);
        safeUi(() => $.ui.toast(warnBanner, { timeoutMs: 5000 }));
      }

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
      const resultText =
        typeof resultRecord['text'] === 'string'
          ? resultRecord['text']
          : resultRecord['result'] !== undefined
            ? typeof resultRecord['result'] === 'string'
              ? resultRecord['result']
              : JSON.stringify(resultRecord['result'])
            : '';
      if (resultText.trim().length > 0) {
        const resultVerdict = await evaluateArmorCept($, resultText);
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
          return { deny: withholdMsg };
        }
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
};

export default register;
