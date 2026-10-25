import type { EvaluationVerdict } from '../types.js';

export interface ClaudeModUiApi {
  render?: (content: string | Record<string, unknown>) => void;
  status?: (text: string) => void;
  toast?: (
    message: string,
    options?: { type?: 'info' | 'warning' | 'error' | 'success' }
  ) => void;
  band?: (content: string) => void;
}

export interface ClaudeModContext {
  ui?: ClaudeModUiApi;
  [key: string]: unknown;
}

/**
 * Formats a blocked verdict into a clear security alert banner for terminal and desktop UI.
 */
export function formatSecurityAlertBanner(
  verdict: EvaluationVerdict,
  targetLabel?: string
): string {
  const categoryText =
    verdict.categories.length > 0
      ? verdict.categories.join(', ')
      : 'Security Policy Violation';
  const contextHeader =
    verdict.contextType === 'tool'
      ? `Tool Call Blocked${targetLabel ? ` (${targetLabel})` : ''}`
      : 'Prompt Blocked';

  const lines = [
    `🛡️ [ArmorCept Security Alert] ${contextHeader}`,
    `  • Engine Source:      ${verdict.source}`,
    `  • Violation Category: ${categoryText}`,
    `  • Evidence / Score:   ${verdict.evidence}`,
    `  • Evaluation Latency: ${verdict.latencyMs.toFixed(1)}ms`,
  ];

  return lines.join('\n');
}

/**
 * Formats the deterministic synthetic error string returned to the LLM context
 * when a PreToolUse / tool.call event is blocked, allowing the agent to self-correct.
 */
export function formatSyntheticToolBlockError(
  verdict: EvaluationVerdict,
  toolName?: string
): string {
  const categoryText =
    verdict.categories.length > 0
      ? verdict.categories.join(', ')
      : 'Policy Violation';
  const toolPrefix = toolName ? `[Tool: ${toolName}] ` : '';
  return `Tool execution blocked by ArmorCept security policy: ${toolPrefix}[Engine: ${verdict.source}] [Violation: ${categoryText}] [Evidence: ${verdict.evidence}]`;
}

/**
 * Formats a concise status badge for unobtrusive UI validation feedback.
 */
export function formatStatusBadge(verdict: EvaluationVerdict): string {
  if (verdict.decision === 'BLOCK') {
    const category = verdict.categories[0] ?? 'Violation';
    return `🛡️ ArmorCept: BLOCKED by ${verdict.source} (${category} • ${verdict.latencyMs.toFixed(
      1
    )}ms)`;
  }

  if (verdict.failOpenTriggered) {
    return `⚠️ ArmorCept: ALLOW (Fail-Open Fallback • ${verdict.latencyMs.toFixed(
      1
    )}ms)`;
  }

  return `🛡️ ArmorCept: Verified by ${verdict.source} (${verdict.latencyMs.toFixed(
    1
  )}ms)`;
}

/**
 * Renders unobtrusive validation states or security block alerts via the Claude Mod UI API (`$.ui`).
 */
export function notifyModUi(
  $: ClaudeModContext | undefined,
  verdict: EvaluationVerdict,
  targetLabel?: string
): void {
  const ui = $?.ui;
  if (!ui) return;

  const badge = formatStatusBadge(verdict);
  if (typeof ui.status === 'function') {
    ui.status(badge);
  } else if (typeof ui.band === 'function' && verdict.decision === 'ALLOW') {
    ui.band(badge);
  }

  if (verdict.decision === 'BLOCK') {
    const alertBanner = formatSecurityAlertBanner(verdict, targetLabel);
    if (typeof ui.render === 'function') {
      ui.render(alertBanner);
    } else if (typeof ui.band === 'function') {
      ui.band(alertBanner);
    }

    if (typeof ui.toast === 'function') {
      ui.toast(alertBanner, { type: 'error' });
    }
  } else if (verdict.failOpenTriggered && typeof ui.toast === 'function') {
    ui.toast(badge, { type: 'warning' });
  }
}
