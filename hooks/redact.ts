/**
 * ArmorCept — Redaction of DLP and secret matches in tool results
 * (ARMORCEPT_TOOL_RESULT_ACTION=redact)
 *
 * Only findings with a known span can be redacted. Prompt-injection and cloud
 * findings have no reliable span, so a result containing one is withheld.
 */

import type { EngineInterface } from 'claude-code';
import { evaluateArmorCept } from './orchestrator';
import type { EvaluationVerdict, MatchSpan } from './types';

/** Rounds of redact-then-rescan before giving up and withholding. */
const MAX_REDACTION_ROUNDS = 3;

export function redactionLabel(category: string): string {
  return `[REDACTED:${category}]`;
}

/**
 * Merges overlapping or touching spans (from overlapping chunks, or several
 * patterns matching the same token). The merged span keeps the category of
 * its longest member.
 */
export function mergeSpans(spans: readonly MatchSpan[]): MatchSpan[] {
  const sorted = [...spans]
    .filter((s) => s.end > s.start)
    .sort((a, b) => a.start - b.start || b.end - a.end);
  const out: (MatchSpan & { longest: number })[] = [];
  for (const span of sorted) {
    const last = out[out.length - 1];
    if (last && span.start <= last.end) {
      if (span.end - span.start > last.longest) {
        last.category = span.category;
        last.longest = span.end - span.start;
      }
      last.end = Math.max(last.end, span.end);
    } else {
      out.push({ ...span, longest: span.end - span.start });
    }
  }
  return out.map(({ category, start, end }) => ({ category, start, end }));
}

export function applyRedactions(text: string, spans: readonly MatchSpan[]): string {
  let out = '';
  let cursor = 0;
  for (const span of mergeSpans(spans)) {
    const start = Math.min(Math.max(span.start, cursor), text.length);
    const end = Math.min(span.end, text.length);
    if (end <= start) continue;
    out += text.slice(cursor, start) + redactionLabel(span.category);
    cursor = end;
  }
  return out + text.slice(cursor);
}

/** A BLOCK can be redacted only when every finding is a category with a known span. */
export function isRedactable(verdict: EvaluationVerdict): boolean {
  const spans = verdict.spans ?? [];
  if (verdict.decision !== 'BLOCK' || spans.length === 0) return false;
  const spanned = new Set(spans.map((s) => s.category));
  return verdict.findings.length > 0 && verdict.findings.every((f) => spanned.has(f));
}

export type RedactionOutcome =
  | { kind: 'redacted'; text: string; categories: string[]; verdict: EvaluationVerdict }
  | { kind: 'withhold'; verdict: EvaluationVerdict };

/**
 * Redacts the spans of a redactable verdict, then rescans: the remaining text
 * may hold a finding the first verdict didn't report (an exact secret match
 * returns before the engine runs, for example). Withholds if a finding can't
 * be redacted, or if matches remain after MAX_REDACTION_ROUNDS.
 */
export async function redactText(
  $: EngineInterface,
  text: string,
  firstVerdict: EvaluationVerdict
): Promise<RedactionOutcome> {
  let verdict = firstVerdict;
  let current = text;
  const categories = new Set<string>();
  for (let round = 0; round < MAX_REDACTION_ROUNDS; round += 1) {
    if (verdict.decision !== 'BLOCK') {
      return { kind: 'redacted', text: current, categories: [...categories], verdict };
    }
    if (!isRedactable(verdict)) {
      return { kind: 'withhold', verdict };
    }
    for (const span of verdict.spans ?? []) categories.add(span.category);
    current = applyRedactions(current, verdict.spans ?? []);
    verdict = await evaluateArmorCept($, current);
  }
  if (verdict.decision !== 'BLOCK') {
    return { kind: 'redacted', text: current, categories: [...categories], verdict };
  }
  return { kind: 'withhold', verdict };
}
