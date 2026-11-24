/**
 * ArmorCept — In-process DLP fallback ("ts-fallback")
 *
 * A TypeScript copy of the built-in secret patterns in python/daemon.py, used
 * when the Python engine can't run so secret protection keeps working. Keep
 * the two lists in sync; tests/register.test.ts checks shared fixtures
 * against both. Custom ARMORCEPT_EXTRA_PATTERNS are Python regexes and only
 * run in the Python engine.
 */

import type { MatchSpan, PromptArmorResult } from './types';

interface FallbackPattern {
  category: string;
  regex: RegExp;
  risk: number;
  confidence: number;
  /** False when a match doesn't cover the whole secret; such matches get no span. */
  redactable: boolean;
}

const TOKEN_END = '(?![A-Za-z0-9_\\-])';

function pattern(
  source: string,
  category: string,
  risk: number,
  confidence: number,
  redactable = true
): FallbackPattern {
  return { category, regex: new RegExp(source, 'g'), risk, confidence, redactable };
}

export const FALLBACK_DLP_PATTERNS: readonly FallbackPattern[] = [
  pattern('\\b(AKIA|ASIA)[0-9A-Z]{16}\\b', 'SECRET_LEAK_AWS_ACCESS_KEY', 0.96, 0.98),
  pattern(
    '\\b(gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22,})\\b',
    'SECRET_LEAK_GITHUB_TOKEN',
    0.97,
    0.98
  ),
  pattern(
    `\\bsk-ant-[a-z]{3,5}\\d{2}-[A-Za-z0-9_\\-]{20,}${TOKEN_END}`,
    'SECRET_LEAK_ANTHROPIC_KEY',
    0.97,
    0.98
  ),
  pattern(
    `\\bsk-(proj-[A-Za-z0-9_\\-]{20,}|[A-Za-z0-9]{32,})${TOKEN_END}`,
    'SECRET_LEAK_API_KEY',
    0.96,
    0.98
  ),
  pattern(`\\bAIza[0-9A-Za-z_\\-]{35}${TOKEN_END}`, 'SECRET_LEAK_GCP_API_KEY', 0.95, 0.97),
  pattern(
    `\\bxox[abprs]-[A-Za-z0-9]{8,}(-[A-Za-z0-9]{4,})+${TOKEN_END}`,
    'SECRET_LEAK_SLACK_TOKEN',
    0.96,
    0.98
  ),
  pattern('\\b[rs]k_live_[A-Za-z0-9]{24,}\\b', 'SECRET_LEAK_STRIPE_KEY', 0.97, 0.98),
  pattern('\\bnpm_[A-Za-z0-9]{36}\\b', 'SECRET_LEAK_NPM_TOKEN', 0.96, 0.98),
  pattern(
    '-----BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED |PRIVATE )?PRIVATE KEY-----',
    'SECRET_LEAK_PRIVATE_KEY',
    0.98,
    0.99,
    false // matches only the PEM header, so the result is withheld whole
  ),
  pattern('\\b(?!000|666|9\\d{2})\\d{3}-(?!00)\\d{2}-(?!0000)\\d{4}\\b', 'DLP_US_SSN', 0.91, 0.93),
];

const MAX_SPANS = 1000;

/**
 * Scans text with the fallback patterns. The result has the same shape as an
 * engine result, with no injection findings: the fallback can't judge those.
 */
export function scanFallbackDlp(text: string): PromptArmorResult {
  const categories: string[] = [];
  const spans: MatchSpan[] = [];
  let score = 0;
  let confidence = 1;
  for (const p of FALLBACK_DLP_PATTERNS) {
    p.regex.lastIndex = 0;
    let hit = false;
    for (const m of text.matchAll(p.regex)) {
      if (m[0].length === 0) continue;
      hit = true;
      if (p.redactable && spans.length < MAX_SPANS) {
        const start = m.index ?? 0;
        spans.push({ category: p.category, start, end: start + m[0].length });
      }
    }
    if (hit) {
      categories.push(p.category);
      if (p.risk > score) {
        score = p.risk;
        confidence = p.confidence;
      }
    }
  }
  return {
    score,
    confidence,
    decision: score >= 0.75 ? 'BLOCK' : 'ALLOW',
    findings: categories,
    dlpCategories: categories,
    dlpSpans: spans,
  };
}
