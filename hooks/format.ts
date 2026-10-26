/**
 * ArmorCept — Formatting, Safe UI Helpers, and Payload Serialization
 */

import type { ArmorCeptMode, EvaluationVerdict, RuntimeConfig } from './types';

const RESERVED_TOOL_ENVELOPE_KEYS = new Set([
  'tool',
  'tool_name',
  'tool_use_id',
  'agentId',
  'consent',
  'requestMeta',
]);

export function safeUi(fn: () => unknown): void {
  try {
    fn();
  } catch {
    // Never allow a UI surface error to interrupt a security gate
  }
}

export function getStatusBadge(
  mode: ArmorCeptMode,
  engineMode?: 'full' | 'lightweight_fallback'
): string {
  if (engineMode === 'lightweight_fallback') {
    return '🛡️ ArmorCept: Active (Local - Lightweight Test Mode)';
  }
  const label =
    mode === 'LOCAL' ? 'Local' : mode === 'CLOUD' ? 'Cloud' : 'Waterfall';
  return `🛡️ ArmorCept: Active (${label})`;
}

export function formatAlertBanner(
  verdict: EvaluationVerdict,
  toolName?: string
): string {
  const extraFindings = verdict.findings.filter((f) => f !== verdict.reason);
  const findingsSuffix =
    extraFindings.length > 0 ? ` [${extraFindings.join(', ')}]` : '';
  const scoreSuffix =
    typeof verdict.score === 'number' && Number.isFinite(verdict.score)
      ? ` (score: ${verdict.score.toFixed(2)}${
          typeof verdict.confidence === 'number' &&
          Number.isFinite(verdict.confidence)
            ? `, confidence: ${verdict.confidence.toFixed(2)}`
            : ''
        })`
      : '';
  const targetPrefix = toolName ? `Tool (${toolName}) — ` : '';
  const actionLabel = verdict.decision === 'WARN' ? 'Warning' : 'Blocked';
  return `🛡️ [ArmorCept ${actionLabel}] Source: ${verdict.source} | Reason: ${targetPrefix}${verdict.reason}${findingsSuffix}${scoreSuffix}`;
}

export function formatToolDenyMessage(
  verdict: EvaluationVerdict,
  toolName: string
): string {
  const details =
    verdict.findings.length > 0
      ? verdict.findings.join(', ')
      : verdict.reason;
  return `Tool execution blocked by ArmorCept security policy (${verdict.source}) for tool "${toolName}": ${details}. Do not retry this tool call with sensitive data or unsafe instructions.`;
}

export function formatToolResultWithheldMessage(
  verdict: EvaluationVerdict,
  toolName: string
): string {
  const details =
    verdict.findings.length > 0
      ? verdict.findings.join(', ')
      : verdict.reason;
  return `Tool "${toolName}" output withheld by ArmorCept security policy (${verdict.source}): ${details}.`;
}

export function extractToolPayload(e: Record<string, unknown>): {
  toolName: string;
  serializedPayload: string;
  filePath?: string;
} {
  const toolName = String(e['tool'] ?? e['tool_name'] ?? 'UnknownTool');
  const argsCopy: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(e)) {
    if (!RESERVED_TOOL_ENVELOPE_KEYS.has(k)) {
      argsCopy[k] = v;
    }
  }
  const rawPath =
    argsCopy['file_path'] ?? argsCopy['path'] ?? argsCopy['notebook_path'];
  const filePath = typeof rawPath === 'string' ? rawPath : undefined;

  return {
    toolName,
    serializedPayload: `Tool: ${toolName}\nArguments: ${JSON.stringify(
      argsCopy,
      null,
      2
    )}`,
    filePath,
  };
}

export function normalizeAllowlistCandidatePath(
  rawPath: string
): string | undefined {
  if (!rawPath || rawPath.includes('\0')) {
    return undefined;
  }
  const posix = rawPath.replace(/\\/g, '/').trim();
  if (!posix) {
    return undefined;
  }

  // Handle Windows drive letter prefix (e.g. C:/...) or leading slash
  const driveMatch = /^([A-Za-z]:)(\/.*|$)/.exec(posix);
  const prefix = driveMatch
    ? `${driveMatch[1]}/`
    : posix.startsWith('/')
      ? '/'
      : '';
  const remainder = driveMatch
    ? (driveMatch[2] ?? '')
    : posix.startsWith('/')
      ? posix.slice(1)
      : posix;

  const segments = remainder.split('/');
  const resolved: string[] = [];

  for (const seg of segments) {
    if (!seg || seg === '.') {
      continue;
    }
    if (seg === '..') {
      if (resolved.length === 0) {
        // Relative path escaping above root — refuse to allowlist
        if (!prefix) {
          return undefined;
        }
        continue;
      }
      resolved.pop();
      continue;
    }
    resolved.push(seg);
  }

  if (!prefix && resolved.length === 0) {
    return undefined;
  }
  return `${prefix}${resolved.join('/')}`;
}

function globToRegExp(glob: string): RegExp {
  let normalized = glob.replace(/\\/g, '/').trim();
  while (normalized.startsWith('./')) {
    normalized = normalized.slice(2);
  }

  const anchored = normalized.startsWith('/');
  if (anchored) {
    normalized = normalized.replace(/^\/+/, '');
  }

  let regexStr = anchored ? '^/' : '(?:^|/)';
  let i = 0;
  while (i < normalized.length) {
    // Handle "/**/" in the middle of a pattern
    if (normalized.startsWith('/**/', i)) {
      regexStr += '/(?:.+/)?';
      i += 4;
      continue;
    }
    // Handle trailing "/**"
    if (normalized.slice(i) === '/**') {
      regexStr += '(?:/.*)?';
      i += 3;
      continue;
    }
    // Handle leading "**/"
    if (i === 0 && normalized.startsWith('**/')) {
      regexStr += '(?:.+/)?';
      i += 3;
      continue;
    }
    const ch = normalized[i];
    if (ch === '*') {
      if (normalized[i + 1] === '*') {
        regexStr += '.*';
        i += 2;
        continue;
      }
      regexStr += '[^/]*';
      i += 1;
      continue;
    }
    if (ch === '?') {
      regexStr += '[^/]';
      i += 1;
      continue;
    }
    if (ch && /[.+^${}()|[\]\\]/.test(ch)) {
      regexStr += `\\${ch}`;
    } else if (ch) {
      regexStr += ch;
    }
    i += 1;
  }
  regexStr += '$';
  return new RegExp(regexStr);
}

export function matchesAllowlistPath(
  filePath: string,
  allowlistPatterns: readonly string[]
): boolean {
  if (!filePath || allowlistPatterns.length === 0) return false;
  const normalizedPath = normalizeAllowlistCandidatePath(filePath);
  if (!normalizedPath) return false;

  for (const rawPattern of allowlistPatterns) {
    const pattern = rawPattern.trim();
    if (!pattern) continue;
    const re = globToRegExp(pattern);
    if (re.test(normalizedPath)) {
      return true;
    }
  }
  return false;
}

const BUILTIN_EXEMPT_TOOLS = new Set(['askuserquestion']);

export function isToolCallExempt(
  toolName: string,
  filePath: string | undefined,
  cfg: RuntimeConfig
): boolean {
  const lowerTool = toolName.toLowerCase();
  if (BUILTIN_EXEMPT_TOOLS.has(lowerTool)) {
    return true;
  }
  if (cfg.exemptTools.some((t) => t.toLowerCase() === lowerTool)) {
    return true;
  }
  if (filePath && matchesAllowlistPath(filePath, cfg.allowlistPaths)) {
    return true;
  }
  return false;
}
