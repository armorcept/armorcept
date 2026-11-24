/**
 * ArmorCept — Exact-value secret matching (ARMORCEPT_SECRET_ENV_VARS)
 *
 * The values of the named environment variables are read once per config load
 * and held only in this module's memory. They are never logged, displayed,
 * returned in a verdict, or sent to any engine: matching happens here, in the
 * hook process, before any payload leaves it.
 */

import type { EngineInterface } from 'claude-code';

export const MIN_EXACT_SECRET_LENGTH = 16;

export type SecretEncoding = 'raw' | 'base64' | 'url' | 'json' | 'split';

export interface SecretMatch {
  /** Environment variable name whose value matched. */
  name: string;
  /** Category reported in verdicts: SECRET_EXACT_<NAME>. */
  category: string;
  encoding: SecretEncoding;
  /** Span in the scanned text, as UTF-16 offsets. */
  start: number;
  end: number;
}

interface Needle {
  name: string;
  text: string;
  encoding: SecretEncoding;
}

let needles: Needle[] = [];
let loadedNames: string[] = [];

export function exactSecretCategory(name: string): string {
  return `SECRET_EXACT_${name.toUpperCase()}`;
}

export function getLoadedExactSecretNames(): readonly string[] {
  return loadedNames;
}

export function clearExactSecrets(): void {
  needles = [];
  loadedNames = [];
}

const B64_ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

// Pure implementations: the hook sandbox guarantees ES2023 globals only.
function utf8Bytes(value: string): number[] {
  const bytes: number[] = [];
  for (const ch of value) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp < 0x80) bytes.push(cp);
    else if (cp < 0x800) bytes.push(0xc0 | (cp >> 6), 0x80 | (cp & 63));
    else if (cp < 0x10000)
      bytes.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
    else
      bytes.push(
        0xf0 | (cp >> 18),
        0x80 | ((cp >> 12) & 63),
        0x80 | ((cp >> 6) & 63),
        0x80 | (cp & 63)
      );
  }
  return bytes;
}

function toBase64(bytes: readonly number[]): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i] ?? 0;
    const b1 = bytes[i + 1] ?? 0;
    const b2 = bytes[i + 2] ?? 0;
    const n = (b0 << 16) | (b1 << 8) | b2;
    out += B64_ALPHABET[(n >> 18) & 63];
    out += B64_ALPHABET[(n >> 12) & 63];
    if (i + 1 < bytes.length) out += B64_ALPHABET[(n >> 6) & 63];
    if (i + 2 < bytes.length) out += B64_ALPHABET[n & 63];
  }
  return out;
}

/**
 * Base64 of the value as it would appear inside a larger base64 stream. The
 * value can start at any of three byte offsets within a 3-byte group, and each
 * gives different characters; only the characters that depend solely on the
 * value's own bytes are kept.
 */
function base64Variants(value: string): string[] {
  const bytes = utf8Bytes(value);
  const out = new Set<string>();
  for (let k = 0; k < 3; k += 1) {
    const encoded = toBase64([...new Array<number>(k).fill(0), ...bytes]);
    const first = Math.ceil((4 * k) / 3);
    const last = Math.floor((8 * (k + bytes.length)) / 6);
    const stable = encoded.slice(first, last);
    if (stable.length >= MIN_EXACT_SECRET_LENGTH) {
      out.add(stable);
      out.add(stable.replace(/\+/g, '-').replace(/\//g, '_'));
    }
  }
  return [...out];
}

function urlVariants(value: string): string[] {
  const upper = encodeURIComponent(value);
  const out = new Set<string>([
    upper,
    upper.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase()),
    upper.replace(/%20/g, '+'),
  ]);
  out.delete(value);
  return [...out];
}

/**
 * Loads the secret values to match. Empty values and values shorter than
 * MIN_EXACT_SECRET_LENGTH are skipped, so short or unset variables never cause
 * matches on ordinary text.
 */
export function setExactSecrets(
  entries: readonly { name: string; value: string | undefined }[]
): void {
  const next: Needle[] = [];
  const names: string[] = [];
  for (const { name, value } of entries) {
    if (typeof value !== 'string') continue;
    const trimmed = value.trim();
    if (trimmed.length < MIN_EXACT_SECRET_LENGTH) continue;
    names.push(name);
    const variants = new Map<string, SecretEncoding>();
    variants.set(trimmed, 'raw');
    const json = JSON.stringify(trimmed).slice(1, -1);
    if (!variants.has(json)) variants.set(json, 'json');
    for (const v of base64Variants(trimmed)) {
      if (!variants.has(v)) variants.set(v, 'base64');
    }
    for (const v of urlVariants(trimmed)) {
      if (!variants.has(v)) variants.set(v, 'url');
    }
    for (const [text, encoding] of variants) {
      next.push({ name, text, encoding });
    }
  }
  needles = next;
  loadedNames = names;
}

// A line break inside a secret: a real newline (optionally CR) or its JSON
// escape, followed by any indentation the wrapping added.
const LINE_BREAK_RE = /(?:\r?\n|\\r\\n|\\n)[ \t]*/g;

/** Removes line breaks and returns the squashed text with an index map back to the original. */
function squashLineBreaks(text: string): { squashed: string; map: number[] } | undefined {
  LINE_BREAK_RE.lastIndex = 0;
  if (!LINE_BREAK_RE.test(text)) return undefined;
  LINE_BREAK_RE.lastIndex = 0;
  const parts: string[] = [];
  const map: number[] = [];
  let cursor = 0;
  for (const m of text.matchAll(LINE_BREAK_RE)) {
    const idx = m.index ?? 0;
    parts.push(text.slice(cursor, idx));
    for (let i = cursor; i < idx; i += 1) map.push(i);
    cursor = idx + m[0].length;
  }
  parts.push(text.slice(cursor));
  for (let i = cursor; i < text.length; i += 1) map.push(i);
  return { squashed: parts.join(''), map };
}

function overlaps(a: { start: number; end: number }, list: SecretMatch[]): boolean {
  return list.some((b) => a.start < b.end && b.start < a.end);
}

/** Finds every occurrence of a loaded secret value, in any supported encoding. */
export function findExactSecrets(text: string): SecretMatch[] {
  if (needles.length === 0 || !text) return [];
  const matches: SecretMatch[] = [];
  for (const needle of needles) {
    let from = 0;
    for (;;) {
      const idx = text.indexOf(needle.text, from);
      if (idx === -1) break;
      const span = { start: idx, end: idx + needle.text.length };
      if (!overlaps(span, matches)) {
        matches.push({
          name: needle.name,
          category: exactSecretCategory(needle.name),
          encoding: needle.encoding,
          ...span,
        });
      }
      from = idx + 1;
    }
  }

  const squashed = squashLineBreaks(text);
  if (squashed) {
    for (const needle of needles) {
      if (needle.encoding !== 'raw' && needle.encoding !== 'base64') continue;
      let from = 0;
      for (;;) {
        const idx = squashed.squashed.indexOf(needle.text, from);
        if (idx === -1) break;
        const start = squashed.map[idx] ?? 0;
        const end = (squashed.map[idx + needle.text.length - 1] ?? start) + 1;
        const span = { start, end };
        if (!overlaps(span, matches)) {
          matches.push({
            name: needle.name,
            category: exactSecretCategory(needle.name),
            encoding: 'split',
            ...span,
          });
        }
        from = idx + 1;
      }
    }
  }

  return matches.sort((a, b) => a.start - b.start);
}

const READ_ENV_TIMEOUT_MS = 3000;
const PY_READ_ENV =
  'import json,os,sys;print(json.dumps({n:os.environ.get(n) for n in sys.argv[1:]}))';

/**
 * Reads the values of the named environment variables. Hook modules can only
 * call $.env.get with a literal name, so the values are read by a short-lived
 * local child process (printenv, or the engine's Python interpreter where
 * printenv is unavailable) and returned over its stdout.
 */
export async function readEnvValues(
  $: EngineInterface,
  names: readonly string[],
  pythonBinary: string
): Promise<{ name: string; value: string | undefined }[]> {
  if (names.length === 0) return [];
  try {
    const out: { name: string; value: string | undefined }[] = [];
    for (const name of names) {
      const res = await $.process.run(['printenv', name], {
        timeoutMs: READ_ENV_TIMEOUT_MS,
      });
      out.push({
        name,
        value: res.exitCode === 0 ? res.stdout.replace(/\r?\n$/, '') : undefined,
      });
    }
    return out;
  } catch {
    // printenv missing (e.g. Windows): fall through to Python
  }
  try {
    const res = await $.process.run(
      [pythonBinary, '-I', '-c', PY_READ_ENV, ...names],
      { timeoutMs: READ_ENV_TIMEOUT_MS }
    );
    if (res.exitCode === 0) {
      const parsed = JSON.parse(res.stdout.trim()) as Record<string, unknown>;
      return names.map((name) => ({
        name,
        value: typeof parsed[name] === 'string' ? (parsed[name] as string) : undefined,
      }));
    }
  } catch {
    // Neither reader worked
  }
  throw new Error(
    'ARMORCEPT_SECRET_ENV_VARS is set but the variable values could not be read (no printenv or python3 available).'
  );
}
