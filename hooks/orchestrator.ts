/**
 * ArmorCept — Hybrid Waterfall & Mode Orchestrator
 */

import type { EngineInterface } from 'claude-code';
import { getLastKnownFailOpen, readRuntimeConfig } from './config';
import { runModelArmor, runPromptArmor } from './engines';
import {
  buildHealthRecord,
  getSessionId,
  recordDecision,
} from './decisions';
import { scanFallbackDlp } from './dlp';
import { getStatusBadge, safeUi } from './format';
import { findExactSecrets, type SecretMatch } from './secrets';
import type {
  ArmorCeptMode,
  EvaluationVerdict,
  MatchSpan,
  PromptArmorDecision,
  PromptArmorResult,
  RuntimeConfig,
} from './types';

// Local chunks stay small because prompt-armor's L1 regex layer has a 0.1 s
// per-rule budget and silently skips rules on larger inputs. Model Armor has
// no such budget, so the cloud pass uses larger chunks and far fewer calls.
const MAX_LOCAL_SCAN_CHUNK_CHARS = 8_192;
const MAX_CLOUD_SCAN_CHUNK_CHARS = 32_768;
const CHUNK_OVERLAP_CHARS = 512;
const MAX_TOTAL_SCAN_CHARS = 524_288;

// prompt-armor only produces the result in full mode, and even then the DLP
// and secret findings come from ArmorCept's own patterns merged in by the daemon.
export function localVerdictSource(
  local: PromptArmorResult
): EvaluationVerdict['source'] {
  if (local.engine_mode === 'lightweight_fallback') {
    return 'ArmorCept Built-in';
  }
  const isPureDlpHit =
    local.dlpCategories.length > 0 &&
    local.findings.length > 0 &&
    local.findings.every((f) => local.dlpCategories.includes(f));
  return isPureDlpHit ? 'ArmorCept DLP' : 'Prompt-Armor';
}

export function evaluateLocalVerdict(
  local: PromptArmorResult,
  cfg: RuntimeConfig
): EvaluationVerdict {
  const isPureDlpHit =
    local.dlpCategories.length > 0 &&
    local.findings.length > 0 &&
    local.findings.every((f) => local.dlpCategories.includes(f));

  if (isPureDlpHit) {
    const primaryDlp = local.findings[0] ?? 'Local DLP policy match';
    if (cfg.localDlpAction === 'allow') {
      return {
        decision: 'ALLOW',
        source: localVerdictSource(local),
        mode: 'LOCAL',
        reason: `Local DLP match allowed by ARMORCEPT_LOCAL_DLP_ACTION=allow (${primaryDlp})`,
        findings: local.findings,
        score: local.score,
        confidence: local.confidence,
        engineMode: local.engine_mode,
        warning: local.warning,
        spans: local.dlpSpans,
      };
    }
    if (cfg.localDlpAction === 'warn') {
      return {
        decision: 'WARN',
        source: localVerdictSource(local),
        mode: 'LOCAL',
        reason: primaryDlp,
        findings: local.findings,
        score: local.score,
        confidence: local.confidence,
        engineMode: local.engine_mode,
        warning: local.warning,
        spans: local.dlpSpans,
      };
    }
  }

  const blocked =
    local.decision === 'BLOCK' || local.score >= cfg.waterfallBlockAbove;
  if (blocked) {
    const reason =
      local.findings[0] ??
      `Local threat score ${local.score.toFixed(2)} exceeded threshold`;
    return {
      decision: 'BLOCK',
      source: localVerdictSource(local),
      mode: 'LOCAL',
      reason,
      findings: local.findings.length > 0 ? local.findings : [reason],
      score: local.score,
      confidence: local.confidence,
      engineMode: local.engine_mode,
      warning: local.warning,
      spans: local.dlpSpans,
    };
  }

  if (
    local.decision === 'WARN' ||
    local.decision === 'ESCALATE' ||
    local.score >= cfg.waterfallAllowBelow
  ) {
    const reason =
      local.findings[0] ??
      `Elevated local risk score ${local.score.toFixed(2)}`;
    return {
      decision: 'WARN',
      source: localVerdictSource(local),
      mode: 'LOCAL',
      reason,
      findings: local.findings.length > 0 ? local.findings : [reason],
      score: local.score,
      confidence: local.confidence,
      engineMode: local.engine_mode,
      warning: local.warning,
      spans: local.dlpSpans,
    };
  }

  return {
    decision: 'ALLOW',
    source: localVerdictSource(local),
    mode: 'LOCAL',
    reason: `Clean payload verified by local ${localVerdictSource(local)}`,
    findings: local.findings,
    score: local.score,
    confidence: local.confidence,
    engineMode: local.engine_mode,
    warning: local.warning,
    spans: local.dlpSpans,
  };
}

const DECISION_RANK: Record<PromptArmorDecision, number> = {
  ALLOW: 0,
  WARN: 1,
  ESCALATE: 2,
  BLOCK: 3,
};

function mergeLocalResults(
  a: PromptArmorResult | undefined,
  b: PromptArmorResult
): PromptArmorResult {
  if (!a) return b;
  const worse = b.score > a.score ? b : a;
  const decision =
    DECISION_RANK[b.decision] > DECISION_RANK[a.decision]
      ? b.decision
      : a.decision;
  const lightweight =
    a.engine_mode === 'lightweight_fallback' ||
    b.engine_mode === 'lightweight_fallback';
  return {
    score: worse.score,
    confidence: worse.confidence,
    decision,
    findings: Array.from(new Set([...a.findings, ...b.findings])),
    dlpCategories: Array.from(
      new Set([...a.dlpCategories, ...b.dlpCategories])
    ),
    dlpSpans: [...(a.dlpSpans ?? []), ...(b.dlpSpans ?? [])],
    latency_ms: (a.latency_ms ?? 0) + (b.latency_ms ?? 0),
    engine_mode: lightweight
      ? 'lightweight_fallback'
      : (a.engine_mode ?? b.engine_mode),
    warning: a.warning ?? b.warning,
  };
}

function isInjectionBlock(result: PromptArmorResult): boolean {
  return (
    result.decision === 'BLOCK' &&
    result.findings.some((f) => !result.dlpCategories.includes(f))
  );
}

async function runLocalPass(
  $: EngineInterface,
  text: string,
  cfg: RuntimeConfig
): Promise<PromptArmorResult> {
  let merged: PromptArmorResult | undefined;
  for (const { chunk, offset } of chunkWithOffsets(
    text,
    MAX_LOCAL_SCAN_CHUNK_CHARS
  )) {
    const raw = await runPromptArmor($, chunk, cfg);
    // Chunk-relative spans become offsets into the whole text
    const result: PromptArmorResult = {
      ...raw,
      dlpSpans: (raw.dlpSpans ?? []).map((s) => ({
        ...s,
        start: s.start + offset,
        end: s.end + offset,
      })),
    };
    merged = mergeLocalResults(merged, result);
    const decisive =
      cfg.mode === 'LOCAL' || result.confidence >= cfg.waterfallMinConfidence;
    if (isInjectionBlock(result) && decisive) {
      break;
    }
  }
  const local = merged ?? (await runPromptArmor($, text, cfg));
  if (local.engine_mode === 'lightweight_fallback' && local.warning) {
    safeUi(() =>
      $.ui.toast(`⚠️ ArmorCept: ${local.warning}`, { timeoutMs: 6000 })
    );
  }
  return local;
}

async function runCloudPass(
  $: EngineInterface,
  text: string,
  cfg: RuntimeConfig,
  escalatedToCloud: boolean
): Promise<EvaluationVerdict> {
  let last: EvaluationVerdict | undefined;
  for (const chunk of splitIntoChunks(text, MAX_CLOUD_SCAN_CHUNK_CHARS)) {
    const verdict = await runModelArmor($, chunk, cfg, escalatedToCloud);
    if (verdict.decision === 'BLOCK') {
      return verdict;
    }
    last = verdict;
  }
  return last ?? (await runModelArmor($, text, cfg, escalatedToCloud));
}

async function evaluateText(
  $: EngineInterface,
  text: string,
  cfg: RuntimeConfig
): Promise<EvaluationVerdict> {
  if (cfg.mode === 'CLOUD') {
    return await runCloudPass($, text, cfg, false);
  }

  let local: PromptArmorResult;
  try {
    local = await runGuardedLocalPass($, text, cfg);
  } catch (err) {
    return await engineUnavailableVerdict($, text, cfg, err);
  }

  if (cfg.mode === 'LOCAL') {
    return evaluateLocalVerdict(local, cfg);
  }

  // WATERFALL mode
  const highConfidenceBlock =
    (local.score >= cfg.waterfallBlockAbove &&
      local.confidence >= cfg.waterfallMinConfidence) ||
    (local.decision === 'BLOCK' &&
      local.confidence >= cfg.waterfallMinConfidence);

  if (highConfidenceBlock) {
    const reason =
      local.findings[0] ??
      `High-confidence local threat (score: ${local.score.toFixed(
        2
      )}, confidence: ${local.confidence.toFixed(2)})`;
    return {
      decision: 'BLOCK',
      source: localVerdictSource(local),
      mode: 'WATERFALL',
      reason,
      findings: local.findings.length > 0 ? local.findings : [reason],
      score: local.score,
      confidence: local.confidence,
      escalatedToCloud: false,
      engineMode: local.engine_mode,
      warning: local.warning,
      spans: local.dlpSpans,
    };
  }

  const lowRiskAndConfident =
    local.score < cfg.waterfallAllowBelow &&
    local.confidence >= cfg.waterfallMinConfidence &&
    local.decision === 'ALLOW';

  if (lowRiskAndConfident && !cfg.waterfallAlwaysRunCloudDlp) {
    return {
      decision: 'ALLOW',
      source: localVerdictSource(local),
      mode: 'WATERFALL',
      reason: 'Fast-path local ALLOW (low risk, high confidence)',
      findings: local.findings,
      score: local.score,
      confidence: local.confidence,
      escalatedToCloud: false,
      engineMode: local.engine_mode,
      warning: local.warning,
      spans: local.dlpSpans,
    };
  }

  return await runCloudPass($, text, cfg, true);
}

// ---------------------------------------------------------------------------
// Engine health, circuit breaker and the in-process fallback (#5)
// ---------------------------------------------------------------------------

/** Consecutive local-engine failures that open the circuit breaker. */
const BREAKER_THRESHOLD = 3;
/** How long the breaker skips the engine before trying it again. */
const BREAKER_COOLDOWN_MS = 30_000;

let engineHealthy = true;
let consecutiveEngineFailures = 0;
let breakerOpenUntilMs = 0;
let lastEngineFailure = '';

export function resetFallbackState(): void {
  engineHealthy = true;
  consecutiveEngineFailures = 0;
  breakerOpenUntilMs = 0;
  lastEngineFailure = '';
}

export class EngineUnavailableError extends Error {}

/** A short, single-line reason, scrubbed of any loaded secret value. */
function shortReason(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  const firstLine = message.split('\n').find((l) => l.trim() !== '') ?? message;
  let reason = firstLine.trim().slice(0, 160);
  for (const hit of findExactSecrets(reason).reverse()) {
    reason = `${reason.slice(0, hit.start)}[REDACTED:${hit.category}]${reason.slice(hit.end)}`;
  }
  return reason || 'unknown error';
}

async function logHealth(
  $: EngineInterface,
  cfg: RuntimeConfig,
  event: 'engine_unavailable' | 'engine_recovered',
  reason?: string
): Promise<void> {
  if (!cfg.decisionLogPath) return;
  try {
    recordDecision($, cfg, buildHealthRecord(cfg, event, reason, await getSessionId($)));
  } catch {
    // Health logging never affects a decision
  }
}

async function noteEngineFailure(
  $: EngineInterface,
  cfg: RuntimeConfig,
  reason: string
): Promise<void> {
  consecutiveEngineFailures += 1;
  lastEngineFailure = reason;
  if (consecutiveEngineFailures >= BREAKER_THRESHOLD) {
    breakerOpenUntilMs = Date.now() + BREAKER_COOLDOWN_MS;
  }
  if (engineHealthy) {
    engineHealthy = false;
    const injection =
      cfg.mode === 'WATERFALL'
        ? 'injection scanning continues in Model Armor'
        : cfg.failOpen
          ? 'injection scanning is skipped (ARMORCEPT_FAIL_OPEN=true)'
          : 'other actions are blocked until it recovers';
    safeUi(() =>
      $.ui.toast(
        `⚠️ ArmorCept engine unavailable (${reason}). Secret checks continue in-process; ${injection}.`,
        { timeoutMs: 8000 }
      )
    );
    safeUi(() => $.ui.status(getStatusBadge(cfg.mode, 'ts-fallback')));
    await logHealth($, cfg, 'engine_unavailable', reason);
  }
}

async function noteEngineSuccess($: EngineInterface, cfg: RuntimeConfig): Promise<void> {
  consecutiveEngineFailures = 0;
  breakerOpenUntilMs = 0;
  if (!engineHealthy) {
    engineHealthy = true;
    lastEngineFailure = '';
    safeUi(() => $.ui.toast('🛡️ ArmorCept engine recovered', { timeoutMs: 4000 }));
    await logHealth($, cfg, 'engine_recovered');
  }
}

async function runGuardedLocalPass(
  $: EngineInterface,
  text: string,
  cfg: RuntimeConfig
): Promise<PromptArmorResult> {
  if (Date.now() < breakerOpenUntilMs) {
    throw new EngineUnavailableError(
      `${lastEngineFailure || 'repeated failures'}; ${consecutiveEngineFailures} failures in a row, retrying in ${Math.ceil(
        (breakerOpenUntilMs - Date.now()) / 1000
      )}s`
    );
  }
  try {
    const local = await runLocalPass($, text, cfg);
    await noteEngineSuccess($, cfg);
    return local;
  } catch (err) {
    await noteEngineFailure($, cfg, shortReason(err));
    throw err;
  }
}

/**
 * The Python engine couldn't produce a result. Secrets are still checked with
 * the in-process patterns; injection goes to Model Armor in WATERFALL mode,
 * and otherwise follows ARMORCEPT_FAIL_OPEN.
 */
async function engineUnavailableVerdict(
  $: EngineInterface,
  text: string,
  cfg: RuntimeConfig,
  err: unknown
): Promise<EvaluationVerdict> {
  const reason = shortReason(err);
  const unavailable = `ArmorCept engine unavailable (${reason})`;

  const dlp: PromptArmorResult = { ...scanFallbackDlp(text), engine_mode: 'ts-fallback' };
  let dlpVerdict: EvaluationVerdict | undefined;
  if (dlp.findings.length > 0) {
    dlpVerdict = {
      ...evaluateLocalVerdict(dlp, cfg),
      mode: cfg.mode,
      source: 'ArmorCept DLP',
      engineMode: 'ts-fallback',
      warning: unavailable,
    };
    if (dlpVerdict.decision === 'BLOCK') {
      return dlpVerdict;
    }
  }

  if (cfg.mode === 'WATERFALL') {
    const cloud = await runCloudPass($, text, cfg, true);
    return { ...cloud, engineMode: 'ts-fallback', warning: unavailable };
  }

  if (cfg.failOpen) {
    if (dlpVerdict) {
      return { ...dlpVerdict, reason: `${dlpVerdict.reason}; ${unavailable}` };
    }
    return {
      decision: 'ALLOW',
      source: 'ArmorCept',
      mode: cfg.mode,
      reason: `${unavailable}; injection scanning skipped (ARMORCEPT_FAIL_OPEN=true)`,
      findings: [],
      engineMode: 'ts-fallback',
      warning: unavailable,
    };
  }

  const message = err instanceof Error ? err.message : String(err);
  return {
    decision: 'BLOCK',
    source: 'ArmorCept',
    mode: cfg.mode,
    reason: unavailable,
    findings: [`EngineError: ${shortReason(message)}`],
    engineMode: 'ts-fallback',
    warning: unavailable,
  };
}

export function chunkWithOffsets(
  text: string,
  chunkSize = MAX_LOCAL_SCAN_CHUNK_CHARS
): { chunk: string; offset: number }[] {
  if (text.length <= chunkSize) {
    return [{ chunk: text, offset: 0 }];
  }
  const chunks: { chunk: string; offset: number }[] = [];
  const step = Math.max(1024, chunkSize - CHUNK_OVERLAP_CHARS);
  for (let offset = 0; offset < text.length; offset += step) {
    chunks.push({ chunk: text.slice(offset, offset + chunkSize), offset });
    if (offset + chunkSize >= text.length) break;
  }
  return chunks;
}

export function splitIntoChunks(
  text: string,
  chunkSize = MAX_LOCAL_SCAN_CHUNK_CHARS
): string[] {
  return chunkWithOffsets(text, chunkSize).map((c) => c.chunk);
}

/** Builds a BLOCK verdict for exact secret matches without ever including the value. */
export function exactSecretVerdict(
  matches: readonly SecretMatch[],
  mode: ArmorCeptMode
): EvaluationVerdict {
  const categories = Array.from(new Set(matches.map((m) => m.category)));
  const first = matches[0];
  const where = first
    ? ` (${first.encoding} at offset ${first.start}${matches.length > 1 ? `, ${matches.length} matches` : ''})`
    : '';
  const spans: MatchSpan[] = matches.map((m) => ({
    category: m.category,
    start: m.start,
    end: m.end,
  }));
  return {
    decision: 'BLOCK',
    source: 'ArmorCept Secrets',
    mode,
    reason: `Exact value of $${first?.name ?? 'secret'} found${where}`,
    findings: categories,
    score: 1,
    confidence: 1,
    spans,
  };
}

export async function evaluateArmorCept(
  $: EngineInterface,
  text: string
): Promise<EvaluationVerdict> {
  let effectiveMode: ArmorCeptMode = 'LOCAL';
  let effectiveFailOpen = getLastKnownFailOpen();

  try {
    const cfg = await readRuntimeConfig($);
    effectiveMode = cfg.mode;
    effectiveFailOpen = cfg.failOpen;

    safeUi(() => $.ui.status('🛡️ ArmorCept: Scanning...'));

    // Exact secret values are checked locally first, so they are caught even
    // in CLOUD mode and never sent to an engine.
    const exact = findExactSecrets(text);
    if (exact.length > 0) {
      return exactSecretVerdict(exact, cfg.mode);
    }

    if (text.length > MAX_TOTAL_SCAN_CHARS) {
      throw new Error(
        `Payload length (${text.length} chars) exceeds maximum scan limit (${MAX_TOTAL_SCAN_CHARS} chars)`
      );
    }

    return await evaluateText($, text, cfg);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (effectiveFailOpen) {
      return {
        decision: 'ALLOW',
        source: 'ArmorCept',
        mode: effectiveMode,
        reason: `Fail-open triggered after engine error: ${message}`,
        findings: [`EngineError: ${message}`],
      };
    }
    return {
      decision: 'BLOCK',
      source: 'ArmorCept',
      mode: effectiveMode,
      reason: `Fail-closed security block due to engine error: ${message}`,
      findings: [`EngineError: ${message}`],
    };
  }
}
