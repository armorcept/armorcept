/**
 * ArmorCept — Hybrid Waterfall & Mode Orchestrator
 */

import type { EngineInterface } from 'claude-code';
import { getLastKnownFailOpen, readRuntimeConfig } from './config';
import { runModelArmor, runPromptArmor } from './engines';
import { safeUi } from './format';
import type {
  ArmorCeptMode,
  EvaluationVerdict,
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
  for (const chunk of splitIntoChunks(text, MAX_LOCAL_SCAN_CHUNK_CHARS)) {
    const result = await runPromptArmor($, chunk, cfg);
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

  const local = await runLocalPass($, text, cfg);

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
    };
  }

  return await runCloudPass($, text, cfg, true);
}

export function splitIntoChunks(
  text: string,
  chunkSize = MAX_LOCAL_SCAN_CHUNK_CHARS
): string[] {
  if (text.length <= chunkSize) {
    return [text];
  }
  const chunks: string[] = [];
  const step = Math.max(1024, chunkSize - CHUNK_OVERLAP_CHARS);
  for (let offset = 0; offset < text.length; offset += step) {
    chunks.push(text.slice(offset, offset + chunkSize));
    if (offset + chunkSize >= text.length) break;
  }
  return chunks;
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
