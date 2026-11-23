/**
 * ArmorCept — Enforcement policy (enforce / audit) and the JSONL decision log
 *
 * Log lines hold metadata only: never the payload, the matched text, or a
 * secret value. Lines are buffered and appended by a short-lived local
 * process, off the hook's critical path.
 */

import type { EngineInterface } from 'claude-code';
import { resolvePythonBinary } from './engines';
import { safeUi } from './format';
import { findExactSecrets } from './secrets';
import type { EvaluationVerdict, RuntimeConfig } from './types';

export type DecisionHook = 'prompt.submit' | 'tool.call' | 'tool.result' | 'engine.health';

/** What ArmorCept actually did, as opposed to what the verdict recommended. */
export type DecisionAction =
  | 'allowed'
  | 'warned'
  | 'blocked'
  | 'withheld'
  | 'redacted'
  | 'overridden'
  | 'audited';

export interface DecisionRecord {
  ts: string;
  session?: string;
  hook: DecisionHook;
  tool?: string;
  decision: EvaluationVerdict['decision'] | 'INFO';
  action: DecisionAction | 'info';
  enforcement: RuntimeConfig['enforcement'];
  mode: EvaluationVerdict['mode'];
  source: EvaluationVerdict['source'];
  engine?: string;
  categories: string[];
  score?: number;
  confidence?: number;
  latency_ms: number;
  error?: string;
  event?: string;
}

/**
 * In audit mode a BLOCK is recorded but not enforced. The one exception is an
 * exact secret match when ARMORCEPT_AUDIT_ENFORCE_SECRETS=true.
 */
export function isAuditBypassed(
  cfg: RuntimeConfig | undefined,
  verdict: EvaluationVerdict
): boolean {
  if (cfg?.enforcement !== 'audit' || verdict.decision !== 'BLOCK') {
    return false;
  }
  return !(cfg.auditEnforceSecrets && verdict.source === 'ArmorCept Secrets');
}

const MAX_ERROR_CHARS = 200;

/** Engine error text is kept short and scrubbed of any loaded secret value. */
function scrubError(message: string): string {
  let out = message.slice(0, MAX_ERROR_CHARS);
  const hits = findExactSecrets(out);
  for (const hit of [...hits].reverse()) {
    out = `${out.slice(0, hit.start)}[REDACTED:${hit.category}]${out.slice(hit.end)}`;
  }
  return out;
}

function engineLabel(verdict: EvaluationVerdict): string {
  if (verdict.engineMode) return `${verdict.source} (${verdict.engineMode})`;
  return verdict.source;
}

export function buildDecisionRecord(
  cfg: RuntimeConfig,
  input: {
    hook: DecisionHook;
    tool?: string;
    verdict: EvaluationVerdict;
    action: DecisionAction;
    latencyMs: number;
    session?: string;
  }
): DecisionRecord {
  const { verdict } = input;
  const record: DecisionRecord = {
    ts: new Date().toISOString(),
    hook: input.hook,
    decision: verdict.decision,
    action: input.action,
    enforcement: cfg.enforcement,
    mode: verdict.mode,
    source: verdict.source,
    engine: engineLabel(verdict),
    // Categories only. Engine-error "findings" carry the message, so they
    // are reduced to a fixed category and the text goes to `error`.
    categories: verdict.findings.map((f) =>
      f.startsWith('EngineError:') ? 'ENGINE_ERROR' : f
    ),
    latency_ms: Math.max(0, Math.round(input.latencyMs)),
  };
  if (input.session) record.session = input.session;
  if (input.tool) record.tool = input.tool;
  if (typeof verdict.score === 'number') record.score = verdict.score;
  if (typeof verdict.confidence === 'number') record.confidence = verdict.confidence;
  if (verdict.source === 'ArmorCept') record.error = scrubError(verdict.reason);
  return record;
}

let buffer: string[] = [];
let chain: Promise<void> = Promise.resolve();
let sessionId: string | undefined;
let writeFailureReported = false;

export function resetDecisionLogState(): void {
  buffer = [];
  chain = Promise.resolve();
  sessionId = undefined;
  writeFailureReported = false;
}

export async function getSessionId($: EngineInterface): Promise<string | undefined> {
  if (sessionId !== undefined) return sessionId;
  try {
    const id: unknown = await $.session.id();
    sessionId = typeof id === 'string' ? id : undefined;
  } catch {
    sessionId = undefined;
  }
  return sessionId;
}

async function writeBatch(
  $: EngineInterface,
  cfg: RuntimeConfig,
  data: string
): Promise<void> {
  const path = cfg.decisionLogPath;
  if (!path) return;
  const { binary } = await resolvePythonBinary($);
  try {
    const res = await $.process.run(
      [
        binary,
        '-I',
        '-S',
        `${$.plugin.root}/python/decision_log.py`,
        path,
        String(cfg.decisionLogMaxBytes),
      ],
      { stdin: data, timeoutMs: 5000 }
    );
    if (res.exitCode === 0) return;
  } catch {
    // Python unavailable: fall through to sh
  }
  try {
    const res = await $.process.run(
      ['sh', '-c', 'umask 077; cat >> "$1"', 'armorcept-log', path],
      { stdin: data, timeoutMs: 5000 }
    );
    if (res.exitCode === 0) return;
  } catch {
    // No writer available
  }
  if (!writeFailureReported) {
    writeFailureReported = true;
    safeUi(() =>
      $.ui.toast(`⚠️ ArmorCept: could not write the decision log at ${path}`, {
        timeoutMs: 6000,
      })
    );
  }
}

/** Queues one log line. Never throws and never blocks the hook on disk I/O. */
export function recordDecision(
  $: EngineInterface,
  cfg: RuntimeConfig | undefined,
  record: DecisionRecord
): void {
  if (!cfg?.decisionLogPath) return;
  try {
    buffer.push(`${JSON.stringify(record)}\n`);
  } catch {
    return;
  }
  chain = chain
    .then(async () => {
      if (buffer.length === 0) return;
      const data = buffer.join('');
      buffer = [];
      await writeBatch($, cfg, data);
    })
    .catch(() => undefined);
}

/** Resolves once every queued line has been handed to the writer. */
export function flushDecisionLog(): Promise<void> {
  return chain;
}
