/**
 * ArmorCept — Shared Types for the Claude Code Sandbox Hooks Module
 */

export type ArmorCeptMode = 'LOCAL' | 'CLOUD' | 'WATERFALL';

export type LocalDlpAction = 'block' | 'warn' | 'allow';

export type Enforcement = 'enforce' | 'audit';

export type ToolResultAction = 'withhold' | 'redact';

/**
 * full: prompt-armor; lightweight_fallback: the daemon's built-in regex engine
 * (prompt-armor not installed); ts-fallback: the in-process DLP patterns, used
 * when the Python engine can't run at all.
 */
export type EngineMode = 'full' | 'lightweight_fallback' | 'ts-fallback';

/** A matched span in a scanned text, as UTF-16 offsets (JavaScript string indices). */
export interface MatchSpan {
  category: string;
  start: number;
  end: number;
}

export type PromptArmorDecision = 'ALLOW' | 'WARN' | 'BLOCK' | 'ESCALATE';

export interface RuntimeConfig {
  mode: ArmorCeptMode;
  failOpen: boolean;
  /** audit: record every verdict, never block or withhold. */
  enforcement: Enforcement;
  /** In audit mode, still block exact secret matches (ARMORCEPT_SECRET_ENV_VARS). */
  auditEnforceSecrets: boolean;
  /** JSONL decision log path (ARMORCEPT_DECISION_LOG). */
  decisionLogPath?: string;
  /** Rotate the decision log to <path>.1 past this size; 0 disables rotation. */
  decisionLogMaxBytes: number;
  promptArmorEndpoint: string;
  promptArmorTimeoutMs: number;
  waterfallAllowBelow: number;
  waterfallBlockAbove: number;
  waterfallMinConfidence: number;
  waterfallAlwaysRunCloudDlp: boolean;
  localDlpAction: LocalDlpAction;
  allowGcloudAdc: boolean;
  scanToolResults: boolean;
  /** What to do with a tool result that has DLP or secret matches. */
  toolResultAction: ToolResultAction;
  interactiveOverride: boolean;
  exemptTools: readonly string[];
  allowlistPaths: readonly string[];
  /** Absolute path to a JSON file of custom DLP patterns, passed to the local engine. */
  extraPatternsPath?: string;
  /** Names (not values) of environment variables whose values are matched exactly. */
  secretEnvVars: readonly string[];
  googleApplicationCredentials?: string;
  googleCloudAccessToken?: string;
  googleCloudProject?: string;
  googleCloudLocation: string;
  modelArmorTemplateId?: string;
  modelArmorTimeoutMs: number;
}

export interface PromptArmorResult {
  score: number;
  confidence: number;
  decision: PromptArmorDecision;
  findings: string[];
  dlpCategories: string[];
  /** Where each DLP match is in the scanned text. */
  dlpSpans?: MatchSpan[];
  latency_ms?: number;
  engine_mode?: EngineMode;
  warning?: string;
}

export interface EvaluationVerdict {
  decision: 'ALLOW' | 'WARN' | 'BLOCK';
  source:
    | 'Prompt-Armor'
    | 'ArmorCept Built-in'
    | 'ArmorCept DLP'
    | 'ArmorCept Secrets'
    | 'Model Armor'
    | 'ArmorCept';
  mode: ArmorCeptMode;
  reason: string;
  findings: string[];
  score?: number;
  confidence?: number;
  escalatedToCloud?: boolean;
  engineMode?: EngineMode;
  warning?: string;
  /** Match spans for DLP and secret findings, when the engine knows them. */
  spans?: MatchSpan[];
}
