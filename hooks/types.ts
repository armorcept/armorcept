/**
 * ArmorCept — Shared Types for the Claude Code Sandbox Hooks Module
 */

export type ArmorCeptMode = 'LOCAL' | 'CLOUD' | 'WATERFALL';

export type LocalDlpAction = 'block' | 'warn' | 'allow';

export type PromptArmorDecision = 'ALLOW' | 'WARN' | 'BLOCK' | 'ESCALATE';

export interface RuntimeConfig {
  mode: ArmorCeptMode;
  failOpen: boolean;
  promptArmorEndpoint: string;
  promptArmorTimeoutMs: number;
  waterfallAllowBelow: number;
  waterfallBlockAbove: number;
  waterfallMinConfidence: number;
  waterfallAlwaysRunCloudDlp: boolean;
  localDlpAction: LocalDlpAction;
  allowGcloudAdc: boolean;
  scanToolResults: boolean;
  interactiveOverride: boolean;
  exemptTools: readonly string[];
  allowlistPaths: readonly string[];
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
  latency_ms?: number;
  engine_mode?: 'full' | 'lightweight_fallback';
  warning?: string;
}

export interface EvaluationVerdict {
  decision: 'ALLOW' | 'WARN' | 'BLOCK';
  source: 'Prompt-Armor' | 'Model Armor' | 'ArmorCept';
  mode: ArmorCeptMode;
  reason: string;
  findings: string[];
  score?: number;
  confidence?: number;
  escalatedToCloud?: boolean;
  engineMode?: 'full' | 'lightweight_fallback';
  warning?: string;
}
