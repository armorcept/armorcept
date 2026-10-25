export type ArmorCeptMode = 'LOCAL' | 'CLOUD' | 'WATERFALL';

export type InterceptionContextType = 'prompt' | 'tool';

export type EngineSource =
  | 'Prompt-Armor (Local)'
  | 'Google Model Armor (Cloud)'
  | 'ArmorCept Policy Engine';

export interface ArmorCeptConfig {
  mode: ArmorCeptMode;
  failOpen: boolean;
  promptArmorEndpoint: string;
  promptArmorTimeoutMs: number;
  waterfallAllowBelow: number;
  waterfallBlockAbove: number;
  waterfallMinConfidence: number;
  waterfallAlwaysRunCloudDlp: boolean;
  googleApplicationCredentials?: string;
  googleCloudProject?: string;
  googleCloudLocation: string;
  modelArmorTemplateId?: string;
  modelArmorTimeoutMs: number;
}

export interface PromptArmorResponse {
  id?: string;
  risk_score: number;
  confidence: number;
  decision: 'ALLOW' | 'BLOCK' | string;
  categories: string[];
  evidence?: Record<string, unknown> | string;
  latency_ms?: number;
  council_enabled?: boolean;
}

export type ModelArmorMatchState =
  | 'MATCH_FOUND'
  | 'NO_MATCH_FOUND'
  | 'ERROR'
  | 'FILTER_MATCH_STATE_UNSPECIFIED'
  | string;

export interface ModelArmorFilterResultItem {
  executionState?: string;
  matchState?: ModelArmorMatchState;
  sdpInspectResult?: {
    matchState?: ModelArmorMatchState;
    findings?: Array<{
      infoType?: string;
      likelihood?: string;
    }>;
  };
  sdpDeidentifyResult?: {
    matchState?: ModelArmorMatchState;
    data?: {
      text?: string;
    };
  };
  piAndJailbreakFilterResult?: {
    matchState?: ModelArmorMatchState;
    confidenceLevel?: string;
  };
  raiFilterSubResults?: Record<
    string,
    {
      matchState?: ModelArmorMatchState;
      confidenceLevel?: string;
    }
  >;
}

export interface ModelArmorSanitizeResponse {
  sanitizationResult?: {
    filterMatchState?: ModelArmorMatchState;
    filterResults?: {
      piAndJailbreakFilterResult?: ModelArmorFilterResultItem;
      raiFilterResult?: ModelArmorFilterResultItem;
      maliciousUriFilterResult?: ModelArmorFilterResultItem;
      csamFilterResult?: ModelArmorFilterResultItem;
      sdpFilterResult?: ModelArmorFilterResultItem;
      [key: string]: ModelArmorFilterResultItem | undefined;
    };
    sanitizedText?: string;
    invocationResult?: string;
  };
}

export interface ModelArmorEvaluation {
  matched: boolean;
  filterMatchState: ModelArmorMatchState;
  categories: string[];
  evidence: string;
  sanitizedText?: string;
  latencyMs: number;
  raw: ModelArmorSanitizeResponse;
}

export interface EvaluationVerdict {
  decision: 'ALLOW' | 'BLOCK';
  source: EngineSource;
  contextType: InterceptionContextType;
  categories: string[];
  reason: string;
  evidence: string;
  riskScore?: number;
  confidence?: number;
  latencyMs: number;
  escalatedToCloud: boolean;
  failOpenTriggered?: boolean;
}

export interface EvaluatePayloadMeta {
  toolName?: string;
}
