import type { ModelArmorClient } from './engines/model-armor-client.js';
import type { PromptArmorClient } from './engines/prompt-armor-client.js';
import type {
  ArmorCeptConfig,
  EvaluatePayloadMeta,
  EvaluationVerdict,
  InterceptionContextType,
  PromptArmorResponse,
} from './types.js';

export interface ArmorCeptRouterDependencies {
  config: ArmorCeptConfig;
  promptArmorClient?: PromptArmorClient;
  modelArmorClient?: ModelArmorClient;
}

/**
 * Orchestrates LOCAL, CLOUD, and WATERFALL evaluation pipelines and enforces
 * ARMORCEPT_FAIL_OPEN / fail-closed resilience policies.
 */
export class ArmorCeptRouter {
  private readonly config: ArmorCeptConfig;
  private readonly promptArmorClient?: PromptArmorClient;
  private readonly modelArmorClient?: ModelArmorClient;

  constructor(deps: ArmorCeptRouterDependencies) {
    this.config = deps.config;
    this.promptArmorClient = deps.promptArmorClient;
    this.modelArmorClient = deps.modelArmorClient;
  }

  public async evaluatePayload(
    text: string,
    contextType: InterceptionContextType,
    _meta?: EvaluatePayloadMeta
  ): Promise<EvaluationVerdict> {
    const start = performance.now();

    try {
      switch (this.config.mode) {
        case 'LOCAL':
          return await this.evaluateLocalOnly(text, contextType, start);
        case 'CLOUD':
          return await this.evaluateCloudOnly(text, contextType, start, false);
        case 'WATERFALL':
        default:
          return await this.evaluateWaterfall(text, contextType, start);
      }
    } catch (err) {
      return this.handleEngineError(err, contextType, start);
    }
  }

  private async evaluateLocalOnly(
    text: string,
    contextType: InterceptionContextType,
    startMs: number
  ): Promise<EvaluationVerdict> {
    if (!this.promptArmorClient) {
      throw new Error('PromptArmorClient is not initialized for LOCAL mode.');
    }

    const localResult = await this.promptArmorClient.analyze(text);
    const totalLatencyMs = this.computeLatency(startMs, localResult.latency_ms);
    const isBlocked =
      localResult.risk_score >= this.config.waterfallBlockAbove ||
      localResult.decision.toUpperCase() === 'BLOCK';

    if (isBlocked) {
      return this.buildLocalBlockVerdict(
        localResult,
        contextType,
        totalLatencyMs
      );
    }

    return {
      decision: 'ALLOW',
      source: 'Prompt-Armor (Local)',
      contextType,
      categories: localResult.categories,
      reason: 'Cleared by local Prompt-Armor analysis.',
      evidence: this.formatLocalEvidence(localResult),
      riskScore: localResult.risk_score,
      confidence: localResult.confidence,
      latencyMs: totalLatencyMs,
      escalatedToCloud: false,
    };
  }

  private async evaluateCloudOnly(
    text: string,
    contextType: InterceptionContextType,
    startMs: number,
    escalatedFromLocal: boolean,
    localResult?: PromptArmorResponse
  ): Promise<EvaluationVerdict> {
    if (!this.modelArmorClient) {
      throw new Error(
        'ModelArmorClient is not initialized for Google Cloud Model Armor evaluation.'
      );
    }

    const cloudResult = await this.modelArmorClient.sanitizeUserPrompt(text);
    const totalLatencyMs = Math.round((performance.now() - startMs) * 100) / 100;

    if (cloudResult.matched) {
      const categorySummary =
        cloudResult.categories.join(', ') || 'Policy Violation';
      return {
        decision: 'BLOCK',
        source: 'Google Model Armor (Cloud)',
        contextType,
        categories: cloudResult.categories,
        reason: `${categorySummary} (${cloudResult.evidence})`,
        evidence: cloudResult.evidence,
        riskScore: localResult?.risk_score,
        confidence: localResult?.confidence,
        latencyMs: totalLatencyMs,
        escalatedToCloud: escalatedFromLocal,
      };
    }

    return {
      decision: 'ALLOW',
      source: 'Google Model Armor (Cloud)',
      contextType,
      categories: [],
      reason: 'Cleared by Google Cloud Model Armor.',
      evidence: cloudResult.evidence,
      riskScore: localResult?.risk_score,
      confidence: localResult?.confidence,
      latencyMs: totalLatencyMs,
      escalatedToCloud: escalatedFromLocal,
    };
  }

  private async evaluateWaterfall(
    text: string,
    contextType: InterceptionContextType,
    startMs: number
  ): Promise<EvaluationVerdict> {
    if (!this.promptArmorClient) {
      throw new Error(
        'PromptArmorClient is not initialized for WATERFALL mode.'
      );
    }

    const localResult = await this.promptArmorClient.analyze(text);
    const localLatencyMs = this.computeLatency(startMs, localResult.latency_ms);

    // 1. Immediate Local Block: risk_score >= WATERFALL_BLOCK_ABOVE (e.g., 0.75)
    if (localResult.risk_score >= this.config.waterfallBlockAbove) {
      return this.buildLocalBlockVerdict(
        localResult,
        contextType,
        localLatencyMs
      );
    }

    // 2. Uncertain / Grey Area Escalation:
    //    risk_score between WATERFALL_ALLOW_BELOW (0.30) and WATERFALL_BLOCK_ABOVE (0.75)
    //    OR confidence < WATERFALL_MIN_CONFIDENCE (0.80)
    const isGreyAreaRisk =
      localResult.risk_score >= this.config.waterfallAllowBelow &&
      localResult.risk_score < this.config.waterfallBlockAbove;
    const isLowConfidence =
      localResult.confidence < this.config.waterfallMinConfidence;

    if (isGreyAreaRisk || isLowConfidence) {
      return await this.evaluateCloudOnly(
        text,
        contextType,
        startMs,
        true,
        localResult
      );
    }

    // 3. Mandatory Cloud DLP: payload scored safely below WATERFALL_ALLOW_BELOW
    //    with high confidence, but WATERFALL_ALWAYS_RUN_CLOUD_DLP=true requires cloud DLP scan
    if (this.config.waterfallAlwaysRunCloudDlp) {
      return await this.evaluateCloudOnly(
        text,
        contextType,
        startMs,
        true,
        localResult
      );
    }

    // 4. Cleared locally and mandatory cloud DLP is disabled
    return {
      decision: 'ALLOW',
      source: 'Prompt-Armor (Local)',
      contextType,
      categories: localResult.categories,
      reason: 'Cleared by local Prompt-Armor fast path.',
      evidence: this.formatLocalEvidence(localResult),
      riskScore: localResult.risk_score,
      confidence: localResult.confidence,
      latencyMs: localLatencyMs,
      escalatedToCloud: false,
    };
  }

  private buildLocalBlockVerdict(
    localResult: PromptArmorResponse,
    contextType: InterceptionContextType,
    latencyMs: number
  ): EvaluationVerdict {
    const categories =
      localResult.categories.length > 0
        ? localResult.categories.map((c) =>
            c.startsWith('Category.') ? c : `Category.${c}`
          )
        : ['Category.PROMPT_INJECTION'];
    const evidence = this.formatLocalEvidence(localResult);

    return {
      decision: 'BLOCK',
      source: 'Prompt-Armor (Local)',
      contextType,
      categories,
      reason: `${categories.join(', ')} (risk_score=${localResult.risk_score.toFixed(
        2
      )}, confidence=${localResult.confidence.toFixed(2)})`,
      evidence,
      riskScore: localResult.risk_score,
      confidence: localResult.confidence,
      latencyMs,
      escalatedToCloud: false,
    };
  }

  private formatLocalEvidence(localResult: PromptArmorResponse): string {
    const scorePart = `risk_score=${localResult.risk_score.toFixed(
      2
    )}, confidence=${localResult.confidence.toFixed(2)}`;
    if (!localResult.evidence) {
      return scorePart;
    }
    if (typeof localResult.evidence === 'string') {
      return `${scorePart}; ${localResult.evidence}`;
    }
    const layer =
      typeof localResult.evidence.layer === 'string'
        ? `layer=${localResult.evidence.layer}`
        : JSON.stringify(localResult.evidence);
    return `${scorePart}; ${layer}`;
  }

  private handleEngineError(
    err: unknown,
    contextType: InterceptionContextType,
    startMs: number
  ): EvaluationVerdict {
    const message = err instanceof Error ? err.message : String(err);
    const latencyMs = Math.round((performance.now() - startMs) * 100) / 100;

    if (this.config.failOpen) {
      return {
        decision: 'ALLOW',
        source: 'ArmorCept Policy Engine',
        contextType,
        categories: ['ENGINE_ERROR_FAIL_OPEN'],
        reason: `Validation engine error (allowed via ARMORCEPT_FAIL_OPEN=true): ${message}`,
        evidence: message,
        latencyMs,
        escalatedToCloud: false,
        failOpenTriggered: true,
      };
    }

    return {
      decision: 'BLOCK',
      source: 'ArmorCept Policy Engine',
      contextType,
      categories: ['ENGINE_UNAVAILABLE'],
      reason: `Validation engine failure (blocked via ARMORCEPT_FAIL_OPEN=false): ${message}`,
      evidence: message,
      latencyMs,
      escalatedToCloud: false,
      failOpenTriggered: false,
    };
  }

  private computeLatency(startMs: number, reportedMs?: number): number {
    if (typeof reportedMs === 'number' && reportedMs > 0) {
      return reportedMs;
    }
    return Math.round((performance.now() - startMs) * 100) / 100;
  }
}
