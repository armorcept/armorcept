import { GoogleAuth } from 'google-auth-library';
import type {
  ModelArmorEvaluation,
  ModelArmorFilterResultItem,
  ModelArmorSanitizeResponse,
} from '../types.js';

export interface ModelArmorClientOptions {
  projectId: string;
  location: string;
  templateId: string;
  keyFilename?: string;
  timeoutMs?: number;
  tokenProvider?: () => Promise<{ token: string; expiresAtMs?: number }>;
  fetchImpl?: typeof fetch;
}

interface CachedToken {
  token: string;
  expiresAtMs: number;
}

const DEFAULT_TOKEN_TTL_MS = 50 * 60 * 1000; // 50 minutes safety margin for 1-hour GCP OAuth tokens
const TOKEN_REFRESH_SKEW_MS = 60 * 1000; // Refresh 60s before expiry

const FILTER_LABELS: Record<string, string> = {
  piAndJailbreakFilterResult: 'Prompt Injection & Jailbreak',
  sdpFilterResult: 'DLP Violation: Sensitive Data / PII Detected',
  raiFilterResult: 'Responsible AI Safety Violation',
  maliciousUriFilterResult: 'Malicious URI Detected',
  csamFilterResult: 'CSAM Safety Violation',
};

/**
 * Client for Google Cloud Model Armor REST API (`sanitizeUserPrompt`).
 * Caches OAuth2 bearer tokens in memory to minimize latency across prompts and tool calls.
 */
export class ModelArmorClient {
  private readonly projectId: string;
  private readonly location: string;
  private readonly templateId: string;
  private readonly timeoutMs: number;
  private readonly auth: GoogleAuth;
  private readonly customTokenProvider?: () => Promise<{
    token: string;
    expiresAtMs?: number;
  }>;
  private readonly fetchImpl: typeof fetch;

  private cachedToken: CachedToken | null = null;

  constructor(options: ModelArmorClientOptions) {
    this.projectId = options.projectId;
    this.location = options.location || 'us-central1';
    this.templateId = options.templateId;
    this.timeoutMs = options.timeoutMs ?? 5000;
    this.customTokenProvider = options.tokenProvider;
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;

    this.auth = new GoogleAuth({
      scopes: ['https://www.googleapis.com/auth/cloud-platform'],
      ...(options.keyFilename ? { keyFilename: options.keyFilename } : {}),
    });
  }

  public getEndpointUrl(): string {
    return `https://modelarmor.${this.location}.rep.googleapis.com/v1/projects/${encodeURIComponent(
      this.projectId
    )}/locations/${encodeURIComponent(
      this.location
    )}/templates/${encodeURIComponent(this.templateId)}:sanitizeUserPrompt`;
  }

  /**
   * Returns a valid OAuth2 bearer token, serving from the in-memory cache when still valid.
   */
  public async getAccessToken(): Promise<string> {
    const now = Date.now();
    if (
      this.cachedToken &&
      this.cachedToken.expiresAtMs - TOKEN_REFRESH_SKEW_MS > now
    ) {
      return this.cachedToken.token;
    }

    if (this.customTokenProvider) {
      const provided = await this.customTokenProvider();
      this.cachedToken = {
        token: provided.token,
        expiresAtMs: provided.expiresAtMs ?? now + DEFAULT_TOKEN_TTL_MS,
      };
      return this.cachedToken.token;
    }

    const client = await this.auth.getClient();
    const tokenResponse = await client.getAccessToken();
    const token =
      typeof tokenResponse === 'string' ? tokenResponse : tokenResponse?.token;

    if (!token) {
      throw new Error(
        'Failed to acquire Google Cloud OAuth2 access token from Application Default Credentials.'
      );
    }

    const expiryDate = client.credentials?.expiry_date;
    const expiresAtMs =
      typeof expiryDate === 'number' && expiryDate > now
        ? expiryDate
        : now + DEFAULT_TOKEN_TTL_MS;

    this.cachedToken = { token, expiresAtMs };
    return token;
  }

  public clearTokenCache(): void {
    this.cachedToken = null;
  }

  /**
   * Calls the Google Cloud Model Armor `sanitizeUserPrompt` endpoint and parses the verdict.
   */
  public async sanitizeUserPrompt(text: string): Promise<ModelArmorEvaluation> {
    const start = performance.now();
    const token = await this.getAccessToken();
    const url = this.getEndpointUrl();

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchImpl(url, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userPromptData: {
            text,
          },
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorBody = await response.text().catch(() => '');
        throw new Error(
          `Google Model Armor API returned HTTP ${response.status}: ${
            errorBody || response.statusText
          }`
        );
      }

      const raw = (await response.json()) as ModelArmorSanitizeResponse;
      const latencyMs = Math.round((performance.now() - start) * 100) / 100;
      return this.parseSanitizeResponse(raw, latencyMs);
    } catch (err) {
      if ((err as Error)?.name === 'AbortError') {
        throw new Error(
          `Google Model Armor request timed out after ${this.timeoutMs}ms`
        );
      }
      throw err instanceof Error ? err : new Error(String(err));
    } finally {
      clearTimeout(timer);
    }
  }

  private parseSanitizeResponse(
    raw: ModelArmorSanitizeResponse,
    latencyMs: number
  ): ModelArmorEvaluation {
    const sanitizationResult = raw.sanitizationResult ?? {};
    const filterMatchState =
      sanitizationResult.filterMatchState ?? 'NO_MATCH_FOUND';
    const filterResults = sanitizationResult.filterResults ?? {};

    const categories: string[] = [];
    const evidenceParts: string[] = [];

    for (const [filterKey, filterVal] of Object.entries(filterResults)) {
      if (!filterVal) continue;
      if (this.isFilterTriggered(filterVal)) {
        const readableCategory = FILTER_LABELS[filterKey] ?? filterKey;
        categories.push(readableCategory);

        const details = this.extractFilterEvidence(filterKey, filterVal);
        evidenceParts.push(details ? `${filterKey}(${details})` : filterKey);
      }
    }

    const matched =
      filterMatchState === 'MATCH_FOUND' || categories.length > 0;

    if (matched && categories.length === 0) {
      categories.push('Model Armor Policy Violation');
    }

    return {
      matched,
      filterMatchState,
      categories,
      evidence:
        evidenceParts.length > 0
          ? evidenceParts.join(', ')
          : `filterMatchState=${filterMatchState}`,
      sanitizedText: sanitizationResult.sanitizedText,
      latencyMs,
      raw,
    };
  }

  private isFilterTriggered(item: ModelArmorFilterResultItem): boolean {
    if (item.matchState === 'MATCH_FOUND') return true;
    if (item.sdpInspectResult?.matchState === 'MATCH_FOUND') return true;
    if (item.sdpDeidentifyResult?.matchState === 'MATCH_FOUND') return true;
    if (item.piAndJailbreakFilterResult?.matchState === 'MATCH_FOUND') {
      return true;
    }
    return false;
  }

  private extractFilterEvidence(
    filterKey: string,
    item: ModelArmorFilterResultItem
  ): string {
    if (filterKey === 'sdpFilterResult') {
      const findings = item.sdpInspectResult?.findings ?? [];
      if (findings.length > 0) {
        const infoTypes = Array.from(
          new Set(findings.map((f) => f.infoType).filter(Boolean))
        );
        if (infoTypes.length > 0) {
          return `infoTypes: ${infoTypes.join('|')}`;
        }
      }
    }
    if (item.piAndJailbreakFilterResult?.confidenceLevel) {
      return `confidence: ${item.piAndJailbreakFilterResult.confidenceLevel}`;
    }
    return item.matchState ?? 'MATCH_FOUND';
  }
}
