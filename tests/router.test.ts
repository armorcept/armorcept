import { describe, expect, it, vi } from 'vitest';
import { loadConfig } from '../src/config.js';
import type { ModelArmorClient } from '../src/engines/model-armor-client.js';
import type { PromptArmorClient } from '../src/engines/prompt-armor-client.js';
import { ArmorCeptRouter } from '../src/router.js';

describe('ArmorCeptRouter Waterfall & Fail-Open Logic', () => {
  const baseConfig = loadConfig({
    ARMORCEPT_MODE: 'WATERFALL',
    ARMORCEPT_FAIL_OPEN: 'false',
    WATERFALL_ALLOW_BELOW: '0.30',
    WATERFALL_BLOCK_ABOVE: '0.75',
    WATERFALL_MIN_CONFIDENCE: '0.80',
    WATERFALL_ALWAYS_RUN_CLOUD_DLP: 'false',
    GOOGLE_CLOUD_PROJECT: 'enterprise-sec-project',
    MODEL_ARMOR_TEMPLATE_ID: 'claude-code-dlp-template',
  });

  it('allows clean payloads locally without hitting cloud when WATERFALL_ALWAYS_RUN_CLOUD_DLP=false', async () => {
    const mockLocal = {
      analyze: vi.fn().mockResolvedValue({
        risk_score: 0.04,
        confidence: 0.97,
        decision: 'ALLOW',
        categories: [],
        latency_ms: 14.2,
      }),
    } as unknown as PromptArmorClient;

    const mockCloud = {
      sanitizeUserPrompt: vi.fn(),
    } as unknown as ModelArmorClient;

    const router = new ArmorCeptRouter({
      config: baseConfig,
      promptArmorClient: mockLocal,
      modelArmorClient: mockCloud,
    });

    const verdict = await router.evaluatePayload(
      'Refactor the calculateTotal function to use BigInt.',
      'prompt'
    );

    expect(verdict.decision).toBe('ALLOW');
    expect(verdict.source).toBe('Prompt-Armor (Local)');
    expect(verdict.escalatedToCloud).toBe(false);
    expect(mockCloud.sanitizeUserPrompt).not.toHaveBeenCalled();
  });

  it('escalates to Google Model Armor when confidence is below WATERFALL_MIN_CONFIDENCE even if risk_score is low', async () => {
    const mockLocal = {
      analyze: vi.fn().mockResolvedValue({
        risk_score: 0.18,
        confidence: 0.65, // < 0.80 threshold
        decision: 'ALLOW',
        categories: [],
        latency_ms: 19.0,
      }),
    } as unknown as PromptArmorClient;

    const mockCloud = {
      sanitizeUserPrompt: vi.fn().mockResolvedValue({
        matched: true,
        filterMatchState: 'MATCH_FOUND',
        categories: ['Prompt Injection & Jailbreak'],
        evidence: 'piAndJailbreakFilterResult(confidence: HIGH)',
        latencyMs: 95.0,
        raw: {},
      }),
    } as unknown as ModelArmorClient;

    const router = new ArmorCeptRouter({
      config: baseConfig,
      promptArmorClient: mockLocal,
      modelArmorClient: mockCloud,
    });

    const verdict = await router.evaluatePayload(
      'Subtle base64 encoded instruction override payload',
      'prompt'
    );

    expect(mockCloud.sanitizeUserPrompt).toHaveBeenCalledTimes(1);
    expect(verdict.decision).toBe('BLOCK');
    expect(verdict.source).toBe('Google Model Armor (Cloud)');
    expect(verdict.escalatedToCloud).toBe(true);
  });

  it('enforces ARMORCEPT_FAIL_OPEN=false (blocks on engine error) and ARMORCEPT_FAIL_OPEN=true (allows on engine error)', async () => {
    const failingLocal = {
      analyze: vi.fn().mockRejectedValue(new Error('Daemon connection refused')),
    } as unknown as PromptArmorClient;

    const failClosedRouter = new ArmorCeptRouter({
      config: { ...baseConfig, failOpen: false },
      promptArmorClient: failingLocal,
    });

    const blockedVerdict = await failClosedRouter.evaluatePayload(
      'Normal prompt',
      'prompt'
    );
    expect(blockedVerdict.decision).toBe('BLOCK');
    expect(blockedVerdict.failOpenTriggered).toBe(false);
    expect(blockedVerdict.categories).toContain('ENGINE_UNAVAILABLE');

    const failOpenRouter = new ArmorCeptRouter({
      config: { ...baseConfig, failOpen: true },
      promptArmorClient: failingLocal,
    });

    const allowedVerdict = await failOpenRouter.evaluatePayload(
      'Normal prompt',
      'prompt'
    );
    expect(allowedVerdict.decision).toBe('ALLOW');
    expect(allowedVerdict.failOpenTriggered).toBe(true);
    expect(allowedVerdict.categories).toContain('ENGINE_ERROR_FAIL_OPEN');
  });
});
