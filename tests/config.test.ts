import { describe, expect, it } from 'vitest';
import { loadConfig } from '../src/config.js';

describe('loadConfig', () => {
  it('loads default WATERFALL configuration when required GCP vars are present', () => {
    const config = loadConfig({
      GOOGLE_CLOUD_PROJECT: 'enterprise-sec-project',
      MODEL_ARMOR_TEMPLATE_ID: 'claude-code-dlp-template',
    });

    expect(config.mode).toBe('WATERFALL');
    expect(config.failOpen).toBe(false);
    expect(config.promptArmorEndpoint).toBe('stdio');
    expect(config.waterfallAllowBelow).toBe(0.3);
    expect(config.waterfallBlockAbove).toBe(0.75);
    expect(config.waterfallMinConfidence).toBe(0.8);
    expect(config.waterfallAlwaysRunCloudDlp).toBe(true);
    expect(config.googleCloudProject).toBe('enterprise-sec-project');
    expect(config.googleCloudLocation).toBe('us-central1');
    expect(config.modelArmorTemplateId).toBe('claude-code-dlp-template');
  });

  it('allows LOCAL mode without GCP environment variables', () => {
    const config = loadConfig({
      ARMORCEPT_MODE: 'LOCAL',
    });

    expect(config.mode).toBe('LOCAL');
    expect(config.googleCloudProject).toBeUndefined();
    expect(config.modelArmorTemplateId).toBeUndefined();
  });

  it('throws when GOOGLE_CLOUD_PROJECT or MODEL_ARMOR_TEMPLATE_ID is missing in CLOUD or WATERFALL mode', () => {
    expect(() =>
      loadConfig({
        ARMORCEPT_MODE: 'WATERFALL',
        MODEL_ARMOR_TEMPLATE_ID: 'template-1',
      })
    ).toThrow(/GOOGLE_CLOUD_PROJECT/);

    expect(() =>
      loadConfig({
        ARMORCEPT_MODE: 'CLOUD',
        GOOGLE_CLOUD_PROJECT: 'proj-1',
      })
    ).toThrow(/MODEL_ARMOR_TEMPLATE_ID/);
  });

  it('throws when WATERFALL_ALLOW_BELOW >= WATERFALL_BLOCK_ABOVE', () => {
    expect(() =>
      loadConfig({
        ARMORCEPT_MODE: 'LOCAL',
        WATERFALL_ALLOW_BELOW: '0.80',
        WATERFALL_BLOCK_ABOVE: '0.75',
      })
    ).toThrow(/must be strictly less than/);
  });
});
