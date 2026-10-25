import type { ArmorCeptConfig, ArmorCeptMode } from './types.js';

function parseBoolean(val: boolean | string | undefined, defaultValue: boolean): boolean {
  if (val === undefined) return defaultValue;
  if (typeof val === 'boolean') return val;
  const normalized = val.trim().toLowerCase();
  if (['true', '1', 'yes'].includes(normalized)) return true;
  if (['false', '0', 'no', ''].includes(normalized)) return false;
  throw new Error(`Invalid boolean value: "${val}"`);
}

function parseProbability(fieldName: string, val: number | string | undefined, defaultValue: number): number {
  if (val === undefined || val === '') return defaultValue;
  const parsed = typeof val === 'number' ? val : Number(val);
  if (Number.isNaN(parsed) || parsed < 0 || parsed > 1) {
    throw new Error(`${fieldName} must be a number between 0.0 and 1.0 (received "${val}")`);
  }
  return parsed;
}

function parsePositiveInt(fieldName: string, val: number | string | undefined, defaultValue: number): number {
  if (val === undefined || val === '') return defaultValue;
  const parsed = typeof val === 'number' ? val : Number.parseInt(String(val), 10);
  if (Number.isNaN(parsed) || parsed <= 0) {
    throw new Error(`${fieldName} must be a positive integer (received "${val}")`);
  }
  return parsed;
}

function parseMode(val: string | undefined): ArmorCeptMode {
  const normalized = (val ?? 'WATERFALL').trim().toUpperCase();
  if (normalized === 'LOCAL' || normalized === 'CLOUD' || normalized === 'WATERFALL') {
    return normalized;
  }
  throw new Error(`Invalid ARMORCEPT_MODE "${val}". Expected LOCAL, CLOUD, or WATERFALL.`);
}

/**
 * Loads and strictly validates ArmorCept configuration from environment variables.
 */
export function loadConfig(
  env: Record<string, string | undefined> = process.env
): ArmorCeptConfig {
  const mode: ArmorCeptMode = parseMode(env.ARMORCEPT_MODE);
  const failOpen = parseBoolean(env.ARMORCEPT_FAIL_OPEN, false);

  const promptArmorEndpoint = (env.PROMPT_ARMOR_ENDPOINT ?? 'stdio').trim() || 'stdio';
  const promptArmorTimeoutMs = parsePositiveInt(
    'PROMPT_ARMOR_TIMEOUT_MS',
    env.PROMPT_ARMOR_TIMEOUT_MS,
    3000
  );

  const waterfallAllowBelow = parseProbability(
    'WATERFALL_ALLOW_BELOW',
    env.WATERFALL_ALLOW_BELOW,
    0.3
  );
  const waterfallBlockAbove = parseProbability(
    'WATERFALL_BLOCK_ABOVE',
    env.WATERFALL_BLOCK_ABOVE,
    0.75
  );
  const waterfallMinConfidence = parseProbability(
    'WATERFALL_MIN_CONFIDENCE',
    env.WATERFALL_MIN_CONFIDENCE,
    0.8
  );
  const waterfallAlwaysRunCloudDlp = parseBoolean(
    env.WATERFALL_ALWAYS_RUN_CLOUD_DLP,
    true
  );

  if (waterfallAllowBelow >= waterfallBlockAbove) {
    throw new Error(
      `Invalid waterfall thresholds: WATERFALL_ALLOW_BELOW (${waterfallAllowBelow}) must be strictly less than WATERFALL_BLOCK_ABOVE (${waterfallBlockAbove}).`
    );
  }

  const googleApplicationCredentials = env.GOOGLE_APPLICATION_CREDENTIALS?.trim() || undefined;
  const googleCloudProject = env.GOOGLE_CLOUD_PROJECT?.trim() || undefined;
  const googleCloudLocation = (env.GOOGLE_CLOUD_LOCATION ?? 'us-central1').trim() || 'us-central1';
  const modelArmorTemplateId = env.MODEL_ARMOR_TEMPLATE_ID?.trim() || undefined;
  const modelArmorTimeoutMs = parsePositiveInt(
    'MODEL_ARMOR_TIMEOUT_MS',
    env.MODEL_ARMOR_TIMEOUT_MS,
    5000
  );

  if (mode === 'CLOUD' || mode === 'WATERFALL') {
    if (!googleCloudProject) {
      throw new Error(
        `Missing required environment variable GOOGLE_CLOUD_PROJECT when ARMORCEPT_MODE=${mode}.`
      );
    }
    if (!modelArmorTemplateId) {
      throw new Error(
        `Missing required environment variable MODEL_ARMOR_TEMPLATE_ID when ARMORCEPT_MODE=${mode}.`
      );
    }
  }

  return {
    mode,
    failOpen,
    promptArmorEndpoint,
    promptArmorTimeoutMs,
    waterfallAllowBelow,
    waterfallBlockAbove,
    waterfallMinConfidence,
    waterfallAlwaysRunCloudDlp,
    googleApplicationCredentials,
    googleCloudProject,
    googleCloudLocation,
    modelArmorTemplateId,
    modelArmorTimeoutMs,
  };
}
