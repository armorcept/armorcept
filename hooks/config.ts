/**
 * ArmorCept — Runtime Configuration & Validation
 */

import type { EngineInterface } from 'claude-code';
import type { ArmorCeptMode, LocalDlpAction, RuntimeConfig } from './types';

let cachedConfig: RuntimeConfig | undefined;
let lastKnownFailOpen = false;

export function resetRuntimeConfigCache(): void {
  cachedConfig = undefined;
  lastKnownFailOpen = false;
}

export function getLastKnownFailOpen(): boolean {
  return cachedConfig?.failOpen ?? lastKnownFailOpen;
}

export function stripQuotes(val: string | undefined): string | undefined {
  if (!val) return undefined;
  const trimmed = val.trim();
  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1).trim() || undefined;
  }
  return trimmed || undefined;
}

export function parseBool(val: string | undefined, fallback: boolean): boolean {
  const cleaned = stripQuotes(val);
  if (cleaned === undefined || cleaned === '') return fallback;
  const norm = cleaned.toLowerCase();
  if (norm === 'true' || norm === '1' || norm === 'yes') return true;
  if (norm === 'false' || norm === '0' || norm === 'no') return false;
  throw new Error(`Invalid boolean configuration value: "${val}"`);
}

export function parseFiniteNumber(
  val: string | undefined,
  fallback: number,
  fieldName: string
): number {
  const cleaned = stripQuotes(val);
  if (cleaned === undefined || cleaned === '') return fallback;
  const n = Number(cleaned);
  if (!Number.isFinite(n)) {
    throw new Error(`Invalid numeric value for ${fieldName}: "${val}"`);
  }
  return n;
}

export function parseCsvList(val: string | undefined): string[] {
  const cleaned = stripQuotes(val);
  if (!cleaned) return [];
  return cleaned
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

export interface RawConfigEnv {
  ARMORCEPT_MODE?: string;
  ARMORCEPT_FAIL_OPEN?: string;
  PROMPT_ARMOR_ENDPOINT?: string;
  PROMPT_ARMOR_TIMEOUT_MS?: string;
  WATERFALL_ALLOW_BELOW?: string;
  WATERFALL_BLOCK_ABOVE?: string;
  WATERFALL_MIN_CONFIDENCE?: string;
  WATERFALL_ALWAYS_RUN_CLOUD_DLP?: string;
  ARMORCEPT_LOCAL_DLP_ACTION?: string;
  ARMORCEPT_ALLOW_GCLOUD_ADC?: string;
  ARMORCEPT_SCAN_TOOL_RESULTS?: string;
  ARMORCEPT_INTERACTIVE_OVERRIDE?: string;
  ARMORCEPT_EXEMPT_TOOLS?: string;
  ARMORCEPT_ALLOWLIST_PATHS?: string;
  GOOGLE_APPLICATION_CREDENTIALS?: string;
  GOOGLE_CLOUD_ACCESS_TOKEN?: string;
  GOOGLE_CLOUD_PROJECT?: string;
  GOOGLE_CLOUD_LOCATION?: string;
  MODEL_ARMOR_TEMPLATE_ID?: string;
  MODEL_ARMOR_TIMEOUT_MS?: string;
  HOME?: string;
}

export function buildRuntimeConfig(
  raw: RawConfigEnv,
  sessionCwd?: string
): RuntimeConfig {
  const failOpen = parseBool(raw.ARMORCEPT_FAIL_OPEN, false);
  lastKnownFailOpen = failOpen;

  const googleCloudProject = stripQuotes(raw.GOOGLE_CLOUD_PROJECT);
  const modelArmorTemplateId = stripQuotes(raw.MODEL_ARMOR_TEMPLATE_ID);
  const hasCloudConfig = Boolean(googleCloudProject && modelArmorTemplateId);

  const rawModeStr = stripQuotes(raw.ARMORCEPT_MODE)?.toUpperCase();
  let mode: ArmorCeptMode;
  if (!rawModeStr) {
    mode = hasCloudConfig ? 'WATERFALL' : 'LOCAL';
  } else if (
    rawModeStr === 'LOCAL' ||
    rawModeStr === 'CLOUD' ||
    rawModeStr === 'WATERFALL'
  ) {
    mode = rawModeStr;
  } else {
    throw new Error(
      `Invalid ARMORCEPT_MODE "${raw.ARMORCEPT_MODE}". Expected LOCAL, CLOUD, or WATERFALL.`
    );
  }

  if ((mode === 'CLOUD' || mode === 'WATERFALL') && !hasCloudConfig) {
    throw new Error(
      `ARMORCEPT_MODE="${mode}" requires both GOOGLE_CLOUD_PROJECT and MODEL_ARMOR_TEMPLATE_ID to be set.`
    );
  }

  const waterfallAllowBelow = parseFiniteNumber(
    raw.WATERFALL_ALLOW_BELOW,
    0.3,
    'WATERFALL_ALLOW_BELOW'
  );
  const waterfallBlockAbove = parseFiniteNumber(
    raw.WATERFALL_BLOCK_ABOVE,
    0.75,
    'WATERFALL_BLOCK_ABOVE'
  );
  const waterfallMinConfidence = parseFiniteNumber(
    raw.WATERFALL_MIN_CONFIDENCE,
    0.8,
    'WATERFALL_MIN_CONFIDENCE'
  );

  if (
    waterfallAllowBelow < 0 ||
    waterfallAllowBelow > 1 ||
    waterfallBlockAbove < 0 ||
    waterfallBlockAbove > 1 ||
    waterfallAllowBelow >= waterfallBlockAbove
  ) {
    throw new Error(
      `Invalid waterfall thresholds: WATERFALL_ALLOW_BELOW (${waterfallAllowBelow}) must be in [0, 1] and strictly less than WATERFALL_BLOCK_ABOVE (${waterfallBlockAbove}).`
    );
  }

  if (waterfallMinConfidence < 0 || waterfallMinConfidence > 1) {
    throw new Error(
      `Invalid WATERFALL_MIN_CONFIDENCE (${waterfallMinConfidence}): must be between 0 and 1.`
    );
  }

  const promptArmorTimeoutMs = parseFiniteNumber(
    raw.PROMPT_ARMOR_TIMEOUT_MS,
    5000,
    'PROMPT_ARMOR_TIMEOUT_MS'
  );
  const modelArmorTimeoutMs = parseFiniteNumber(
    raw.MODEL_ARMOR_TIMEOUT_MS,
    5000,
    'MODEL_ARMOR_TIMEOUT_MS'
  );
  if (promptArmorTimeoutMs <= 0 || modelArmorTimeoutMs <= 0) {
    throw new Error('Timeout values must be positive numbers.');
  }

  const rawDlpAction = stripQuotes(raw.ARMORCEPT_LOCAL_DLP_ACTION)?.toLowerCase();
  let localDlpAction: LocalDlpAction = 'block';
  if (rawDlpAction) {
    if (
      rawDlpAction === 'block' ||
      rawDlpAction === 'warn' ||
      rawDlpAction === 'allow'
    ) {
      localDlpAction = rawDlpAction;
    } else {
      throw new Error(
        `Invalid ARMORCEPT_LOCAL_DLP_ACTION "${raw.ARMORCEPT_LOCAL_DLP_ACTION}". Expected block, warn, or allow.`
      );
    }
  }

  const rawHome = stripQuotes(raw.HOME);
  let googleApplicationCredentials = stripQuotes(
    raw.GOOGLE_APPLICATION_CREDENTIALS
  );
  if (googleApplicationCredentials) {
    if (googleApplicationCredentials.startsWith('~/') && rawHome) {
      googleApplicationCredentials = `${rawHome.replace(/\/+$/, '')}/${googleApplicationCredentials.slice(2)}`;
    } else if (
      !googleApplicationCredentials.startsWith('/') &&
      !/^[A-Za-z]:[\\/]/.test(googleApplicationCredentials) &&
      sessionCwd
    ) {
      googleApplicationCredentials = `${sessionCwd.replace(/\/+$/, '')}/${googleApplicationCredentials.replace(/^\.\//, '')}`;
    }
  }

  // Interactive override defaults to false whenever cloud mode is active
  const defaultInteractiveOverride = false;
  const interactiveOverride = parseBool(
    raw.ARMORCEPT_INTERACTIVE_OVERRIDE,
    defaultInteractiveOverride
  );

  return {
    mode,
    failOpen,
    promptArmorEndpoint: stripQuotes(raw.PROMPT_ARMOR_ENDPOINT) || 'stdio',
    promptArmorTimeoutMs,
    waterfallAllowBelow,
    waterfallBlockAbove,
    waterfallMinConfidence,
    waterfallAlwaysRunCloudDlp: parseBool(
      raw.WATERFALL_ALWAYS_RUN_CLOUD_DLP,
      true
    ),
    localDlpAction,
    allowGcloudAdc: parseBool(raw.ARMORCEPT_ALLOW_GCLOUD_ADC, false),
    scanToolResults: parseBool(raw.ARMORCEPT_SCAN_TOOL_RESULTS, false),
    interactiveOverride,
    exemptTools: parseCsvList(raw.ARMORCEPT_EXEMPT_TOOLS),
    allowlistPaths: parseCsvList(raw.ARMORCEPT_ALLOWLIST_PATHS),
    googleApplicationCredentials,
    googleCloudAccessToken: stripQuotes(raw.GOOGLE_CLOUD_ACCESS_TOKEN),
    googleCloudProject,
    googleCloudLocation: stripQuotes(raw.GOOGLE_CLOUD_LOCATION) || 'us-central1',
    modelArmorTemplateId,
    modelArmorTimeoutMs,
  };
}

export async function readRuntimeConfig(
  $: EngineInterface,
  forceRefresh = false
): Promise<RuntimeConfig> {
  if (cachedConfig && !forceRefresh) {
    return cachedConfig;
  }

  // Read fail-open first so lastKnownFailOpen is updated even if another variable fails validation
  const rawFailOpen = await $.env.get('ARMORCEPT_FAIL_OPEN');
  try {
    lastKnownFailOpen = parseBool(rawFailOpen, false);
  } catch {
    lastKnownFailOpen = false;
  }

  const [
    rawMode,
    rawEndpoint,
    rawLocalTimeout,
    rawAllowBelow,
    rawBlockAbove,
    rawMinConfidence,
    rawAlwaysCloudDlp,
    rawLocalDlpAction,
    rawAllowGcloudAdc,
    rawScanToolResults,
    rawInteractiveOverride,
    rawExemptTools,
    rawAllowlistPaths,
    rawGcpCreds,
    rawGcpToken,
    rawGcpProject,
    rawGcpLocation,
    rawTemplateId,
    rawCloudTimeout,
    rawHome,
  ] = await Promise.all([
    $.env.get('ARMORCEPT_MODE'),
    $.env.get('PROMPT_ARMOR_ENDPOINT'),
    $.env.get('PROMPT_ARMOR_TIMEOUT_MS'),
    $.env.get('WATERFALL_ALLOW_BELOW'),
    $.env.get('WATERFALL_BLOCK_ABOVE'),
    $.env.get('WATERFALL_MIN_CONFIDENCE'),
    $.env.get('WATERFALL_ALWAYS_RUN_CLOUD_DLP'),
    $.env.get('ARMORCEPT_LOCAL_DLP_ACTION'),
    $.env.get('ARMORCEPT_ALLOW_GCLOUD_ADC'),
    $.env.get('ARMORCEPT_SCAN_TOOL_RESULTS'),
    $.env.get('ARMORCEPT_INTERACTIVE_OVERRIDE'),
    $.env.get('ARMORCEPT_EXEMPT_TOOLS'),
    $.env.get('ARMORCEPT_ALLOWLIST_PATHS'),
    $.env.get('GOOGLE_APPLICATION_CREDENTIALS'),
    $.env.get('GOOGLE_CLOUD_ACCESS_TOKEN'),
    $.env.get('GOOGLE_CLOUD_PROJECT'),
    $.env.get('GOOGLE_CLOUD_LOCATION'),
    $.env.get('MODEL_ARMOR_TEMPLATE_ID'),
    $.env.get('MODEL_ARMOR_TIMEOUT_MS'),
    $.env.get('HOME'),
  ]);

  let sessionCwd: string | undefined;
  try {
    sessionCwd = await $.session.cwd();
  } catch {
    sessionCwd = undefined;
  }

  // Check managed policy settings so enterprise policy outranks user overrides
  let policyEnv: Record<string, string> = {};
  try {
    const policySettings = await $.settings.read({ source: 'policy' });
    if (
      policySettings &&
      typeof policySettings === 'object' &&
      'env' in policySettings &&
      policySettings.env &&
      typeof policySettings.env === 'object'
    ) {
      policyEnv = policySettings.env as Record<string, string>;
    }
  } catch {
    // Managed policy source may not be present in test or standalone runs
  }

  const cfg = buildRuntimeConfig(
    {
      ARMORCEPT_MODE: policyEnv['ARMORCEPT_MODE'] ?? rawMode,
      ARMORCEPT_FAIL_OPEN: policyEnv['ARMORCEPT_FAIL_OPEN'] ?? rawFailOpen,
      PROMPT_ARMOR_ENDPOINT:
        policyEnv['PROMPT_ARMOR_ENDPOINT'] ?? rawEndpoint,
      PROMPT_ARMOR_TIMEOUT_MS:
        policyEnv['PROMPT_ARMOR_TIMEOUT_MS'] ?? rawLocalTimeout,
      WATERFALL_ALLOW_BELOW:
        policyEnv['WATERFALL_ALLOW_BELOW'] ?? rawAllowBelow,
      WATERFALL_BLOCK_ABOVE:
        policyEnv['WATERFALL_BLOCK_ABOVE'] ?? rawBlockAbove,
      WATERFALL_MIN_CONFIDENCE:
        policyEnv['WATERFALL_MIN_CONFIDENCE'] ?? rawMinConfidence,
      WATERFALL_ALWAYS_RUN_CLOUD_DLP:
        policyEnv['WATERFALL_ALWAYS_RUN_CLOUD_DLP'] ?? rawAlwaysCloudDlp,
      ARMORCEPT_LOCAL_DLP_ACTION:
        policyEnv['ARMORCEPT_LOCAL_DLP_ACTION'] ?? rawLocalDlpAction,
      ARMORCEPT_ALLOW_GCLOUD_ADC:
        policyEnv['ARMORCEPT_ALLOW_GCLOUD_ADC'] ?? rawAllowGcloudAdc,
      ARMORCEPT_SCAN_TOOL_RESULTS:
        policyEnv['ARMORCEPT_SCAN_TOOL_RESULTS'] ?? rawScanToolResults,
      ARMORCEPT_INTERACTIVE_OVERRIDE:
        policyEnv['ARMORCEPT_INTERACTIVE_OVERRIDE'] ?? rawInteractiveOverride,
      ARMORCEPT_EXEMPT_TOOLS:
        policyEnv['ARMORCEPT_EXEMPT_TOOLS'] ?? rawExemptTools,
      ARMORCEPT_ALLOWLIST_PATHS:
        policyEnv['ARMORCEPT_ALLOWLIST_PATHS'] ?? rawAllowlistPaths,
      GOOGLE_APPLICATION_CREDENTIALS:
        policyEnv['GOOGLE_APPLICATION_CREDENTIALS'] ?? rawGcpCreds,
      GOOGLE_CLOUD_ACCESS_TOKEN:
        policyEnv['GOOGLE_CLOUD_ACCESS_TOKEN'] ?? rawGcpToken,
      GOOGLE_CLOUD_PROJECT:
        policyEnv['GOOGLE_CLOUD_PROJECT'] ?? rawGcpProject,
      GOOGLE_CLOUD_LOCATION:
        policyEnv['GOOGLE_CLOUD_LOCATION'] ?? rawGcpLocation,
      MODEL_ARMOR_TEMPLATE_ID:
        policyEnv['MODEL_ARMOR_TEMPLATE_ID'] ?? rawTemplateId,
      MODEL_ARMOR_TIMEOUT_MS:
        policyEnv['MODEL_ARMOR_TIMEOUT_MS'] ?? rawCloudTimeout,
      HOME: rawHome,
    },
    sessionCwd
  );

  // If cloud mode is active, disallow interactive override unless explicitly permitted by managed policy
  let policyAllowsInteractiveOverride = false;
  try {
    policyAllowsInteractiveOverride = parseBool(
      policyEnv['ARMORCEPT_INTERACTIVE_OVERRIDE'],
      false
    );
  } catch {
    policyAllowsInteractiveOverride = false;
  }
  if (
    (cfg.mode === 'CLOUD' || cfg.mode === 'WATERFALL') &&
    !policyAllowsInteractiveOverride
  ) {
    cfg.interactiveOverride = false;
  }

  cachedConfig = cfg;
  return cfg;
}
