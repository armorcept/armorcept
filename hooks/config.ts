/**
 * ArmorCept — Runtime Configuration & Validation
 */

import type { EngineInterface } from 'claude-code';
import { resolvePythonBinary } from './engines';
import { clearExactSecrets, readEnvValues, setExactSecrets } from './secrets';
import type {
  ArmorCeptMode,
  Enforcement,
  LocalDlpAction,
  RuntimeConfig,
  ToolResultAction,
} from './types';

let cachedConfig: RuntimeConfig | undefined;
let lastKnownFailOpen = false;
let lastKnownAudit = false;

export function resetRuntimeConfigCache(): void {
  cachedConfig = undefined;
  lastKnownFailOpen = false;
  lastKnownAudit = false;
}

/** Whether an unhandled hook error should let the action through (fail-open or audit mode). */
export function getLastKnownFailOpen(): boolean {
  if (cachedConfig) {
    return cachedConfig.failOpen || cachedConfig.enforcement === 'audit';
  }
  return lastKnownFailOpen || lastKnownAudit;
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

/** Expands ~/ against HOME and resolves relative paths against the session cwd. */
export function resolveUserPath(
  value: string | undefined,
  home: string | undefined,
  sessionCwd: string | undefined
): string | undefined {
  if (!value) return undefined;
  if (value.startsWith('~/')) {
    // Never fall through to a cwd-relative "~" directory inside the repository
    if (!home) throw new Error(`Cannot expand "${value}": HOME is not set`);
    return `${home.replace(/\/+$/, '')}/${value.slice(2)}`;
  }
  if (!value.startsWith('/') && !/^[A-Za-z]:[\\/]/.test(value) && sessionCwd) {
    return `${sessionCwd.replace(/\/+$/, '')}/${value.replace(/^\.\//, '')}`;
  }
  return value;
}

/** Every environment variable the configuration reads. */
export const CONFIG_ENV_NAMES = [
  'ARMORCEPT_MODE',
  'ARMORCEPT_FAIL_OPEN',
  'PROMPT_ARMOR_ENDPOINT',
  'PROMPT_ARMOR_TIMEOUT_MS',
  'WATERFALL_ALLOW_BELOW',
  'WATERFALL_BLOCK_ABOVE',
  'WATERFALL_MIN_CONFIDENCE',
  'WATERFALL_ALWAYS_RUN_CLOUD_DLP',
  'ARMORCEPT_LOCAL_DLP_ACTION',
  'ARMORCEPT_ALLOW_GCLOUD_ADC',
  'ARMORCEPT_SCAN_TOOL_RESULTS',
  'ARMORCEPT_INTERACTIVE_OVERRIDE',
  'ARMORCEPT_EXEMPT_TOOLS',
  'ARMORCEPT_ALLOWLIST_PATHS',
  'ARMORCEPT_EXTRA_PATTERNS',
  'ARMORCEPT_SECRET_ENV_VARS',
  'ARMORCEPT_ENFORCEMENT',
  'ARMORCEPT_TOOL_RESULT_ACTION',
  'ARMORCEPT_AUDIT_ENFORCE_SECRETS',
  'ARMORCEPT_DECISION_LOG',
  'ARMORCEPT_DECISION_LOG_MAX_BYTES',
  'GOOGLE_APPLICATION_CREDENTIALS',
  'GOOGLE_CLOUD_ACCESS_TOKEN',
  'GOOGLE_CLOUD_PROJECT',
  'GOOGLE_CLOUD_LOCATION',
  'MODEL_ARMOR_TEMPLATE_ID',
  'MODEL_ARMOR_TIMEOUT_MS',
  'HOME',
] as const;

export type ConfigEnvName = (typeof CONFIG_ENV_NAMES)[number];
export type RawConfigEnv = Partial<Record<ConfigEnvName, string>>;

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
  const googleApplicationCredentials = resolveUserPath(
    stripQuotes(raw.GOOGLE_APPLICATION_CREDENTIALS),
    rawHome,
    sessionCwd
  );
  const extraPatternsPath = resolveUserPath(
    stripQuotes(raw.ARMORCEPT_EXTRA_PATTERNS),
    rawHome,
    sessionCwd
  );

  const rawEnforcement = stripQuotes(raw.ARMORCEPT_ENFORCEMENT)?.toLowerCase();
  let enforcement: Enforcement = 'enforce';
  if (rawEnforcement) {
    if (rawEnforcement === 'enforce' || rawEnforcement === 'audit') {
      enforcement = rawEnforcement;
    } else {
      throw new Error(
        `Invalid ARMORCEPT_ENFORCEMENT "${raw.ARMORCEPT_ENFORCEMENT}". Expected enforce or audit.`
      );
    }
  }
  lastKnownAudit = enforcement === 'audit';

  const rawResultAction = stripQuotes(raw.ARMORCEPT_TOOL_RESULT_ACTION)?.toLowerCase();
  let toolResultAction: ToolResultAction = 'withhold';
  if (rawResultAction) {
    if (rawResultAction === 'withhold' || rawResultAction === 'redact') {
      toolResultAction = rawResultAction;
    } else {
      throw new Error(
        `Invalid ARMORCEPT_TOOL_RESULT_ACTION "${raw.ARMORCEPT_TOOL_RESULT_ACTION}". Expected withhold or redact.`
      );
    }
  }

  const decisionLogMaxBytes = parseFiniteNumber(
    raw.ARMORCEPT_DECISION_LOG_MAX_BYTES,
    10 * 1024 * 1024,
    'ARMORCEPT_DECISION_LOG_MAX_BYTES'
  );
  if (decisionLogMaxBytes < 0 || !Number.isInteger(decisionLogMaxBytes)) {
    throw new Error(
      'ARMORCEPT_DECISION_LOG_MAX_BYTES must be a non-negative whole number of bytes (0 disables rotation).'
    );
  }

  const secretEnvVars = parseCsvList(raw.ARMORCEPT_SECRET_ENV_VARS);
  for (const name of secretEnvVars) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
      throw new Error(
        `Invalid ARMORCEPT_SECRET_ENV_VARS entry "${name}": expected environment variable names separated by commas.`
      );
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
    enforcement,
    auditEnforceSecrets: parseBool(raw.ARMORCEPT_AUDIT_ENFORCE_SECRETS, false),
    decisionLogPath: resolveUserPath(
      stripQuotes(raw.ARMORCEPT_DECISION_LOG),
      rawHome,
      sessionCwd
    ),
    decisionLogMaxBytes,
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
    toolResultAction,
    interactiveOverride,
    exemptTools: parseCsvList(raw.ARMORCEPT_EXEMPT_TOOLS),
    allowlistPaths: parseCsvList(raw.ARMORCEPT_ALLOWLIST_PATHS),
    extraPatternsPath,
    secretEnvVars,
    ignoredRepoSettings: [],
    googleApplicationCredentials,
    googleCloudAccessToken: stripQuotes(raw.GOOGLE_CLOUD_ACCESS_TOKEN),
    googleCloudProject,
    googleCloudLocation: stripQuotes(raw.GOOGLE_CLOUD_LOCATION) || 'us-central1',
    modelArmorTemplateId,
    modelArmorTimeoutMs,
  };
}

// ---------------------------------------------------------------------------
// Settings a repository may not weaken
// ---------------------------------------------------------------------------

type SettingsLayerSource = 'user' | 'project' | 'local' | 'flag' | 'policy';

const norm = (v: string): string => (stripQuotes(v) ?? '').trim().toLowerCase();
const truthy = (v: string): boolean => ['true', '1', 'yes'].includes(norm(v));

/**
 * Values a repository's own settings may set, by variable: each rule says
 * whether a value only adds protection. A variable with no rule here is
 * never taken from a repository, so a new variable is guarded until someone
 * decides otherwise. `trusted` is the value from policy, --settings or user
 * settings, if any.
 */
export const REPO_ALLOWED_VALUES: Readonly<
  Partial<Record<ConfigEnvName, (value: string, trusted: string | undefined) => boolean>>
> = {
  ARMORCEPT_ENFORCEMENT: (v) => norm(v) === 'enforce',
  ARMORCEPT_FAIL_OPEN: (v) => !truthy(v),
  ARMORCEPT_INTERACTIVE_OVERRIDE: (v) => !truthy(v),
  ARMORCEPT_ALLOW_GCLOUD_ADC: (v) => !truthy(v),
  ARMORCEPT_AUDIT_ENFORCE_SECRETS: (v) => truthy(v),
  ARMORCEPT_SCAN_TOOL_RESULTS: (v) => truthy(v),
  WATERFALL_ALWAYS_RUN_CLOUD_DLP: (v) => truthy(v),
  ARMORCEPT_LOCAL_DLP_ACTION: (v) => norm(v) === 'block',
  ARMORCEPT_TOOL_RESULT_ACTION: (v) => norm(v) === 'withhold',
  ARMORCEPT_EXEMPT_TOOLS: (v) => parseCsvList(v).length === 0,
  ARMORCEPT_ALLOWLIST_PATHS: (v) => parseCsvList(v).length === 0,
  // A repository may add names to match, never drop the trusted ones
  ARMORCEPT_SECRET_ENV_VARS: (v, trusted) => {
    const names = new Set(parseCsvList(v));
    return parseCsvList(trusted).every((n) => names.has(n));
  },
};

async function readLayerEnv(
  $: EngineInterface,
  source: SettingsLayerSource
): Promise<Record<string, string> | undefined> {
  try {
    const layer: unknown = await $.settings.read({ source });
    if (!layer || typeof layer !== 'object') return undefined;
    const env = 'env' in layer ? (layer as { env?: unknown }).env : undefined;
    if (env === undefined) return {};
    if (!env || typeof env !== 'object') return {};
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(env as Record<string, unknown>)) {
      if (v !== undefined && v !== null) out[k] = String(v);
    }
    return out;
  } catch {
    return undefined;
  }
}

/**
 * Drops configuration values that only a repository's settings supply,
 * unless REPO_ALLOWED_VALUES says the value only adds protection. A value
 * stays when managed policy, user settings or `--settings` give the same
 * value, or when one of those sets ARMORCEPT_TRUST_PROJECT_SETTINGS=true.
 *
 * If the project or local layer can't be read, any value not confirmed by a
 * trusted layer is treated as the repository's.
 *
 * Returns the names dropped; `raw` is changed in place.
 */
export async function dropRepoWeakenedSettings(
  $: EngineInterface,
  raw: RawConfigEnv,
  policyEnv: Record<string, string>
): Promise<string[]> {
  const [user = {}, project, local, flag = {}] = await Promise.all([
    readLayerEnv($, 'user'),
    readLayerEnv($, 'project'),
    readLayerEnv($, 'local'),
    readLayerEnv($, 'flag'),
  ]);
  const trustFlag =
    policyEnv['ARMORCEPT_TRUST_PROJECT_SETTINGS'] ??
    flag['ARMORCEPT_TRUST_PROJECT_SETTINGS'] ??
    user['ARMORCEPT_TRUST_PROJECT_SETTINGS'];
  if (trustFlag !== undefined && truthy(trustFlag)) return [];
  const repoUnreadable = project === undefined || local === undefined;

  const dropped: string[] = [];
  for (const name of CONFIG_ENV_NAMES) {
    if (name in policyEnv) continue;
    const effective = raw[name];
    if (effective === undefined) continue;
    const repoValue = local?.[name] ?? project?.[name];
    if (repoValue === undefined && !repoUnreadable) continue;
    if (repoValue !== undefined && effective !== repoValue) continue;
    const trusted = flag[name] ?? user[name];
    if (trusted === effective) continue;
    if (repoValue === undefined && name === 'HOME') continue; // the shell's own HOME
    const allowed = REPO_ALLOWED_VALUES[name];
    if (allowed && allowed(effective, trusted)) continue;
    raw[name] = trusted;
    dropped.push(name);
  }
  return dropped;
}

export async function readRuntimeConfig(
  $: EngineInterface,
  forceRefresh = false
): Promise<RuntimeConfig> {
  if (cachedConfig && !forceRefresh) {
    return cachedConfig;
  }

  const rawFailOpen = await $.env.get('ARMORCEPT_FAIL_OPEN');

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
    rawExtraPatterns,
    rawSecretEnvVars,
    rawEnforcement,
    rawToolResultAction,
    rawAuditEnforceSecrets,
    rawDecisionLog,
    rawDecisionLogMaxBytes,
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
    $.env.get('ARMORCEPT_EXTRA_PATTERNS'),
    $.env.get('ARMORCEPT_SECRET_ENV_VARS'),
    $.env.get('ARMORCEPT_ENFORCEMENT'),
    $.env.get('ARMORCEPT_TOOL_RESULT_ACTION'),
    $.env.get('ARMORCEPT_AUDIT_ENFORCE_SECRETS'),
    $.env.get('ARMORCEPT_DECISION_LOG'),
    $.env.get('ARMORCEPT_DECISION_LOG_MAX_BYTES'),
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

  const raw: RawConfigEnv = {
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
      ARMORCEPT_EXTRA_PATTERNS:
        policyEnv['ARMORCEPT_EXTRA_PATTERNS'] ?? rawExtraPatterns,
      ARMORCEPT_SECRET_ENV_VARS:
        policyEnv['ARMORCEPT_SECRET_ENV_VARS'] ?? rawSecretEnvVars,
      ARMORCEPT_ENFORCEMENT:
        policyEnv['ARMORCEPT_ENFORCEMENT'] ?? rawEnforcement,
      ARMORCEPT_TOOL_RESULT_ACTION:
        policyEnv['ARMORCEPT_TOOL_RESULT_ACTION'] ?? rawToolResultAction,
      ARMORCEPT_AUDIT_ENFORCE_SECRETS:
        policyEnv['ARMORCEPT_AUDIT_ENFORCE_SECRETS'] ?? rawAuditEnforceSecrets,
      ARMORCEPT_DECISION_LOG:
        policyEnv['ARMORCEPT_DECISION_LOG'] ?? rawDecisionLog,
      ARMORCEPT_DECISION_LOG_MAX_BYTES:
        policyEnv['ARMORCEPT_DECISION_LOG_MAX_BYTES'] ?? rawDecisionLogMaxBytes,
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
  };
  const ignoredRepoSettings = await dropRepoWeakenedSettings($, raw, policyEnv);
  // Set before validation, so lastKnownFailOpen is current even if another
  // variable fails validation, and only from a value that passed the guard
  try {
    lastKnownFailOpen = parseBool(raw.ARMORCEPT_FAIL_OPEN, false);
  } catch {
    lastKnownFailOpen = false;
  }
  const cfg = buildRuntimeConfig(raw, sessionCwd);
  cfg.ignoredRepoSettings = ignoredRepoSettings;

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

  // Values stay in hooks/secrets.ts memory only; they are never put on cfg.
  clearExactSecrets();
  if (cfg.secretEnvVars.length > 0) {
    const { binary } = await resolvePythonBinary($);
    setExactSecrets(await readEnvValues($, cfg.secretEnvVars, binary));
  }

  cachedConfig = cfg;
  return cfg;
}
