/**
 * ArmorCept — Claude Code Security Mod Hooks Module
 *
 * Self-contained hooks module for Claude Code's hardened VM sandbox.
 * Enforces client-side DLP and Prompt Injection protection across:
 *   - LOCAL mode (prompt-armor local daemon via stdio or localhost HTTP)
 *   - CLOUD mode (Google Cloud Model Armor REST API)
 *   - WATERFALL mode (Tier 1 local fast-path + Tier 2 cloud deep escalation)
 */

interface RuntimeConfig {
  mode: 'LOCAL' | 'CLOUD' | 'WATERFALL';
  failOpen: boolean;
  promptArmorEndpoint: string;
  promptArmorTimeoutMs: number;
  waterfallAllowBelow: number;
  waterfallBlockAbove: number;
  waterfallMinConfidence: number;
  waterfallAlwaysRunCloudDlp: boolean;
  googleApplicationCredentials?: string;
  googleCloudAccessToken?: string;
  googleCloudProject?: string;
  googleCloudLocation: string;
  modelArmorTemplateId?: string;
  modelArmorTimeoutMs: number;
}

interface PromptArmorResult {
  score: number;
  confidence: number;
  decision: 'ALLOW' | 'BLOCK' | 'ESCALATE';
  findings: string[];
  latency_ms?: number;
  engine_mode?: 'full' | 'lightweight_fallback';
  warning?: string;
}

interface EvaluationVerdict {
  decision: 'ALLOW' | 'BLOCK';
  source: 'Prompt-Armor' | 'Model Armor' | 'ArmorCept';
  mode: 'LOCAL' | 'CLOUD' | 'WATERFALL';
  reason: string;
  findings: string[];
  score?: number;
  confidence?: number;
  escalatedToCloud?: boolean;
  engineMode?: 'full' | 'lightweight_fallback';
  warning?: string;
}

function parseBool(val: string | undefined, fallback: boolean): boolean {
  if (val === undefined || val.trim() === '') return fallback;
  const norm = val.trim().toLowerCase();
  if (norm === 'true' || norm === '1' || norm === 'yes') return true;
  if (norm === 'false' || norm === '0' || norm === 'no') return false;
  return fallback;
}

function parseNum(val: string | undefined, fallback: number): number {
  if (val === undefined || val.trim() === '') return fallback;
  const n = Number(val);
  return Number.isFinite(n) ? n : fallback;
}

function stripQuotes(val: string | undefined): string | undefined {
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

async function readRuntimeConfig($: any): Promise<RuntimeConfig> {
  const rawMode = await $.env.get('ARMORCEPT_MODE');
  const rawFailOpen = await $.env.get('ARMORCEPT_FAIL_OPEN');
  const rawEndpoint = await $.env.get('PROMPT_ARMOR_ENDPOINT');
  const rawLocalTimeout = await $.env.get('PROMPT_ARMOR_TIMEOUT_MS');
  const rawAllowBelow = await $.env.get('WATERFALL_ALLOW_BELOW');
  const rawBlockAbove = await $.env.get('WATERFALL_BLOCK_ABOVE');
  const rawMinConfidence = await $.env.get('WATERFALL_MIN_CONFIDENCE');
  const rawAlwaysCloudDlp = await $.env.get('WATERFALL_ALWAYS_RUN_CLOUD_DLP');
  const rawGcpCreds = await $.env.get('GOOGLE_APPLICATION_CREDENTIALS');
  const rawGcpToken = await $.env.get('GOOGLE_CLOUD_ACCESS_TOKEN');
  const rawGcpProject = await $.env.get('GOOGLE_CLOUD_PROJECT');
  const rawGcpLocation = await $.env.get('GOOGLE_CLOUD_LOCATION');
  const rawTemplateId = await $.env.get('MODEL_ARMOR_TEMPLATE_ID');
  const rawCloudTimeout = await $.env.get('MODEL_ARMOR_TIMEOUT_MS');
  const rawHome = await $.env.get('HOME');

  const googleCloudProject = stripQuotes(rawGcpProject);
  const modelArmorTemplateId = stripQuotes(rawTemplateId);
  const hasCloudConfig = Boolean(googleCloudProject && modelArmorTemplateId);

  let googleApplicationCredentials = stripQuotes(rawGcpCreds);
  if (googleApplicationCredentials) {
    if (googleApplicationCredentials.startsWith('~/') && rawHome) {
      googleApplicationCredentials = `${rawHome.replace(/\/+$/, '')}/${googleApplicationCredentials.slice(2)}`;
    } else if (!googleApplicationCredentials.startsWith('/')) {
      try {
        const sessionCwd = await $.session.cwd();
        if (sessionCwd) {
          googleApplicationCredentials = `${sessionCwd.replace(/\/+$/, '')}/${googleApplicationCredentials.replace(/^\.\//, '')}`;
        }
      } catch {
        // Keep as-is if session.cwd is unavailable
      }
    }
  }

  let mode: 'LOCAL' | 'CLOUD' | 'WATERFALL' = 'WATERFALL';
  const normalizedMode = stripQuotes(rawMode)?.toUpperCase();
  if (
    normalizedMode === 'LOCAL' ||
    normalizedMode === 'CLOUD' ||
    normalizedMode === 'WATERFALL'
  ) {
    mode = normalizedMode;
  } else if (!hasCloudConfig) {
    // Default to LOCAL mode when GCP vars are not set and ARMORCEPT_MODE was not explicitly set
    mode = 'LOCAL';
  }

  return {
    mode,
    failOpen: parseBool(rawFailOpen, false),
    promptArmorEndpoint: stripQuotes(rawEndpoint) || 'stdio',
    promptArmorTimeoutMs: parseNum(rawLocalTimeout, 8000),
    waterfallAllowBelow: parseNum(rawAllowBelow, 0.3),
    waterfallBlockAbove: parseNum(rawBlockAbove, 0.75),
    waterfallMinConfidence: parseNum(rawMinConfidence, 0.8),
    waterfallAlwaysRunCloudDlp: parseBool(rawAlwaysCloudDlp, true),
    googleApplicationCredentials,
    googleCloudAccessToken: stripQuotes(rawGcpToken),
    googleCloudProject,
    googleCloudLocation: stripQuotes(rawGcpLocation) || 'us-central1',
    modelArmorTemplateId,
    modelArmorTimeoutMs: parseNum(rawCloudTimeout, 5000),
  };
}

function getStatusBadge(
  mode: 'LOCAL' | 'CLOUD' | 'WATERFALL',
  engineMode?: 'full' | 'lightweight_fallback'
): string {
  if (engineMode === 'lightweight_fallback') {
    return '🛡️ ArmorCept: Active (Local - Lightweight Test Mode)';
  }
  const label =
    mode === 'LOCAL' ? 'Local' : mode === 'CLOUD' ? 'Cloud' : 'Waterfall';
  return `🛡️ ArmorCept: Active (${label})`;
}

function formatAlertBanner(
  verdict: EvaluationVerdict,
  toolName?: string
): string {
  const extraFindings = verdict.findings.filter((f) => f !== verdict.reason);
  const findingsSuffix =
    extraFindings.length > 0 ? ` [${extraFindings.join(', ')}]` : '';
  const scoreSuffix =
    typeof verdict.score === 'number'
      ? ` (score: ${verdict.score.toFixed(2)}${
          typeof verdict.confidence === 'number'
            ? `, confidence: ${verdict.confidence.toFixed(2)}`
            : ''
        })`
      : '';
  const targetPrefix = toolName ? `Tool (${toolName}) — ` : '';
  return `🛡️ [ArmorCept Blocked] Source: ${verdict.source} | Reason: ${targetPrefix}${verdict.reason}${findingsSuffix}${scoreSuffix}`;
}

function formatToolDenyMessage(
  verdict: EvaluationVerdict,
  toolName: string
): string {
  const details =
    verdict.findings.length > 0
      ? verdict.findings.join(', ')
      : verdict.reason;
  return `Tool execution blocked by ArmorCept security policy (${verdict.source}) for tool "${toolName}": ${details}. Do not retry this tool call with sensitive data or unsafe instructions.`;
}

function parsePromptArmorJson(parsed: any): PromptArmorResult {
  const rawList = Array.isArray(parsed.categories)
    ? parsed.categories
    : Array.isArray(parsed.findings)
      ? parsed.findings
      : [];
  return {
    score: Number(parsed.risk_score ?? parsed.score ?? 0),
    confidence: Number(parsed.confidence ?? 1),
    decision: String(parsed.decision ?? 'ALLOW').toUpperCase() as
      | 'ALLOW'
      | 'BLOCK'
      | 'ESCALATE',
    findings: rawList.map(String),
    latency_ms: parsed.latency_ms,
    engine_mode: parsed.engine_mode,
    warning: parsed.warning,
  };
}

async function resolvePythonBinary($: any): Promise<string> {
  const venvPython = `${$.plugin.root}/.venv/bin/python`;
  try {
    const hasVenv = await $.fs.exists(venvPython);
    if (hasVenv) {
      return venvPython;
    }
  } catch {
    // Fallback to system python3
  }
  return 'python3';
}

async function runPromptArmor($: any, text: string, cfg: RuntimeConfig): Promise<PromptArmorResult> {
  if (
    cfg.promptArmorEndpoint.startsWith('http://') ||
    cfg.promptArmorEndpoint.startsWith('https://')
  ) {
    const res = await $.http.fetch(cfg.promptArmorEndpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    if (!res.ok) {
      throw new Error(`prompt-armor HTTP ${res.status}: ${res.text}`);
    }
    const parsed = JSON.parse(res.text);
    return parsePromptArmorJson(parsed);
  }

  const pythonBin = await resolvePythonBinary($);
  const daemonPath = `${$.plugin.root}/python/daemon.py`;
  const proc = await $.process.run([pythonBin, daemonPath, '--mode', 'stdio'], {
    stdin: JSON.stringify({ text }) + '\n',
    timeoutMs: cfg.promptArmorTimeoutMs,
  });

  if (proc.exitCode !== 0) {
    throw new Error(
      `prompt-armor daemon exited ${proc.exitCode}: ${proc.stderr || proc.stdout}`
    );
  }

  const lines = proc.stdout
    .split('\n')
    .map((l: string) => l.trim())
    .filter(Boolean);
  const lastLine = lines[lines.length - 1];
  if (!lastLine) {
    throw new Error('Empty stdout from prompt-armor daemon');
  }

  const parsed = JSON.parse(lastLine);
  if (parsed.error) {
    throw new Error(`prompt-armor daemon error: ${parsed.error}`);
  }

  return parsePromptArmorJson(parsed);
}

async function mintCloudAccessToken($: any, cfg: RuntimeConfig): Promise<string> {
  if (cfg.googleCloudAccessToken) {
    return cfg.googleCloudAccessToken;
  }

  let mintError = '';
  const mintScript = `${$.plugin.root}/scripts/mint-token.mjs`;
  const args = cfg.googleApplicationCredentials
    ? ['node', mintScript, cfg.googleApplicationCredentials]
    : ['node', mintScript];

  try {
    const nodeRes = await $.process.run(args, {
      timeoutMs: cfg.modelArmorTimeoutMs,
    });
    if (nodeRes.exitCode === 0 && nodeRes.stdout.trim()) {
      return nodeRes.stdout.trim();
    }
    mintError = (nodeRes.stderr || nodeRes.stdout || '').trim();
  } catch (err) {
    mintError = err instanceof Error ? err.message : String(err);
  }

  try {
    const gcloudRes = await $.process.run(
      ['gcloud', 'auth', 'application-default', 'print-access-token'],
      { timeoutMs: cfg.modelArmorTimeoutMs }
    );
    if (gcloudRes.exitCode === 0 && gcloudRes.stdout.trim()) {
      return gcloudRes.stdout.trim();
    }
  } catch {
    // gcloud not on PATH or failed
  }

  const detail = mintError ? ` (${mintError})` : '';
  throw new Error(
    `Unable to obtain Google Cloud OAuth2 access token for Model Armor${detail}. Ensure GOOGLE_APPLICATION_CREDENTIALS is exported in the same terminal before starting claude.`
  );
}

async function runModelArmor(
  $: any,
  text: string,
  cfg: RuntimeConfig,
  escalatedToCloud: boolean
): Promise<EvaluationVerdict> {
  if (!cfg.googleCloudProject || !cfg.modelArmorTemplateId) {
    throw new Error(
      `Missing GOOGLE_CLOUD_PROJECT or MODEL_ARMOR_TEMPLATE_ID for ${cfg.mode} mode.`
    );
  }

  const token = await mintCloudAccessToken($, cfg);
  const url = `https://modelarmor.${cfg.googleCloudLocation}.rep.googleapis.com/v1/projects/${encodeURIComponent(
    cfg.googleCloudProject
  )}/locations/${encodeURIComponent(
    cfg.googleCloudLocation
  )}/templates/${encodeURIComponent(cfg.modelArmorTemplateId)}:sanitizeUserPrompt`;

  const res = await $.http.fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ userPromptData: { text } }),
  });

  if (!res.ok) {
    throw new Error(`Model Armor API HTTP ${res.status}: ${res.text}`);
  }

  const data = JSON.parse(res.text);
  const result = data?.sanitizationResult ?? {};
  const overallMatch = result.filterMatchState === 'MATCH_FOUND';
  const filters = result.filterResults ?? {};
  const findings: string[] = [];

  const sdp = filters.sdp?.sdpFilterResult;
  const sdpInspect = sdp?.inspectResult;
  const sdpDeid = sdp?.deidentifyResult;
  if (
    sdpInspect?.matchState === 'MATCH_FOUND' ||
    sdpDeid?.matchState === 'MATCH_FOUND'
  ) {
    const infoTypes = (sdpInspect?.findings ?? [])
      .map((f: any) => f?.infoType)
      .filter(Boolean);
    if (infoTypes.length > 0) {
      findings.push(
        `SDP/DLP Violation (${Array.from(new Set(infoTypes)).join(', ')})`
      );
    } else {
      findings.push('SDP/DLP Sensitive Data Violation');
    }
  }

  const pi = filters.piAndJailbreak?.piAndJailbreakFilterResult;
  if (pi?.matchState === 'MATCH_FOUND') {
    findings.push(
      `Prompt Injection / Jailbreak${
        pi.confidenceLevel ? ` (confidence: ${pi.confidenceLevel})` : ''
      }`
    );
  }

  const malUri = filters.maliciousUris?.maliciousUriFilterResult;
  if (malUri?.matchState === 'MATCH_FOUND') {
    findings.push('Malicious URI Detected');
  }

  const rai = filters.rai?.raiFilterResult;
  if (rai?.matchState === 'MATCH_FOUND') {
    findings.push('Responsible AI Safety Policy Violation');
  }

  const csam = filters.csam?.csamFilterResult;
  if (csam?.matchState === 'MATCH_FOUND') {
    findings.push('CSAM Policy Violation');
  }

  if (overallMatch || findings.length > 0) {
    if (findings.length === 0) {
      findings.push('Model Armor Security Policy Match');
    }
    return {
      decision: 'BLOCK',
      source: 'Model Armor',
      mode: cfg.mode,
      reason: findings[0],
      findings,
      escalatedToCloud,
    };
  }

  return {
    decision: 'ALLOW',
    source: 'Model Armor',
    mode: cfg.mode,
    reason: 'Clean payload verified by Google Cloud Model Armor',
    findings: [],
    escalatedToCloud,
  };
}

async function evaluateArmorCept($: any, text: string): Promise<EvaluationVerdict> {
  const cfg = await readRuntimeConfig($);
  $.ui.status('🛡️ ArmorCept: Scanning...');

  try {
    if (cfg.mode === 'LOCAL') {
      const local = await runPromptArmor($, text, cfg);
      if (local.engine_mode === 'lightweight_fallback' && local.warning) {
        $.ui.toast(`⚠️ ArmorCept: ${local.warning}`, { timeoutMs: 6000 });
      }
      const blocked =
        local.decision === 'BLOCK' || local.score >= cfg.waterfallBlockAbove;
      if (blocked) {
        const reason =
          local.findings[0] ??
          `Local threat score ${local.score.toFixed(2)} exceeded threshold`;
        return {
          decision: 'BLOCK',
          source: 'Prompt-Armor',
          mode: 'LOCAL',
          reason,
          findings: local.findings.length > 0 ? local.findings : [reason],
          score: local.score,
          confidence: local.confidence,
          engineMode: local.engine_mode,
          warning: local.warning,
        };
      }
      return {
        decision: 'ALLOW',
        source: 'Prompt-Armor',
        mode: 'LOCAL',
        reason: 'Clean payload verified by local Prompt-Armor',
        findings: local.findings,
        score: local.score,
        confidence: local.confidence,
        engineMode: local.engine_mode,
        warning: local.warning,
      };
    }

    if (cfg.mode === 'CLOUD') {
      return await runModelArmor($, text, cfg, false);
    }

    // WATERFALL mode
    const local = await runPromptArmor($, text, cfg);
    if (local.engine_mode === 'lightweight_fallback' && local.warning) {
      $.ui.toast(`⚠️ ArmorCept: ${local.warning}`, { timeoutMs: 6000 });
    }
    const highConfidenceBlock =
      (local.score >= cfg.waterfallBlockAbove &&
        local.confidence >= cfg.waterfallMinConfidence) ||
      (local.decision === 'BLOCK' &&
        local.confidence >= cfg.waterfallMinConfidence);

    if (highConfidenceBlock) {
      const reason =
        local.findings[0] ??
        `High-confidence local threat (score: ${local.score.toFixed(
          2
        )}, confidence: ${local.confidence.toFixed(2)})`;
      return {
        decision: 'BLOCK',
        source: 'Prompt-Armor',
        mode: 'WATERFALL',
        reason,
        findings: local.findings.length > 0 ? local.findings : [reason],
        score: local.score,
        confidence: local.confidence,
        escalatedToCloud: false,
        engineMode: local.engine_mode,
        warning: local.warning,
      };
    }

    const lowRiskAndConfident =
      local.score < cfg.waterfallAllowBelow &&
      local.confidence >= cfg.waterfallMinConfidence &&
      local.decision === 'ALLOW';

    if (lowRiskAndConfident && !cfg.waterfallAlwaysRunCloudDlp) {
      return {
        decision: 'ALLOW',
        source: 'Prompt-Armor',
        mode: 'WATERFALL',
        reason: 'Fast-path local ALLOW (low risk, high confidence)',
        findings: local.findings,
        score: local.score,
        confidence: local.confidence,
        escalatedToCloud: false,
        engineMode: local.engine_mode,
        warning: local.warning,
      };
    }

    return await runModelArmor($, text, cfg, true);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (cfg.failOpen) {
      return {
        decision: 'ALLOW',
        source: 'ArmorCept',
        mode: cfg.mode,
        reason: `Fail-open triggered after engine error: ${message}`,
        findings: [`EngineError: ${message}`],
      };
    }
    return {
      decision: 'BLOCK',
      source: 'ArmorCept',
      mode: cfg.mode,
      reason: `Fail-closed security block due to engine error: ${message}`,
      findings: [`EngineError: ${message}`],
    };
  }
}

export function register(on: any): void {
  on('session.start', async ($: any, e: any, next: any) => {
    const cfg = await readRuntimeConfig($);
    if (cfg.mode !== 'CLOUD') {
      const venvPython = `${$.plugin.root}/.venv/bin/python`;
      const hasVenv = await $.fs.exists(venvPython).catch(() => false);
      if (!hasVenv) {
        $.ui.toast(
          '⚠️ ArmorCept: running in lightweight local test mode, for full mode install prompt-armor',
          { timeoutMs: 6000 }
        );
        $.ui.status(getStatusBadge(cfg.mode, 'lightweight_fallback'));
        return next(e);
      }
    }
    $.ui.status(getStatusBadge(cfg.mode, 'full'));
    return next(e);
  });

  on('prompt.submit', async ($: any, e: any, next: any) => {
    const promptText =
      typeof e?.text === 'string'
        ? e.text
        : typeof e?.prompt === 'string'
          ? e.prompt
          : '';

    const verdict = await evaluateArmorCept($, promptText);

    if (verdict.decision === 'BLOCK') {
      const banner = formatAlertBanner(verdict);
      $.ui.status(`🛡️ ArmorCept: Blocked (${verdict.source})`);
      $.ui.toast(banner, { timeoutMs: 6000 });
      return { drop: banner };
    }

    $.ui.status(getStatusBadge(verdict.mode, verdict.engineMode));
    return next(e);
  });

  on('tool.call', async ($: any, e: any, next: any) => {
    const toolName = String(e?.tool ?? e?.tool_name ?? 'UnknownTool');
    const argsCopy: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(e ?? {})) {
      if (k !== 'tool' && k !== 'tool_use_id') {
        argsCopy[k] = v;
      }
    }
    const serializedPayload = `Tool: ${toolName}\nArguments: ${JSON.stringify(
      argsCopy,
      null,
      2
    )}`;

    const verdict = await evaluateArmorCept($, serializedPayload);

    if (verdict.decision === 'BLOCK') {
      const banner = formatAlertBanner(verdict, toolName);
      const denyMessage = formatToolDenyMessage(verdict, toolName);
      $.ui.status(`🛡️ ArmorCept: Blocked (${verdict.source})`);
      $.ui.toast(banner, { timeoutMs: 6000 });
      if (typeof e?.tool_use_id === 'string' && e.tool_use_id !== '') {
        $.ui.notice(e.tool_use_id, banner);
      }
      return { deny: denyMessage };
    }

    $.ui.status(getStatusBadge(verdict.mode, verdict.engineMode));
    return next(e);
  });
}

export default register;
