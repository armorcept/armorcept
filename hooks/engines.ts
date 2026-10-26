/**
 * ArmorCept — Local (prompt-armor) and Cloud (Google Cloud Model Armor) Engine Clients
 */

import type {
  EngineInterface,
  HookStream,
  ProcessSpawnChunk,
  ProcessSpawnResult,
} from 'claude-code';
import type {
  EvaluationVerdict,
  PromptArmorDecision,
  PromptArmorResult,
  RuntimeConfig,
} from './types';

interface CachedToken {
  token: string;
  expiresAtMs: number;
  cacheKey: string;
}

let cachedPythonBin: string | undefined;
let cachedHasVenv: boolean | undefined;
let warmDaemonUrl: string | undefined;
let warmDaemonMode: 'full' | 'lightweight_fallback' | undefined;
let daemonAuthToken: string | undefined;
let daemonReadyPromise: Promise<string | undefined> | undefined;
let daemonGeneration = 0;
let daemonWaitExpired = false;
let activeDaemonStream:
  | HookStream<ProcessSpawnChunk, ProcessSpawnResult>
  | undefined;
let lastDaemonSpawnAttemptMs = 0;
let daemonFailureCount = 0;
let cachedCloudToken: CachedToken | undefined;

const READY_WAIT_CAP_MS = 3500;
const READY_WAIT_EXPIRED: unique symbol = Symbol('expired');

export class DaemonTransportError extends Error {}

export function resetEngineState(): void {
  daemonGeneration += 1;
  cachedPythonBin = undefined;
  cachedHasVenv = undefined;
  warmDaemonUrl = undefined;
  warmDaemonMode = undefined;
  daemonAuthToken = undefined;
  daemonReadyPromise = undefined;
  daemonWaitExpired = false;
  activeDaemonStream = undefined;
  lastDaemonSpawnAttemptMs = 0;
  daemonFailureCount = 0;
  cachedCloudToken = undefined;
}

export function getWarmDaemonEngineMode():
  | 'full'
  | 'lightweight_fallback'
  | undefined {
  return warmDaemonMode;
}

export function parsePromptArmorJson(parsed: unknown): PromptArmorResult {
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('Invalid JSON payload from prompt-armor daemon');
  }
  const obj = parsed as Record<string, unknown>;

  if (typeof obj['error'] === 'string' && obj['error']) {
    throw new Error(`prompt-armor daemon error: ${obj['error']}`);
  }

  const rawScore = obj['risk_score'] ?? obj['score'];
  if (
    rawScore === undefined ||
    rawScore === null ||
    (typeof rawScore === 'string' && rawScore.trim() === '')
  ) {
    throw new Error('Missing risk_score in prompt-armor response');
  }
  const numScore = Number(rawScore);
  if (!Number.isFinite(numScore)) {
    throw new Error(
      `Malformed risk_score "${String(rawScore)}" in prompt-armor response`
    );
  }
  const score = Math.min(1, Math.max(0, numScore));

  const rawConf = obj['confidence'] ?? 1;
  const numConf = Number(rawConf);
  if (!Number.isFinite(numConf)) {
    throw new Error(
      `Malformed confidence "${String(rawConf)}" in prompt-armor response`
    );
  }
  const confidence = Math.min(1, Math.max(0, numConf));

  const rawDecision = String(obj['decision'] ?? 'ALLOW')
    .replace(/^Decision\./i, '')
    .trim()
    .toUpperCase();

  let decision: PromptArmorDecision;
  if (
    rawDecision === 'ALLOW' ||
    rawDecision === 'WARN' ||
    rawDecision === 'BLOCK' ||
    rawDecision === 'ESCALATE'
  ) {
    decision = rawDecision;
  } else {
    throw new Error(
      `Unknown decision "${String(obj['decision'])}" in prompt-armor response`
    );
  }

  const rawList = Array.isArray(obj['categories'])
    ? obj['categories']
    : Array.isArray(obj['findings'])
      ? obj['findings']
      : [];

  const rawDlpList = Array.isArray(obj['dlp_categories'])
    ? obj['dlp_categories']
    : [];

  const engineModeRaw = obj['engine_mode'];
  const engine_mode =
    engineModeRaw === 'full' || engineModeRaw === 'lightweight_fallback'
      ? engineModeRaw
      : undefined;

  return {
    score,
    confidence,
    decision,
    findings: rawList.map((item) =>
      String(item).replace(/^Category\./i, '')
    ),
    dlpCategories: rawDlpList.map((item) => String(item)),
    latency_ms:
      typeof obj['latency_ms'] === 'number' ? obj['latency_ms'] : undefined,
    engine_mode,
    warning: typeof obj['warning'] === 'string' ? obj['warning'] : undefined,
  };
}

export async function resolvePythonBinary(
  $: EngineInterface
): Promise<{ binary: string; hasVenv: boolean }> {
  if (cachedPythonBin !== undefined && cachedHasVenv !== undefined) {
    return { binary: cachedPythonBin, hasVenv: cachedHasVenv };
  }

  const candidates = [
    `${$.plugin.root}/.venv/bin/python`,
    `${$.plugin.root}/.venv/Scripts/python.exe`,
  ];

  for (const candidate of candidates) {
    try {
      const exists = await $.fs.exists(candidate);
      if (exists) {
        cachedPythonBin = candidate;
        cachedHasVenv = true;
        return { binary: candidate, hasVenv: true };
      }
    } catch {
      // Ignore fs check error and try next candidate
    }
  }

  cachedPythonBin = 'python3';
  cachedHasVenv = false;
  return { binary: 'python3', hasVenv: false };
}

/**
 * Spawns the warm HTTP daemon for the life of the module. The returned promise
 * settles with the daemon's URL when it reports ready, or with undefined when
 * its process exits first. Callers bound their own wait with awaitWarmDaemon:
 * a slow start never blocks a hook for long and never causes the
 * still-starting process to be killed and respawned.
 */
export function startWarmDaemon($: EngineInterface): Promise<string | undefined> {
  if (warmDaemonUrl) {
    return Promise.resolve(warmDaemonUrl);
  }
  if (daemonReadyPromise) {
    return daemonReadyPromise;
  }

  const myGen = ++daemonGeneration;
  lastDaemonSpawnAttemptMs = Date.now();
  daemonWaitExpired = false;

  const token =
    typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
      ? crypto.randomUUID()
      : `armorcept-${Date.now()}-${Math.random().toString(36).slice(2)}`;
  daemonAuthToken = token;

  let resolveReady: (url: string | undefined) => void = () => {};
  const readyPromise = new Promise<string | undefined>((resolve) => {
    resolveReady = resolve;
  });
  daemonReadyPromise = readyPromise;

  void (async () => {
    let becameReady = false;
    try {
      const { binary } = await resolvePythonBinary($);
      if (daemonGeneration !== myGen) {
        return;
      }
      const daemonPath = `${$.plugin.root}/python/daemon.py`;
      const stream = $.process.spawn({
        argv: [
          binary,
          daemonPath,
          '--mode',
          'http',
          '--host',
          '127.0.0.1',
          '--port',
          '0',
        ],
        env: {
          ARMORCEPT_DAEMON_TOKEN: token,
          HF_HUB_OFFLINE: '1',
        },
      });
      activeDaemonStream = stream;

      let stdoutBuffer = '';
      for await (const chunk of stream) {
        if (daemonGeneration !== myGen) {
          break;
        }
        if (becameReady || chunk.stream !== 'stdout') {
          continue;
        }
        stdoutBuffer += chunk.text;
        const newlineIdx = stdoutBuffer.indexOf('\n');
        if (newlineIdx === -1) {
          continue;
        }
        const firstLine = stdoutBuffer.slice(0, newlineIdx).trim();
        try {
          const info = JSON.parse(firstLine) as Record<string, unknown>;
          if (info['ready'] && typeof info['port'] === 'number') {
            becameReady = true;
            warmDaemonUrl = `http://127.0.0.1:${info['port']}/analyze`;
            if (
              info['engine_mode'] === 'full' ||
              info['engine_mode'] === 'lightweight_fallback'
            ) {
              warmDaemonMode = info['engine_mode'];
            }
            daemonFailureCount = 0;
            resolveReady(warmDaemonUrl);
          }
        } catch {
          // Not the readiness line
        }
      }
    } catch {
      // process.spawn unavailable, or the daemon could not be started
    } finally {
      if (daemonGeneration === myGen) {
        warmDaemonUrl = undefined;
        daemonReadyPromise = undefined;
        activeDaemonStream = undefined;
        daemonFailureCount += 1;
        lastDaemonSpawnAttemptMs = Date.now();
      }
      resolveReady(undefined);
    }
  })();

  return readyPromise;
}

/**
 * Waits for the warm daemon for at most boundMs. Once a wait has expired for
 * the current daemon generation, later callers stop waiting and go straight
 * to the one-shot path; the daemon is adopted as soon as it reports ready.
 */
async function awaitWarmDaemon(
  $: EngineInterface,
  boundMs: number
): Promise<string | undefined> {
  if (warmDaemonUrl) {
    return warmDaemonUrl;
  }
  const pending = daemonReadyPromise;
  if (!pending || daemonWaitExpired) {
    return undefined;
  }
  const gen = daemonGeneration;
  const timer = (async (): Promise<typeof READY_WAIT_EXPIRED> => {
    try {
      await $.clock.sleep(boundMs);
    } catch {
      // An unhooked clock cannot bound the wait: treat it as expired
    }
    return READY_WAIT_EXPIRED;
  })();
  const outcome = await Promise.race([pending, timer]);
  if (outcome === READY_WAIT_EXPIRED) {
    if (daemonGeneration === gen) {
      daemonWaitExpired = true;
    }
    return undefined;
  }
  return outcome;
}

function markDaemonDead(): void {
  daemonGeneration += 1;
  warmDaemonUrl = undefined;
  daemonReadyPromise = undefined;
  daemonWaitExpired = false;
  daemonFailureCount += 1;
  lastDaemonSpawnAttemptMs = Date.now();
  const stream = activeDaemonStream;
  activeDaemonStream = undefined;
  if (stream) {
    try {
      void stream.return({ code: null, signal: null }).catch(() => undefined);
    } catch {
      // Stream already closed
    }
  }
}

async function callHttpDaemon(
  $: EngineInterface,
  endpointUrl: string,
  text: string,
  authToken?: string
): Promise<PromptArmorResult> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (authToken) {
    headers['X-ArmorCept-Token'] = authToken;
  }

  let res;
  try {
    res = await $.http.fetch(endpointUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify({ text }),
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    throw new DaemonTransportError(`prompt-armor daemon unreachable: ${message}`);
  }

  if (!res.ok) {
    const message = `prompt-armor HTTP ${res.status}: ${res.text}`;
    if (res.status >= 500) {
      throw new DaemonTransportError(message);
    }
    throw new Error(message);
  }

  const parsed: unknown = JSON.parse(res.text);
  return parsePromptArmorJson(parsed);
}

async function callStdioOneShot(
  $: EngineInterface,
  text: string,
  cfg: RuntimeConfig
): Promise<PromptArmorResult> {
  const { binary: pythonBin } = await resolvePythonBinary($);
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
    .map((l) => l.trim())
    .filter(Boolean);
  const lastLine = lines[lines.length - 1];
  if (!lastLine) {
    throw new Error('Empty stdout from prompt-armor daemon');
  }

  const parsed: unknown = JSON.parse(lastLine);
  return parsePromptArmorJson(parsed);
}

export async function runPromptArmor(
  $: EngineInterface,
  text: string,
  cfg: RuntimeConfig
): Promise<PromptArmorResult> {
  if (
    cfg.promptArmorEndpoint.startsWith('http://') ||
    cfg.promptArmorEndpoint.startsWith('https://')
  ) {
    return await callHttpDaemon($, cfg.promptArmorEndpoint, text, daemonAuthToken);
  }

  if (!warmDaemonUrl && !daemonReadyPromise) {
    const backoffMs =
      daemonFailureCount === 0
        ? 0
        : Math.min(30_000, 1000 * 2 ** (daemonFailureCount - 1));
    if (Date.now() - lastDaemonSpawnAttemptMs >= backoffMs) {
      void startWarmDaemon($);
    }
  }

  const boundMs = Math.max(
    50,
    Math.min(cfg.promptArmorTimeoutMs, READY_WAIT_CAP_MS)
  );
  const activeWarmUrl = await awaitWarmDaemon($, boundMs);

  if (activeWarmUrl) {
    try {
      return await callHttpDaemon($, activeWarmUrl, text, daemonAuthToken);
    } catch (err) {
      if (!(err instanceof DaemonTransportError)) {
        throw err;
      }
      markDaemonDead();
    }
  }

  return await callStdioOneShot($, text, cfg);
}

export async function mintCloudAccessToken(
  $: EngineInterface,
  cfg: RuntimeConfig,
  forceRefresh = false
): Promise<string> {
  if (cfg.googleCloudAccessToken && !forceRefresh) {
    return cfg.googleCloudAccessToken;
  }

  const cacheKey = `${cfg.googleApplicationCredentials ?? 'adc'}:${cfg.googleCloudProject ?? ''}`;
  const nowMs = Date.now();
  if (
    !forceRefresh &&
    cachedCloudToken &&
    cachedCloudToken.cacheKey === cacheKey &&
    nowMs < cachedCloudToken.expiresAtMs - 60_000
  ) {
    return cachedCloudToken.token;
  }

  let mintError = '';
  const mintScript = `${$.plugin.root}/scripts/mint-token.mjs`;
  const args = cfg.googleApplicationCredentials
    ? ['node', mintScript, cfg.googleApplicationCredentials]
    : ['node', mintScript];

  try {
    const nodeRes = await $.process.run(args, {
      timeoutMs: cfg.modelArmorTimeoutMs,
      env: {
        ARMORCEPT_ALLOW_GCLOUD_ADC: cfg.allowGcloudAdc ? 'true' : 'false',
      },
    });
    if (nodeRes.exitCode === 0 && nodeRes.stdout.trim()) {
      const rawOut = nodeRes.stdout.trim();
      let token = rawOut;
      let expiresInSec = 3600;
      if (rawOut.startsWith('{')) {
        try {
          const parsed = JSON.parse(rawOut) as Record<string, unknown>;
          if (typeof parsed['access_token'] === 'string') {
            token = parsed['access_token'];
          }
          if (
            typeof parsed['expires_in'] === 'number' &&
            Number.isFinite(parsed['expires_in'])
          ) {
            expiresInSec = parsed['expires_in'];
          }
        } catch {
          // Treat as plain token string if JSON parse fails
        }
      }
      cachedCloudToken = {
        token,
        expiresAtMs: Date.now() + expiresInSec * 1000,
        cacheKey,
      };
      return token;
    }
    mintError = (nodeRes.stderr || nodeRes.stdout || '').trim();
  } catch (err) {
    mintError = err instanceof Error ? err.message : String(err);
  }

  if (cfg.allowGcloudAdc) {
    try {
      const gcloudRes = await $.process.run(
        ['gcloud', 'auth', 'application-default', 'print-access-token'],
        { timeoutMs: cfg.modelArmorTimeoutMs }
      );
      if (gcloudRes.exitCode === 0 && gcloudRes.stdout.trim()) {
        const token = gcloudRes.stdout.trim();
        cachedCloudToken = {
          token,
          expiresAtMs: Date.now() + 3000 * 1000,
          cacheKey,
        };
        return token;
      }
    } catch {
      // gcloud not on PATH or failed
    }
  }

  const detail = mintError ? ` (${mintError})` : '';
  throw new Error(
    `Unable to obtain Google Cloud OAuth2 access token for Model Armor${detail}. Set GOOGLE_APPLICATION_CREDENTIALS in settings.json or export it before starting claude.`
  );
}

export async function runModelArmor(
  $: EngineInterface,
  text: string,
  cfg: RuntimeConfig,
  escalatedToCloud: boolean
): Promise<EvaluationVerdict> {
  if (!cfg.googleCloudProject || !cfg.modelArmorTemplateId) {
    throw new Error(
      `Missing GOOGLE_CLOUD_PROJECT or MODEL_ARMOR_TEMPLATE_ID for ${cfg.mode} mode.`
    );
  }

  let token = await mintCloudAccessToken($, cfg, false);
  const url = `https://modelarmor.${cfg.googleCloudLocation}.rep.googleapis.com/v1/projects/${encodeURIComponent(
    cfg.googleCloudProject
  )}/locations/${encodeURIComponent(
    cfg.googleCloudLocation
  )}/templates/${encodeURIComponent(cfg.modelArmorTemplateId)}:sanitizeUserPrompt`;

  let res = await $.http.fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ userPromptData: { text } }),
  });

  // Handle expired token (HTTP 401)
  if (res.status === 401) {
    cachedCloudToken = undefined;
    if (cfg.googleCloudAccessToken && !cfg.googleApplicationCredentials) {
      throw new Error(
        'Model Armor authentication failed (HTTP 401): Static GOOGLE_CLOUD_ACCESS_TOKEN has expired or is invalid. Configure GOOGLE_APPLICATION_CREDENTIALS for automatic token refresh.'
      );
    }
    token = await mintCloudAccessToken($, cfg, true);
    res = await $.http.fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ userPromptData: { text } }),
    });
  }

  if (!res.ok) {
    throw new Error(`Model Armor API HTTP ${res.status}: ${res.text}`);
  }

  const data = JSON.parse(res.text) as Record<string, unknown>;
  const result = (data['sanitizationResult'] ?? {}) as Record<string, unknown>;
  const overallMatch = result['filterMatchState'] === 'MATCH_FOUND';
  const filters = (result['filterResults'] ?? {}) as Record<string, unknown>;
  const findings: string[] = [];

  const sdpWrapper = filters['sdp'] as Record<string, unknown> | undefined;
  const sdp = (sdpWrapper?.['sdpFilterResult'] ??
    filters['sdpFilterResult']) as Record<string, unknown> | undefined;
  const sdpInspect = (sdp?.['inspectResult'] ??
    sdp?.['sdpInspectResult']) as Record<string, unknown> | undefined;
  const sdpDeid = (sdp?.['deidentifyResult'] ??
    sdp?.['sdpDeidentifyResult']) as Record<string, unknown> | undefined;

  if (
    sdpInspect?.['matchState'] === 'MATCH_FOUND' ||
    sdpDeid?.['matchState'] === 'MATCH_FOUND'
  ) {
    const rawFindings = Array.isArray(sdpInspect?.['findings'])
      ? (sdpInspect['findings'] as Record<string, unknown>[])
      : [];
    const infoTypes = rawFindings
      .map((f) => (typeof f?.['infoType'] === 'string' ? f['infoType'] : ''))
      .filter(Boolean);
    if (infoTypes.length > 0) {
      findings.push(
        `SDP/DLP Violation (${Array.from(new Set(infoTypes)).join(', ')})`
      );
    } else {
      findings.push('SDP/DLP Sensitive Data Violation');
    }
  }

  const piWrapper = filters['piAndJailbreak'] as
    | Record<string, unknown>
    | undefined;
  const pi = (piWrapper?.['piAndJailbreakFilterResult'] ??
    filters['piAndJailbreakFilterResult']) as
    | Record<string, unknown>
    | undefined;
  if (pi?.['matchState'] === 'MATCH_FOUND') {
    const confLevel =
      typeof pi['confidenceLevel'] === 'string' ? pi['confidenceLevel'] : '';
    findings.push(
      `Prompt Injection / Jailbreak${
        confLevel ? ` (confidence: ${confLevel})` : ''
      }`
    );
  }

  const malUriWrapper = filters['maliciousUris'] as
    | Record<string, unknown>
    | undefined;
  const malUri = (malUriWrapper?.['maliciousUriFilterResult'] ??
    filters['maliciousUriFilterResult']) as
    | Record<string, unknown>
    | undefined;
  if (malUri?.['matchState'] === 'MATCH_FOUND') {
    findings.push('Malicious URI Detected');
  }

  const raiWrapper = filters['rai'] as Record<string, unknown> | undefined;
  const rai = (raiWrapper?.['raiFilterResult'] ??
    filters['raiFilterResult']) as Record<string, unknown> | undefined;
  if (rai?.['matchState'] === 'MATCH_FOUND') {
    findings.push('Responsible AI Safety Policy Violation');
  }

  const csamWrapper = filters['csam'] as Record<string, unknown> | undefined;
  const csam = (csamWrapper?.['csamFilterResult'] ??
    filters['csamFilterResult']) as Record<string, unknown> | undefined;
  if (csam?.['matchState'] === 'MATCH_FOUND') {
    findings.push('CSAM Policy Violation');
  }

  if (overallMatch || findings.length > 0) {
    const primaryReason = findings[0] ?? 'Model Armor Security Policy Match';
    if (findings.length === 0) {
      findings.push(primaryReason);
    }
    return {
      decision: 'BLOCK',
      source: 'Model Armor',
      mode: cfg.mode,
      reason: primaryReason,
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
