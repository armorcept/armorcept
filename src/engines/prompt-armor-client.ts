import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import * as path from 'node:path';
import * as readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import type { PromptArmorResponse } from '../types.js';

export interface PromptArmorClientOptions {
  endpoint: string;
  timeoutMs?: number;
  pythonCommand?: string;
  daemonScriptPath?: string;
  fetchImpl?: typeof fetch;
}

interface PendingRequest {
  resolve: (value: PromptArmorResponse) => void;
  reject: (reason: Error) => void;
  timer: NodeJS.Timeout;
}

/**
 * Client adapter for the local prompt-armor engine.
 * Supports either a persistent warm Python worker over `stdio` or an HTTP endpoint
 * (e.g., `http://127.0.0.1:8443/analyze`).
 */
export class PromptArmorClient {
  private readonly endpoint: string;
  private readonly timeoutMs: number;
  private readonly pythonCommand: string;
  private readonly daemonScriptPath: string;
  private readonly fetchImpl: typeof fetch;

  private worker: ChildProcessWithoutNullStreams | null = null;
  private rl: readline.Interface | null = null;
  private pending = new Map<string, PendingRequest>();

  constructor(options: PromptArmorClientOptions) {
    this.endpoint = options.endpoint.trim() || 'stdio';
    this.timeoutMs = options.timeoutMs ?? 3000;
    this.pythonCommand =
      options.pythonCommand ??
      process.env.PROMPT_ARMOR_PYTHON_BIN ??
      (process.platform === 'win32' ? 'python' : 'python3');

    if (options.daemonScriptPath) {
      this.daemonScriptPath = options.daemonScriptPath;
    } else {
      const currentDir = path.dirname(fileURLToPath(import.meta.url));
      this.daemonScriptPath = path.resolve(currentDir, '../../python/daemon.py');
    }

    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
  }

  public isHttpMode(): boolean {
    return (
      this.endpoint.startsWith('http://') || this.endpoint.startsWith('https://')
    );
  }

  public async analyze(text: string): Promise<PromptArmorResponse> {
    const start = performance.now();
    const raw = this.isHttpMode()
      ? await this.analyzeViaHttp(text)
      : await this.analyzeViaStdio(text);

    const latencyMs =
      typeof raw.latency_ms === 'number'
        ? raw.latency_ms
        : Math.round((performance.now() - start) * 100) / 100;

    return this.normalizeResponse(raw, latencyMs);
  }

  private async analyzeViaHttp(text: string): Promise<PromptArmorResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchImpl(this.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          text,
          council: { enabled: false },
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const bodyText = await response.text().catch(() => '');
        throw new Error(
          `Prompt-Armor HTTP daemon returned ${response.status}: ${bodyText || response.statusText}`
        );
      }

      const data = (await response.json()) as PromptArmorResponse & {
        error?: string;
      };
      if (data.error) {
        throw new Error(`Prompt-Armor daemon error: ${data.error}`);
      }
      return data;
    } catch (err) {
      if ((err as Error)?.name === 'AbortError') {
        throw new Error(
          `Prompt-Armor HTTP request timed out after ${this.timeoutMs}ms`
        );
      }
      throw err instanceof Error ? err : new Error(String(err));
    } finally {
      clearTimeout(timer);
    }
  }

  private ensureStdioWorker(): ChildProcessWithoutNullStreams {
    if (this.worker && !this.worker.killed && this.worker.exitCode === null) {
      return this.worker;
    }

    const child = spawn(
      this.pythonCommand,
      [this.daemonScriptPath, '--mode', 'stdio'],
      {
        stdio: ['pipe', 'pipe', 'pipe'],
      }
    );

    this.worker = child;
    this.rl = readline.createInterface({
      input: child.stdout,
      crlfDelay: Infinity,
    });

    this.rl.on('line', (line: string) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      try {
        const parsed = JSON.parse(trimmed) as PromptArmorResponse & {
          id?: string;
          error?: string;
        };
        const reqId = parsed.id;
        if (reqId && this.pending.has(reqId)) {
          const entry = this.pending.get(reqId)!;
          clearTimeout(entry.timer);
          this.pending.delete(reqId);
          if (parsed.error) {
            entry.reject(new Error(`Prompt-Armor stdio error: ${parsed.error}`));
          } else {
            entry.resolve(parsed);
          }
        }
      } catch {
        // Ignore non-JSON stdout lines
      }
    });

    const handleWorkerExit = (err?: Error) => {
      const reason =
        err ?? new Error('Prompt-Armor stdio daemon exited unexpectedly');
      for (const [id, entry] of this.pending.entries()) {
        clearTimeout(entry.timer);
        entry.reject(reason);
        this.pending.delete(id);
      }
      this.worker = null;
      this.rl = null;
    };

    child.on('error', (err) => handleWorkerExit(err));
    child.on('exit', () => handleWorkerExit());

    return child;
  }

  private analyzeViaStdio(text: string): Promise<PromptArmorResponse> {
    return new Promise<PromptArmorResponse>((resolve, reject) => {
      let child: ChildProcessWithoutNullStreams;
      try {
        child = this.ensureStdioWorker();
      } catch (err) {
        reject(err instanceof Error ? err : new Error(String(err)));
        return;
      }

      const id = randomUUID();
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(
          new Error(
            `Prompt-Armor stdio request timed out after ${this.timeoutMs}ms`
          )
        );
      }, this.timeoutMs);

      this.pending.set(id, { resolve, reject, timer });

      const payload = JSON.stringify({ id, text }) + '\n';
      child.stdin.write(payload, (err) => {
        if (err) {
          clearTimeout(timer);
          this.pending.delete(id);
          reject(err);
        }
      });
    });
  }

  private normalizeResponse(
    raw: Partial<PromptArmorResponse>,
    fallbackLatencyMs: number
  ): PromptArmorResponse {
    const riskScore =
      typeof raw.risk_score === 'number' && !Number.isNaN(raw.risk_score)
        ? Math.max(0, Math.min(1, raw.risk_score))
        : 0;
    const confidence =
      typeof raw.confidence === 'number' && !Number.isNaN(raw.confidence)
        ? Math.max(0, Math.min(1, raw.confidence))
        : 1;
    const decision = String(raw.decision ?? (riskScore >= 0.75 ? 'BLOCK' : 'ALLOW'))
      .replace(/^Decision\./i, '')
      .toUpperCase();
    const categories = Array.isArray(raw.categories)
      ? raw.categories.map((c) => String(c).replace(/^Category\./i, ''))
      : [];

    return {
      id: raw.id,
      risk_score: riskScore,
      confidence,
      decision,
      categories,
      evidence: raw.evidence ?? {},
      latency_ms:
        typeof raw.latency_ms === 'number' ? raw.latency_ms : fallbackLatencyMs,
      council_enabled: false,
    };
  }

  public async close(): Promise<void> {
    if (this.rl) {
      this.rl.close();
      this.rl = null;
    }
    if (this.worker && !this.worker.killed) {
      this.worker.kill();
      this.worker = null;
    }
  }
}
