#!/usr/bin/env node
/**
 * Headless (claude -p) end-to-end test for ArmorCept.
 *
 * Runs real Claude Code sessions with the plugin loaded via --plugin-dir,
 * against the scripted stub model in stub-model.mjs, and checks what reached
 * the "model". Nothing leaves the machine: the stub listens on 127.0.0.1 and
 * Claude Code runs with a throwaway config dir and nonessential traffic off.
 *
 * Usage: node scripts/headless/run-headless-test.mjs [--claude <path>]
 */

import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pluginDir = resolve(here, '..', '..');
const claudeBin = process.argv.includes('--claude')
  ? process.argv[process.argv.indexOf('--claude') + 1]
  : 'claude';

// Fake credentials, assembled at run time
const FAKE_AWS_KEY = `AKIA${'HEADLESSTEST0001'}`;
const PEM_BODY = 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCheadlessfakekeybody0123456789';
const FAKE_PEM = `-----BEGIN ${'PRIVATE'} KEY-----\n${PEM_BODY}\n-----END ${'PRIVATE'} KEY-----\n`;
const RUNNER_SECRET = `armorcept-headless-${process.pid}-${Date.now()}-runner-secret`;

const scenarios = [
  {
    name: 'clean session runs through and the warm worker starts at session.start',
    env: {},
    steps: ['echo armorcept-clean-ok'],
    check: ({ record, work }) => [
      ['worker running before first model call', record.workerRunningAtFirstCall === true],
      ['tool output reached the model', record.toolResults[0]?.text.includes('armorcept-clean-ok')],
      ['decision log written', logLines(work).some((l) => l.hook === 'tool.call' && l.action === 'allowed')],
    ],
  },
  {
    name: 'tool call containing a fake secret is blocked before it runs',
    env: {},
    steps: [`echo ${FAKE_AWS_KEY} > leaked.txt`],
    check: ({ record, work }) => [
      ['model told the call was blocked', record.toolResults[0]?.text.includes('blocked by ArmorCept')],
      ['category named', record.toolResults[0]?.text.includes('SECRET_LEAK_AWS_ACCESS_KEY')],
      ['command never ran', !existsSync(join(work, 'leaked.txt'))],
      ['block logged', logLines(work).some((l) => l.action === 'blocked')],
    ],
  },
  {
    name: 'tool result with a fake secret is redacted (ARMORCEPT_TOOL_RESULT_ACTION=redact)',
    env: { ARMORCEPT_SCAN_TOOL_RESULTS: 'true', ARMORCEPT_TOOL_RESULT_ACTION: 'redact' },
    setup: (work) => writeFileSync(join(work, 'config.txt'), `region=us-east-1\nkey=${FAKE_AWS_KEY}\nretries=3\n`),
    steps: ['cat config.txt'],
    check: ({ record }) => [
      ['secret replaced', record.toolResults[0]?.text.includes('[REDACTED:SECRET_LEAK_AWS_ACCESS_KEY]')],
      ['rest of output kept', record.toolResults[0]?.text.includes('retries=3')],
      ['secret never reached the model', !JSON.stringify(record).includes(FAKE_AWS_KEY)],
    ],
  },
  {
    name: 'a private key in a tool result is withheld whole, even in redact mode',
    env: { ARMORCEPT_SCAN_TOOL_RESULTS: 'true', ARMORCEPT_TOOL_RESULT_ACTION: 'redact' },
    setup: (work) => {
      writeFileSync(join(work, 'id_key.pem'), FAKE_PEM);
      writeFileSync(
        join(work, 'sa.json'),
        JSON.stringify({ type: 'service_account', private_key: FAKE_PEM })
      );
    },
    steps: ['cat id_key.pem', 'cat sa.json'],
    check: ({ record }) => [
      ['PEM file withheld', record.toolResults[0]?.text.includes('output withheld by ArmorCept')],
      ['service-account JSON withheld', record.toolResults[1]?.text.includes('output withheld by ArmorCept')],
      ['key body never reached the model', !JSON.stringify(record).includes(PEM_BODY)],
    ],
  },
  {
    name: 'tool result with a fake secret is withheld by default',
    env: { ARMORCEPT_SCAN_TOOL_RESULTS: 'true' },
    setup: (work) => writeFileSync(join(work, 'config.txt'), `key=${FAKE_AWS_KEY}\n`),
    steps: ['cat config.txt'],
    check: ({ record }) => [
      ['model told output was withheld', record.toolResults[0]?.text.includes('output withheld by ArmorCept')],
      ['secret never reached the model', !JSON.stringify(record).includes(FAKE_AWS_KEY)],
    ],
  },
  {
    name: 'exact value of a named env var is redacted from a printed environment',
    env: {
      ARMORCEPT_SCAN_TOOL_RESULTS: 'true',
      ARMORCEPT_TOOL_RESULT_ACTION: 'redact',
      ARMORCEPT_SECRET_ENV_VARS: 'RUNNER_SECRET',
      RUNNER_SECRET,
    },
    steps: ['printenv RUNNER_SECRET'],
    check: ({ record, work }) => [
      ['value redacted', record.toolResults[0]?.text.includes('[REDACTED:SECRET_EXACT_RUNNER_SECRET]')],
      ['value never reached the model', !JSON.stringify(record).includes(RUNNER_SECRET)],
      ['value never in the decision log', !readLog(work).includes(RUNNER_SECRET)],
    ],
  },
  {
    name: "a repo's own .claude/settings.json cannot switch on audit mode",
    env: {},
    setup: (work) => {
      mkdirSync(join(work, '.claude'), { recursive: true });
      writeFileSync(
        join(work, '.claude', 'settings.json'),
        JSON.stringify({ env: { ARMORCEPT_ENFORCEMENT: 'audit' } })
      );
    },
    steps: [`echo ${FAKE_AWS_KEY} > repo-audit.txt`],
    check: ({ record, work }) => [
      ['call still blocked', record.toolResults[0]?.text.includes('blocked by ArmorCept')],
      ['command never ran', !existsSync(join(work, 'repo-audit.txt'))],
      ['logged as enforce', logLines(work).some((l) => l.action === 'blocked' && l.enforcement === 'enforce')],
    ],
  },
  {
    name: 'recommended runner config in user settings survives a repo turning secret enforcement off',
    env: { RUNNER_SECRET },
    // User settings, not --settings: a project's settings outrank the user's
    // but not --settings, so this is the layering the guard has to handle
    userSettings: {
      env: {
        ARMORCEPT_ENFORCEMENT: 'audit',
        ARMORCEPT_AUDIT_ENFORCE_SECRETS: 'true',
        ARMORCEPT_SECRET_ENV_VARS: 'RUNNER_SECRET',
        ARMORCEPT_SCAN_TOOL_RESULTS: 'true',
        ARMORCEPT_TOOL_RESULT_ACTION: 'redact',
      },
    },
    setup: (work) => {
      mkdirSync(join(work, '.claude'), { recursive: true });
      writeFileSync(
        join(work, '.claude', 'settings.json'),
        JSON.stringify({
          env: {
            ARMORCEPT_AUDIT_ENFORCE_SECRETS: 'false',
            ARMORCEPT_SECRET_ENV_VARS: 'SOME_UNSET_NAME',
            ARMORCEPT_SCAN_TOOL_RESULTS: 'false',
          },
        })
      );
    },
    steps: ['printenv RUNNER_SECRET'],
    check: ({ record }) => [
      ['value redacted', record.toolResults[0]?.text.includes('[REDACTED:SECRET_EXACT_RUNNER_SECRET]')],
      ['value never reached the model', !JSON.stringify(record).includes(RUNNER_SECRET)],
    ],
  },
  {
    name: 'audit mode records but does not block',
    env: { ARMORCEPT_ENFORCEMENT: 'audit' },
    steps: [`echo ${FAKE_AWS_KEY} > audited.txt`],
    check: ({ work }) => [
      ['command ran', existsSync(join(work, 'audited.txt'))],
      ['audited verdict logged', logLines(work).some((l) => l.action === 'audited')],
      ['payload not in log', !readLog(work).includes(FAKE_AWS_KEY)],
    ],
  },
];

function readLog(work) {
  const path = join(work, 'armorcept-decisions.jsonl');
  return existsSync(path) ? readFileSync(path, 'utf8') : '';
}

function logLines(work) {
  return readLog(work)
    .split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => JSON.parse(l));
}

function startStub() {
  return new Promise((resolveStub, reject) => {
    const proc = spawn(process.execPath, [join(here, 'stub-model.mjs')], {
      stdio: ['ignore', 'pipe', 'inherit'],
    });
    proc.stdout.once('data', (chunk) => {
      const { port } = JSON.parse(String(chunk).split('\n')[0]);
      resolveStub({ proc, base: `http://127.0.0.1:${port}` });
    });
    proc.once('error', reject);
  });
}

function runClaude(work, configDir, base, extraEnv, settings) {
  return new Promise((resolveRun) => {
    const started = Date.now();
    const env = {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      TMPDIR: process.env.TMPDIR ?? tmpdir(),
      CLAUDE_CONFIG_DIR: configDir,
      ANTHROPIC_BASE_URL: base,
      ANTHROPIC_API_KEY: 'stub-key-not-a-secret',
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1',
      DISABLE_AUTOUPDATER: '1',
      ARMORCEPT_DECISION_LOG: join(work, 'armorcept-decisions.jsonl'),
      ...extraEnv,
    };
    const proc = spawn(
      claudeBin,
      [
        '-p',
        'Run the requested steps.',
        '--plugin-dir',
        pluginDir,
        '--output-format',
        'stream-json',
        '--verbose',
        '--allowedTools',
        'Bash',
        '--max-turns',
        '6',
        ...(settings ? ['--settings', JSON.stringify(settings)] : []),
      ],
      { cwd: work, env, stdio: ['ignore', 'pipe', 'pipe'] }
    );
    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', (c) => (stdout += c));
    proc.stderr.on('data', (c) => (stderr += c));
    const timer = setTimeout(() => proc.kill('SIGKILL'), 120_000);
    proc.on('close', (code) => {
      clearTimeout(timer);
      resolveRun({ code, stdout, stderr, ms: Date.now() - started });
    });
  });
}

const { proc: stub, base } = await startStub();
let failed = 0;
const latencies = [];
try {
  for (const scenario of scenarios) {
    const work = mkdtempSync(join(tmpdir(), 'armorcept-headless-'));
    const configDir = mkdtempSync(join(tmpdir(), 'armorcept-claude-config-'));
    try {
      scenario.setup?.(work);
      if (scenario.userSettings) {
        writeFileSync(join(configDir, 'settings.json'), JSON.stringify(scenario.userSettings));
      }
      await fetch(`${base}/__script`, {
        method: 'POST',
        body: JSON.stringify({ steps: scenario.steps }),
      });
      const run = await runClaude(work, configDir, base, scenario.env, scenario.settings);
      // Give the decision log's background writer a moment after exit
      await new Promise((r) => setTimeout(r, 300));
      const record = await (await fetch(`${base}/__record`)).json();
      const checks = [
        ['claude exited 0', run.code === 0],
        ['model was called', record.requests > 0],
        ...scenario.check({ record, work, run }),
      ];
      const ok = checks.every(([, pass]) => pass);
      if (!ok) failed += 1;
      console.log(`${ok ? 'PASS' : 'FAIL'}  ${scenario.name}  (${run.ms} ms)`);
      for (const [label, pass] of checks) {
        console.log(`        ${pass ? '✓' : '✗'} ${label}`);
      }
      if (!ok) {
        console.log('        --- tool results seen by the model ---');
        console.log(JSON.stringify(record.toolResults, null, 2).replace(/^/gm, '        '));
        console.log('        --- claude stderr (tail) ---');
        console.log(run.stderr.slice(-2000).replace(/^/gm, '        '));
        console.log('        --- claude stdout (tail) ---');
        console.log(run.stdout.slice(-2000).replace(/^/gm, '        '));
      }
      for (const line of logLines(work)) {
        if (typeof line.latency_ms === 'number' && line.hook !== 'engine.health') {
          latencies.push(line.latency_ms);
        }
      }
    } finally {
      rmSync(work, { recursive: true, force: true });
      rmSync(configDir, { recursive: true, force: true });
    }
  }
} finally {
  stub.kill();
}

if (latencies.length > 0) {
  const sorted = [...latencies].sort((a, b) => a - b);
  const pct = (p) => sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];
  console.log(
    `\nScan latency over ${sorted.length} verdicts: p50 ${pct(50)} ms, p95 ${pct(95)} ms, max ${sorted[sorted.length - 1]} ms`
  );
}
console.log(failed === 0 ? '\nAll headless scenarios passed.' : `\n${failed} scenario(s) failed.`);
process.exit(failed === 0 ? 0 : 1);
