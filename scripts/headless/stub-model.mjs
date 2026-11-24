#!/usr/bin/env node
/**
 * A scripted stand-in for the Anthropic Messages API, for headless tests.
 *
 * Point Claude Code at it with ANTHROPIC_BASE_URL. For every request that
 * offers tools, it asks for the next Bash command in the current script, one
 * per turn, then ends the turn with a short text reply. Requests without tools
 * (titles, summaries and other side calls) get a plain text reply.
 *
 * It records the tool_result blocks it receives, which is exactly what the
 * model would have seen, plus whether ArmorCept's warm worker was already
 * running when the first model call arrived.
 *
 * Control endpoints (used by run-headless-test.mjs):
 *   POST /__script   body: {"steps": ["cmd", ...]}  resets the recording
 *   GET  /__record   returns the recording
 */

import { execFileSync } from 'node:child_process';
import http from 'node:http';

let steps = [];
let record = { requests: 0, toolResults: [], workerRunningAtFirstCall: null };

function warmWorkerRunning() {
  try {
    const out = execFileSync('pgrep', ['-f', 'daemon.py --mode http'], { encoding: 'utf8' });
    return out.trim().length > 0;
  } catch {
    return false;
  }
}

function toolResultText(block) {
  if (typeof block.content === 'string') return block.content;
  if (Array.isArray(block.content)) {
    return block.content.map((c) => (c.type === 'text' ? c.text : '')).join('');
  }
  return '';
}

function sse(res, events) {
  res.writeHead(200, {
    'content-type': 'text/event-stream',
    'cache-control': 'no-cache',
    'request-id': 'req_stub',
  });
  for (const [event, data] of events) {
    res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  }
  res.end();
}

function reply(res, body, stream, content, stopReason) {
  const message = {
    id: `msg_stub_${record.requests}`,
    type: 'message',
    role: 'assistant',
    model: body.model ?? 'stub',
    content: [],
    stop_reason: null,
    stop_sequence: null,
    usage: { input_tokens: 1, output_tokens: 1 },
  };
  if (!stream) {
    res.writeHead(200, { 'content-type': 'application/json', 'request-id': 'req_stub' });
    res.end(JSON.stringify({ ...message, content, stop_reason: stopReason }));
    return;
  }
  const events = [['message_start', { type: 'message_start', message }]];
  content.forEach((block, index) => {
    if (block.type === 'tool_use') {
      events.push([
        'content_block_start',
        { type: 'content_block_start', index, content_block: { ...block, input: {} } },
      ]);
      events.push([
        'content_block_delta',
        {
          type: 'content_block_delta',
          index,
          delta: { type: 'input_json_delta', partial_json: JSON.stringify(block.input) },
        },
      ]);
    } else {
      events.push([
        'content_block_start',
        { type: 'content_block_start', index, content_block: { type: 'text', text: '' } },
      ]);
      events.push([
        'content_block_delta',
        { type: 'content_block_delta', index, delta: { type: 'text_delta', text: block.text } },
      ]);
    }
    events.push(['content_block_stop', { type: 'content_block_stop', index }]);
  });
  events.push([
    'message_delta',
    {
      type: 'message_delta',
      delta: { stop_reason: stopReason, stop_sequence: null },
      usage: { output_tokens: 1 },
    },
  ]);
  events.push(['message_stop', { type: 'message_stop' }]);
  sse(res, events);
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

const server = http.createServer(async (req, res) => {
  const raw = await readBody(req);
  const url = new URL(req.url ?? '/', 'http://stub');

  if (url.pathname === '/__script' && req.method === 'POST') {
    steps = JSON.parse(raw).steps ?? [];
    record = { requests: 0, toolResults: [], workerRunningAtFirstCall: null };
    res.writeHead(204).end();
    return;
  }
  if (url.pathname === '/__record') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(record));
    return;
  }
  if (!url.pathname.endsWith('/messages')) {
    // count_tokens and anything else: a harmless, well-formed answer
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ input_tokens: 1 }));
    return;
  }

  let body = {};
  try {
    body = JSON.parse(raw);
  } catch {
    // leave empty
  }
  const stream = body.stream === true;
  const hasBash = Array.isArray(body.tools) && body.tools.some((t) => t.name === 'Bash');
  if (!hasBash) {
    reply(res, body, stream, [{ type: 'text', text: 'ok' }], 'end_turn');
    return;
  }

  record.requests += 1;
  if (record.workerRunningAtFirstCall === null) {
    record.workerRunningAtFirstCall = warmWorkerRunning();
  }

  const messages = Array.isArray(body.messages) ? body.messages : [];
  const results = [];
  for (const m of messages) {
    if (m.role !== 'user' || !Array.isArray(m.content)) continue;
    for (const block of m.content) {
      if (block.type === 'tool_result') {
        results.push({ text: toolResultText(block), isError: block.is_error === true });
      }
    }
  }
  record.toolResults = results;

  const next = steps[results.length];
  if (next === undefined) {
    reply(res, body, stream, [{ type: 'text', text: 'All steps finished.' }], 'end_turn');
    return;
  }
  reply(
    res,
    body,
    stream,
    [
      {
        type: 'tool_use',
        id: `toolu_stub_${results.length}`,
        name: 'Bash',
        input: { command: next, description: `step ${results.length + 1}` },
      },
    ],
    'tool_use'
  );
});

server.listen(Number(process.env.STUB_PORT ?? 0), '127.0.0.1', () => {
  const addr = server.address();
  process.stdout.write(`${JSON.stringify({ ready: true, port: addr.port })}\n`);
});
