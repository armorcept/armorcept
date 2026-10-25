import { loadConfig } from './config.js';
import { ModelArmorClient } from './engines/model-armor-client.js';
import { PromptArmorClient } from './engines/prompt-armor-client.js';
import { ArmorCeptRouter } from './router.js';
import type { ArmorCeptConfig, EvaluationVerdict } from './types.js';
import {
  formatSecurityAlertBanner,
  formatSyntheticToolBlockError,
  notifyModUi,
  type ClaudeModContext,
} from './ui/feedback.js';

export interface ModPromptEvent {
  prompt?: string;
  text?: string;
  message?: string;
  content?: string;
  [key: string]: unknown;
}

export interface ModToolCallEvent {
  tool?: string;
  tool_name?: string;
  name?: string;
  input?: unknown;
  arguments?: unknown;
  parameters?: unknown;
  tool_input?: unknown;
  [key: string]: unknown;
}

export type ModNextFn<TEvent = unknown> = (
  event: TEvent
) => Promise<unknown> | unknown;

export type ModEventHandler<TEvent = any> = (
  $: ClaudeModContext,
  e: TEvent,
  next: ModNextFn<TEvent>
) => Promise<unknown> | unknown;

export type ModRegisterOnFn = (
  eventName: string,
  filterOrHandler: Record<string, unknown> | ModEventHandler,
  maybeHandler?: ModEventHandler
) => void;

export interface CreateArmorCeptModOptions {
  env?: Record<string, string | undefined>;
  config?: ArmorCeptConfig;
  router?: ArmorCeptRouter;
}

/**
 * Extracts the raw conversational prompt string from a Claude Code prompt hook event.
 */
export function extractPromptText(event: ModPromptEvent | string): string {
  if (typeof event === 'string') return event;
  if (typeof event?.prompt === 'string') return event.prompt;
  if (typeof event?.text === 'string') return event.text;
  if (typeof event?.message === 'string') return event.message;
  if (typeof event?.content === 'string') return event.content;
  return JSON.stringify(event ?? {});
}

/**
 * Extracts the target tool name and serializes its JSON arguments/parameters
 * into a deterministic payload string for inspection.
 */
export function extractToolCallPayload(event: ModToolCallEvent): {
  toolName: string;
  serializedPayload: string;
} {
  const toolName =
    event?.tool ?? event?.tool_name ?? event?.name ?? 'UnknownTool';

  const rawArgs =
    event?.input ??
    event?.arguments ??
    event?.parameters ??
    event?.tool_input ??
    extractRemainingToolFields(event);

  const serializedArgs =
    typeof rawArgs === 'string' ? rawArgs : JSON.stringify(rawArgs ?? {}, null, 2);

  return {
    toolName: String(toolName),
    serializedPayload: `Tool: ${toolName}\nArguments: ${serializedArgs}`,
  };
}

function extractRemainingToolFields(
  event: ModToolCallEvent
): Record<string, unknown> {
  const copy: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(event ?? {})) {
    if (!['tool', 'tool_name', 'name', 'type', 'event'].includes(k)) {
      copy[k] = v;
    }
  }
  return copy;
}

/**
 * Creates a configured ArmorCeptRouter instance from environment variables or explicit options.
 */
export function createArmorCeptRouter(
  options: CreateArmorCeptModOptions = {}
): ArmorCeptRouter {
  if (options.router) return options.router;

  const config = options.config ?? loadConfig(options.env ?? process.env);

  const promptArmorClient =
    config.mode === 'LOCAL' || config.mode === 'WATERFALL'
      ? new PromptArmorClient({
          endpoint: config.promptArmorEndpoint,
          timeoutMs: config.promptArmorTimeoutMs,
        })
      : undefined;

  const modelArmorClient =
    config.mode === 'CLOUD' || config.mode === 'WATERFALL'
      ? new ModelArmorClient({
          projectId: config.googleCloudProject!,
          location: config.googleCloudLocation,
          templateId: config.modelArmorTemplateId!,
          keyFilename: config.googleApplicationCredentials,
          timeoutMs: config.modelArmorTimeoutMs,
        })
      : undefined;

  return new ArmorCeptRouter({
    config,
    promptArmorClient,
    modelArmorClient,
  });
}

/**
 * Builds the prompt and PreToolUse hook handlers bound to an ArmorCeptRouter instance.
 */
export function createModHandlers(router: ArmorCeptRouter) {
  const handlePrompt: ModEventHandler<ModPromptEvent> = async ($, e, next) => {
    const promptText = extractPromptText(e);
    const verdict: EvaluationVerdict = await router.evaluatePayload(
      promptText,
      'prompt'
    );

    notifyModUi($, verdict);

    if (verdict.decision === 'BLOCK') {
      const alertBanner = formatSecurityAlertBanner(verdict);
      return {
        deny: alertBanner,
        blocked: true,
        decision: 'block',
        reason: alertBanner,
        verdict,
      };
    }

    return typeof next === 'function' ? await next(e) : e;
  };

  const handleToolCall: ModEventHandler<ModToolCallEvent> = async (
    $,
    e,
    next
  ) => {
    const { toolName, serializedPayload } = extractToolCallPayload(e);
    const verdict: EvaluationVerdict = await router.evaluatePayload(
      serializedPayload,
      'tool',
      { toolName }
    );

    notifyModUi($, verdict, toolName);

    if (verdict.decision === 'BLOCK') {
      const syntheticError = formatSyntheticToolBlockError(verdict, toolName);
      return {
        deny: syntheticError,
        blocked: true,
        decision: 'block',
        reason: syntheticError,
        verdict,
      };
    }

    return typeof next === 'function' ? await next(e) : e;
  };

  return {
    handlePrompt,
    handleToolCall,
  };
}

/**
 * Primary Claude Code Mod registration entrypoint (`register(on)`).
 * Registers listeners for both the Mod middleware event names (`prompt`, `tool.call`)
 * and lifecycle hook aliases (`UserPromptSubmit`, `PreToolUse`).
 */
export const register = (
  on: ModRegisterOnFn,
  options: CreateArmorCeptModOptions = {}
): ArmorCeptRouter => {
  const router = createArmorCeptRouter(options);
  const { handlePrompt, handleToolCall } = createModHandlers(router);

  on('prompt', handlePrompt);
  on('UserPromptSubmit', handlePrompt);
  on('tool.call', handleToolCall);
  on('PreToolUse', handleToolCall);

  return router;
};

export default register;
