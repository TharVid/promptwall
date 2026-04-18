/**
 * Bulwark — the core class
 *
 * Usage:
 *   import bulwark from 'bulwark';
 *   const guard = bulwark();                           // all defaults
 *   const guard = bulwark({ mode: 'redact' });         // custom config
 *   const guard = bulwark({ rules: [bulwark.pii()] }); // specific rules
 *
 *   const result = await guard.scan('some text');
 *   if (!result.safe) { ... }
 */

import type { BulwarkOptions, BulwarkMiddleware, ScanResult, ScanDirection } from './types';
import { Scanner } from './scanner';
import { AuditLogger } from './logger';
import { defaultRules } from './rules';

export class Bulwark implements BulwarkMiddleware {
  private scanner: Scanner;
  private logger: AuditLogger;
  private direction: ScanDirection;
  private onDetection?: (result: ScanResult) => boolean | void;

  constructor(options: BulwarkOptions = {}) {
    const rules = options.rules ?? defaultRules();
    const mode = options.mode ?? 'block';
    const threshold = options.threshold ?? 0.7;

    this.scanner = new Scanner({ rules, mode, threshold });
    this.logger = new AuditLogger(options.logging ?? true, options.onLog);
    this.direction = options.direction ?? 'both';
    this.onDetection = options.onDetection;
  }

  /**
   * Scan outgoing prompt before sending to LLM
   */
  async scanPrompt(text: string): Promise<ScanResult> {
    return this.scan(text, 'outbound');
  }

  /**
   * Scan incoming response/tool output/RAG content from LLM
   */
  async scanResponse(text: string): Promise<ScanResult> {
    return this.scan(text, 'inbound');
  }

  /**
   * Scan any text with specified direction
   */
  async scan(text: string, direction?: ScanDirection): Promise<ScanResult> {
    const dir = direction ?? this.direction;
    const result = this.scanner.scan(text, dir);

    this.logger.logWithLength(result, dir, text.length);

    if (!result.safe && this.onDetection) {
      const override = this.onDetection(result);
      if (override === false) {
        return { ...result, safe: true, action: 'pass' };
      }
    }

    return result;
  }

  /**
   * Wrap an LLM call with automatic prompt/response scanning.
   *
   *   const safeLLM = guard.wrap(callOpenAI);
   *   const response = await safeLLM('Tell me about...');
   */
  wrap<T>(fn: (prompt: string) => Promise<T>): (prompt: string) => Promise<T> {
    return async (prompt: string): Promise<T> => {
      // Scan outbound prompt
      const promptResult = await this.scanPrompt(prompt);

      if (!promptResult.safe && promptResult.action === 'block') {
        throw new BulwarkError('Prompt blocked by Bulwark', promptResult);
      }

      const effectivePrompt = promptResult.redacted ?? prompt;

      // Call the LLM
      const response = await fn(effectivePrompt);

      // Scan inbound response if it's a string
      if (typeof response === 'string') {
        const responseResult = await this.scanResponse(response);
        if (!responseResult.safe && responseResult.action === 'block') {
          throw new BulwarkError('Response blocked by Bulwark', responseResult);
        }
      }

      return response;
    };
  }
}

/**
 * Custom error class with scan result attached
 */
export class BulwarkError extends Error {
  public result: ScanResult;

  constructor(message: string, result: ScanResult) {
    super(message);
    this.name = 'BulwarkError';
    this.result = result;
  }
}
