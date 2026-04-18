/**
 * Prompt injection detection rule
 * Detects: instruction override, role manipulation, delimiter injection,
 *          system prompt extraction, encoded attacks, tool abuse
 */

import { BaseRule } from './base';
import { INJECTION_PATTERNS } from '../utils/patterns';
import { redactByPattern } from '../redactor';
import type { Finding, InjectionRuleOptions, DetectionCategory, ScanDirection } from '../types';

export class InjectionRule extends BaseRule {
  name = 'injection';
  category: DetectionCategory = 'injection';
  direction: ScanDirection = 'both';

  private customPatterns: Array<{ pattern: RegExp; score: number; description: string }>;
  private threshold: number;

  constructor(options: InjectionRuleOptions = {}) {
    super();
    this.threshold = options.threshold ?? 0.3;
    this.customPatterns = (options.customPatterns ?? []).map(p => ({
      pattern: p,
      score: 0.8,
      description: 'Custom injection pattern',
    }));
  }

  scan(text: string): Finding[] {
    const allPatterns = [...INJECTION_PATTERNS, ...this.customPatterns];
    return this.scanPatterns(text, allPatterns, this.threshold);
  }

  redact(text: string): string {
    let result = text;
    for (const { pattern } of [...INJECTION_PATTERNS, ...this.customPatterns]) {
      result = redactByPattern(result, pattern, '[INJECTION_BLOCKED]');
    }
    return result;
  }
}

export function injection(options?: InjectionRuleOptions): InjectionRule {
  return new InjectionRule(options);
}
