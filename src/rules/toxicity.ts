/**
 * Toxicity detection rule
 * Detects: violence incitement, dangerous instructions, illegal activity requests
 */

import { BaseRule } from './base';
import { TOXICITY_PATTERNS } from '../utils/patterns';
import { redactByPattern } from '../redactor';
import type { Finding, ToxicityRuleOptions, DetectionCategory, ScanDirection } from '../types';

export class ToxicityRule extends BaseRule {
  name = 'toxicity';
  category: DetectionCategory = 'toxicity';
  direction: ScanDirection = 'both';

  private customPatterns: Array<{ pattern: RegExp; score: number; description: string }>;
  private threshold: number;

  constructor(options: ToxicityRuleOptions = {}) {
    super();
    this.threshold = options.threshold ?? 0.3;
    this.customPatterns = (options.customPatterns ?? []).map(p => ({
      pattern: p,
      score: 0.8,
      description: 'Custom toxicity pattern',
    }));
  }

  scan(text: string): Finding[] {
    const allPatterns = [...TOXICITY_PATTERNS, ...this.customPatterns];
    return this.scanPatterns(text, allPatterns, this.threshold);
  }

  redact(text: string): string {
    let result = text;
    for (const { pattern } of [...TOXICITY_PATTERNS, ...this.customPatterns]) {
      result = redactByPattern(result, pattern, '[TOXIC_BLOCKED]');
    }
    return result;
  }
}

export function toxicity(options?: ToxicityRuleOptions): ToxicityRule {
  return new ToxicityRule(options);
}
