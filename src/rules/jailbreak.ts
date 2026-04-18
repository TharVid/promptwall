/**
 * Jailbreak detection rule
 * Detects: DAN, STAN, DUDE, AIM, constraint removal, dev mode, unicode tricks, etc.
 */

import { BaseRule } from './base';
import { JAILBREAK_PATTERNS } from '../utils/patterns';
import { redactByPattern } from '../redactor';
import type { Finding, JailbreakRuleOptions, DetectionCategory, ScanDirection } from '../types';

export class JailbreakRule extends BaseRule {
  name = 'jailbreak';
  category: DetectionCategory = 'jailbreak';
  direction: ScanDirection = 'outbound';

  private customPatterns: Array<{ pattern: RegExp; score: number; description: string }>;
  private threshold: number;

  constructor(options: JailbreakRuleOptions = {}) {
    super();
    this.threshold = options.threshold ?? 0.3;
    this.customPatterns = (options.customPatterns ?? []).map(p => ({
      pattern: p,
      score: 0.8,
      description: 'Custom jailbreak pattern',
    }));
  }

  scan(text: string): Finding[] {
    const allPatterns = [...JAILBREAK_PATTERNS, ...this.customPatterns];
    return this.scanPatterns(text, allPatterns, this.threshold);
  }

  redact(text: string): string {
    let result = text;
    for (const { pattern } of [...JAILBREAK_PATTERNS, ...this.customPatterns]) {
      result = redactByPattern(result, pattern, '[JAILBREAK_BLOCKED]');
    }
    return result;
  }
}

export function jailbreak(options?: JailbreakRuleOptions): JailbreakRule {
  return new JailbreakRule(options);
}
