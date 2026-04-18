/**
 * PII (Personally Identifiable Information) detection rule
 * Detects: SSN, email, phone, IP, DOB, address, names
 * Patterns sourced from Microsoft Presidio and common DLP engines
 */

import { BaseRule } from './base';
import { PII_PATTERNS } from '../utils/patterns';
import { redactByPattern } from '../redactor';
import type { Finding, PiiRuleOptions, DetectionCategory, ScanDirection } from '../types';

type PiiType = keyof typeof PII_PATTERNS;

const PII_SCORES: Record<PiiType, number> = {
  ssn: 0.95,
  email: 0.7,
  phone: 0.7,
  ip: 0.5,
  dob: 0.6,
  address: 0.75,
  name: 0.4,
};

const PII_DESCRIPTIONS: Record<PiiType, string> = {
  ssn: 'Social Security Number detected',
  email: 'Email address detected',
  phone: 'Phone number detected',
  ip: 'IP address detected',
  dob: 'Date of birth detected',
  address: 'Street address detected',
  name: 'Person name detected',
};

export class PiiRule extends BaseRule {
  name = 'pii';
  category: DetectionCategory = 'pii';
  direction: ScanDirection = 'both';

  private detectTypes: PiiType[];
  private redactWith: string;
  private allowList: Set<string>;

  constructor(options: PiiRuleOptions = {}) {
    super();
    this.detectTypes = (options.detect as PiiType[] | undefined) ?? (Object.keys(PII_PATTERNS) as PiiType[]);
    this.redactWith = options.redactWith ?? '[REDACTED]';
    this.allowList = new Set((options.allowList ?? []).map(v => v.toLowerCase()));
  }

  scan(text: string): Finding[] {
    const findings: Finding[] = [];

    for (const type of this.detectTypes) {
      const pattern = PII_PATTERNS[type];
      if (!pattern) continue;

      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(text)) !== null) {
        if (this.allowList.has(match[0].toLowerCase())) continue;

        findings.push(this.createFinding(
          PII_SCORES[type],
          PII_DESCRIPTIONS[type],
          match[0],
          match.index,
          match.index + match[0].length,
        ));
      }
    }

    return findings;
  }

  redact(text: string): string {
    let result = text;
    for (const type of this.detectTypes) {
      const pattern = PII_PATTERNS[type];
      if (!pattern) continue;
      result = redactByPattern(result, pattern, `[PII_${type.toUpperCase()}]`);
    }
    return result;
  }
}

export function pii(options?: PiiRuleOptions): PiiRule {
  return new PiiRule(options);
}
