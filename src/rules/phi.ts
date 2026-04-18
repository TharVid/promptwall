/**
 * PHI (Protected Health Information) detection rule — HIPAA compliance
 * Detects: MRN, ICD-10 codes, medications, procedures, provider names
 */

import { BaseRule } from './base';
import { PHI_PATTERNS } from '../utils/patterns';
import { redactByPattern } from '../redactor';
import type { Finding, PhiRuleOptions, DetectionCategory, ScanDirection } from '../types';

type PhiType = keyof typeof PHI_PATTERNS;

const PHI_SCORES: Record<PhiType, number> = {
  mrn: 0.95,
  diagnosis: 0.7,
  medication: 0.6,
  procedure: 0.5,
  provider: 0.6,
};

const PHI_DESCRIPTIONS: Record<PhiType, string> = {
  mrn: 'Medical Record Number detected',
  diagnosis: 'ICD-10 diagnosis code detected',
  medication: 'Medication name detected',
  procedure: 'Medical procedure detected',
  provider: 'Healthcare provider name detected',
};

export class PhiRule extends BaseRule {
  name = 'phi';
  category: DetectionCategory = 'phi';
  direction: ScanDirection = 'both';

  private detectTypes: PhiType[];
  private redactWith: string;
  private allowList: Set<string>;

  constructor(options: PhiRuleOptions = {}) {
    super();
    this.detectTypes = (options.detect as PhiType[] | undefined) ?? (Object.keys(PHI_PATTERNS) as PhiType[]);
    this.redactWith = options.redactWith ?? '[REDACTED]';
    this.allowList = new Set((options.allowList ?? []).map(v => v.toLowerCase()));
  }

  scan(text: string): Finding[] {
    const findings: Finding[] = [];

    for (const type of this.detectTypes) {
      const pattern = PHI_PATTERNS[type];
      if (!pattern) continue;

      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(text)) !== null) {
        const matchedText = match[1] ?? match[0];
        if (this.allowList.has(matchedText.toLowerCase())) continue;

        findings.push(this.createFinding(
          PHI_SCORES[type],
          PHI_DESCRIPTIONS[type],
          matchedText,
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
      const pattern = PHI_PATTERNS[type];
      if (!pattern) continue;
      result = redactByPattern(result, pattern, `[PHI_${type.toUpperCase()}]`);
    }
    return result;
  }
}

export function phi(options?: PhiRuleOptions): PhiRule {
  return new PhiRule(options);
}
