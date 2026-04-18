/**
 * PCI (Payment Card Industry) detection rule — PCI DSS compliance
 * Detects: Credit card numbers, CVV, expiry dates, bank account & routing numbers
 * Card validation uses Luhn algorithm for reduced false positives
 */

import { BaseRule } from './base';
import { PCI_PATTERNS } from '../utils/patterns';
import { redactByPattern } from '../redactor';
import type { Finding, PciRuleOptions, DetectionCategory, ScanDirection } from '../types';

type PciType = keyof typeof PCI_PATTERNS;

const PCI_SCORES: Record<PciType, number> = {
  credit_card: 0.95,
  amex: 0.95,
  cvv: 0.9,
  expiry: 0.6,
  bank_account: 0.9,
  routing_number: 0.85,
};

const PCI_DESCRIPTIONS: Record<PciType, string> = {
  credit_card: 'Credit card number detected',
  amex: 'American Express card number detected',
  cvv: 'CVV/security code detected',
  expiry: 'Card expiry date detected',
  bank_account: 'Bank account number detected',
  routing_number: 'Routing/ABA number detected',
};

/**
 * Luhn algorithm — validates credit card numbers to reduce false positives
 */
function luhnCheck(numStr: string): boolean {
  const digits = numStr.replace(/[\s\-]/g, '');
  if (!/^\d+$/.test(digits)) return false;

  let sum = 0;
  let alternate = false;

  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }

  return sum % 10 === 0;
}

export class PciRule extends BaseRule {
  name = 'pci';
  category: DetectionCategory = 'pci';
  direction: ScanDirection = 'both';

  private detectTypes: PciType[];
  private redactWith: string;
  private allowList: Set<string>;

  constructor(options: PciRuleOptions = {}) {
    super();
    const requestedTypes = (options.detect as PciType[] | undefined) ?? ['credit_card', 'cvv', 'expiry', 'bank_account', 'routing_number'];
    // Always include amex when credit_card is included
    this.detectTypes = requestedTypes.includes('credit_card') && !requestedTypes.includes('amex' as PciType)
      ? [...requestedTypes, 'amex']
      : requestedTypes;
    this.redactWith = options.redactWith ?? '[REDACTED]';
    this.allowList = new Set((options.allowList ?? []).map(v => v.replace(/[\s\-]/g, '')));
  }

  scan(text: string): Finding[] {
    const findings: Finding[] = [];

    for (const type of this.detectTypes) {
      const pattern = PCI_PATTERNS[type];
      if (!pattern) continue;

      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(text)) !== null) {
        const matchedText = match[1] ?? match[0];
        const normalized = matchedText.replace(/[\s\-]/g, '');

        if (this.allowList.has(normalized)) continue;

        // Luhn check for card numbers to reduce false positives
        if ((type === 'credit_card' || type === 'amex') && !luhnCheck(matchedText)) {
          continue;
        }

        findings.push(this.createFinding(
          PCI_SCORES[type],
          PCI_DESCRIPTIONS[type],
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
      const pattern = PCI_PATTERNS[type];
      if (!pattern) continue;
      result = redactByPattern(result, pattern, `[PCI_${type.toUpperCase()}]`);
    }
    return result;
  }
}

export function pci(options?: PciRuleOptions): PciRule {
  return new PciRule(options);
}
