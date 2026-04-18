/**
 * Scanner engine — orchestrates rules and produces ScanResult
 *
 * Key security feature: normalizes text BEFORE scanning to defeat
 * evasion techniques (unicode, leetspeak, encoding, homoglyphs).
 */

import type { Rule, Finding, ScanResult, ScanDirection, ActionMode } from './types';
import { finalScore } from './utils/scoring';
import { normalizeText, hasEvasionIndicators } from './utils/normalizer';

export interface ScannerOptions {
  rules: Rule[];
  mode: ActionMode;
  threshold: number;
}

export class Scanner {
  private rules: Rule[];
  private mode: ActionMode;
  private threshold: number;

  constructor(options: ScannerOptions) {
    this.rules = options.rules;
    this.mode = options.mode;
    this.threshold = options.threshold;
  }

  scan(text: string, direction: ScanDirection = 'both'): ScanResult {
    const start = performance.now();

    // Guard: handle empty/null input
    if (!text || text.trim().length === 0) {
      return {
        safe: true,
        score: 0,
        action: 'pass',
        findings: [],
        duration: Math.round((performance.now() - start) * 100) / 100,
        timestamp: new Date().toISOString(),
      };
    }

    // Filter rules by direction
    const applicableRules = this.rules.filter(
      rule => rule.direction === 'both' || rule.direction === direction || direction === 'both'
    );

    // ── Normalize text to defeat evasion ─────────────────────────
    // Scan both original AND normalized text.
    // Original catches literal patterns; normalized catches evasion.
    const needsNormalization = hasEvasionIndicators(text);
    const normalized = needsNormalization ? normalizeText(text) : text;

    // Run all rules against original text
    const findings: Finding[] = [];
    for (const rule of applicableRules) {
      const ruleFindings = rule.scan(text);
      findings.push(...ruleFindings);
    }

    // If text was normalized, also scan the normalized version
    // and merge any NEW findings (avoids duplicates)
    if (needsNormalization && normalized !== text) {
      const existingDescs = new Set(findings.map(f => f.description));
      for (const rule of applicableRules) {
        const normalizedFindings = rule.scan(normalized);
        for (const finding of normalizedFindings) {
          // Only add if this is a genuinely new detection
          if (!existingDescs.has(finding.description)) {
            findings.push({
              ...finding,
              description: finding.description + ' (detected after normalization)',
            });
            existingDescs.add(finding.description);
          }
        }
      }

      // If evasion indicators were found, add a meta-finding
      findings.push({
        rule: 'normalizer',
        category: 'injection',
        severity: 'medium',
        score: 0.5,
        description: 'Text contains evasion indicators (unicode tricks, encoding, or obfuscation)',
      });
    }

    // Calculate aggregate score
    const score = finalScore(findings, text.length);
    const triggered = score >= this.threshold;

    // Determine action
    let action: ActionMode | 'pass' = 'pass';
    let redacted: string | undefined;

    if (triggered) {
      action = this.mode;

      if (this.mode === 'redact') {
        redacted = text;
        for (const rule of applicableRules) {
          redacted = rule.redact(redacted);
        }
      }
    }

    const duration = Math.round((performance.now() - start) * 100) / 100;

    return {
      safe: !triggered,
      score,
      action,
      findings,
      redacted,
      duration,
      timestamp: new Date().toISOString(),
    };
  }
}
