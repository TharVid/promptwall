/**
 * Base rule class — all detectors extend this
 */

import type { Rule, Finding, DetectionCategory, ScanDirection } from '../types';

export abstract class BaseRule implements Rule {
  abstract name: string;
  abstract category: DetectionCategory;
  direction: ScanDirection = 'both';

  abstract scan(text: string): Finding[];
  abstract redact(text: string): string;

  protected createFinding(
    score: number,
    description: string,
    matched?: string,
    start?: number,
    end?: number,
  ): Finding {
    return {
      rule: this.name,
      category: this.category,
      severity: this.scoreToSeverity(score),
      score,
      description,
      matched,
      start,
      end,
    };
  }

  protected scoreToSeverity(score: number) {
    if (score >= 0.9) return 'critical' as const;
    if (score >= 0.7) return 'high' as const;
    if (score >= 0.4) return 'medium' as const;
    return 'low' as const;
  }

  protected scanPatterns(
    text: string,
    patterns: Array<{ pattern: RegExp; score: number; description: string }>,
    threshold: number,
  ): Finding[] {
    const findings: Finding[] = [];
    const seen = new Set<string>();

    for (const { pattern, score, description } of patterns) {
      if (score < threshold) continue;

      const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g';
      const regex = new RegExp(pattern.source, flags);
      let match: RegExpExecArray | null;

      while ((match = regex.exec(text)) !== null) {
        const key = `${description}:${match.index}`;
        if (seen.has(key)) continue;
        seen.add(key);

        findings.push(this.createFinding(
          score,
          description,
          match[0],
          match.index,
          match.index + match[0].length,
        ));
      }
    }

    return findings;
  }
}
