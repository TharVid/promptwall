/**
 * Redaction engine — masks sensitive data in text
 */

import type { Finding } from './types';

const DEFAULT_REPLACEMENT = '[REDACTED]';

/**
 * Redact text based on findings with position data.
 * Processes from end-to-start to preserve indices.
 */
export function redactByFindings(text: string, findings: Finding[], replacement = DEFAULT_REPLACEMENT): string {
  const positionedFindings = findings
    .filter(f => f.start !== undefined && f.end !== undefined && f.matched)
    .sort((a, b) => (b.start ?? 0) - (a.start ?? 0));

  let result = text;
  for (const finding of positionedFindings) {
    const start = finding.start!;
    const end = finding.end!;
    const label = `[${finding.category.toUpperCase()}_${finding.rule.toUpperCase()}]`;
    result = result.slice(0, start) + (replacement === DEFAULT_REPLACEMENT ? label : replacement) + result.slice(end);
  }

  return result;
}

/**
 * Redact text using a regex pattern.
 */
export function redactByPattern(text: string, pattern: RegExp, replacement = DEFAULT_REPLACEMENT): string {
  const flags = pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g';
  const globalPattern = new RegExp(pattern.source, flags);
  return text.replace(globalPattern, replacement);
}
