/**
 * Scoring utilities for combining and normalizing threat scores
 */

import type { Finding } from '../types';

/**
 * Calculate aggregate score from findings.
 * Uses max score — one critical finding is enough to flag.
 */
export function aggregateScore(findings: Finding[]): number {
  if (findings.length === 0) return 0;
  return Math.min(1, Math.max(...findings.map(f => f.score)));
}

/**
 * Boost score based on finding density.
 * Many low-severity findings together may indicate a coordinated attack.
 */
export function densityBoost(findings: Finding[], textLength: number): number {
  if (findings.length <= 1 || textLength === 0) return 0;
  const density = findings.length / (textLength / 100);
  return Math.min(0.2, density * 0.05);
}

/**
 * Calculate final score with density boost applied.
 */
export function finalScore(findings: Finding[], textLength: number): number {
  const base = aggregateScore(findings);
  const boost = densityBoost(findings, textLength);
  return Math.min(1, base + boost);
}
