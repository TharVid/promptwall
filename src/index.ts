/**
 * Bulwark — helmet.js for LLM apps
 *
 * Quick start:
 *   import bulwark from 'bulwark';
 *   const guard = bulwark();
 *   const result = await guard.scan(userInput);
 *   if (!result.safe) console.log('Threat detected:', result.findings);
 *
 * With specific rules:
 *   const guard = bulwark({ rules: [bulwark.pii(), bulwark.injection()] });
 *
 * Wrap an LLM call:
 *   const safeLLM = guard.wrap(myLLMCall);
 *   const response = await safeLLM('Hello world');
 */

import { Bulwark, BulwarkError } from './bulwark';
import { jailbreak } from './rules/jailbreak';
import { injection } from './rules/injection';
import { pii } from './rules/pii';
import { phi } from './rules/phi';
import { pci } from './rules/pci';
import { toxicity } from './rules/toxicity';
import { defaultRules } from './rules';

import type {
  BulwarkOptions,
  BulwarkMiddleware,
  ScanResult,
  ScanDirection,
  ActionMode,
  Severity,
  DetectionCategory,
  Finding,
  AuditEvent,
  Rule,
  JailbreakRuleOptions,
  InjectionRuleOptions,
  PiiRuleOptions,
  PhiRuleOptions,
  PciRuleOptions,
  ToxicityRuleOptions,
} from './types';

// ─── Factory function (default export) ──────────────────────────

function bulwark(options?: BulwarkOptions): Bulwark {
  return new Bulwark(options);
}

// Attach rule factories as static methods for convenience:
//   bulwark.pii(), bulwark.injection(), etc.
bulwark.jailbreak = jailbreak;
bulwark.injection = injection;
bulwark.pii = pii;
bulwark.phi = phi;
bulwark.pci = pci;
bulwark.toxicity = toxicity;
bulwark.defaultRules = defaultRules;

// ─── Exports ────────────────────────────────────────────────────

export default bulwark;

// Named exports for fine-grained imports
export { Bulwark, BulwarkError } from './bulwark';
export { Scanner } from './scanner';
export { AuditLogger } from './logger';
export { BaseRule } from './rules/base';
export { jailbreak, JailbreakRule } from './rules/jailbreak';
export { injection, InjectionRule } from './rules/injection';
export { pii, PiiRule } from './rules/pii';
export { phi, PhiRule } from './rules/phi';
export { pci, PciRule } from './rules/pci';
export { toxicity, ToxicityRule } from './rules/toxicity';
export { defaultRules } from './rules';
export { redactByFindings, redactByPattern } from './redactor';
export { normalizeText, hasEvasionIndicators } from './utils/normalizer';

export type {
  BulwarkOptions,
  BulwarkMiddleware,
  ScanResult,
  ScanDirection,
  ActionMode,
  Severity,
  DetectionCategory,
  Finding,
  AuditEvent,
  Rule,
  JailbreakRuleOptions,
  InjectionRuleOptions,
  PiiRuleOptions,
  PhiRuleOptions,
  PciRuleOptions,
  ToxicityRuleOptions,
};
