/**
 * Promptwall — helmet.js for LLM apps
 *
 * Quick start:
 *   import promptwall from 'promptwall';
 *   const guard = promptwall();
 *   const result = await guard.scan(userInput);
 *   if (!result.safe) console.log('Threat detected:', result.findings);
 *
 * With specific rules:
 *   const guard = promptwall({ rules: [promptwall.pii(), promptwall.injection()] });
 *
 * Wrap an LLM call:
 *   const safeLLM = guard.wrap(myLLMCall);
 *   const response = await safeLLM('Hello world');
 */

import { Promptwall, PromptwallError } from './promptwall';
import { jailbreak } from './rules/jailbreak';
import { injection } from './rules/injection';
import { pii } from './rules/pii';
import { phi } from './rules/phi';
import { pci } from './rules/pci';
import { toxicity } from './rules/toxicity';
import { defaultRules } from './rules';

import type {
  PromptwallOptions,
  PromptwallMiddleware,
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

function promptwall(options?: PromptwallOptions): Promptwall {
  return new Promptwall(options);
}

// Attach rule factories as static methods for convenience:
//   promptwall.pii(), promptwall.injection(), etc.
promptwall.jailbreak = jailbreak;
promptwall.injection = injection;
promptwall.pii = pii;
promptwall.phi = phi;
promptwall.pci = pci;
promptwall.toxicity = toxicity;
promptwall.defaultRules = defaultRules;

// ─── Exports ────────────────────────────────────────────────────

export default promptwall;

// CJS/ESM interop: ensure `require('promptwall')` returns the factory directly
// and `import promptwall from 'promptwall'` works in ESM via .default
module.exports = promptwall;
module.exports.default = promptwall;
module.exports.Promptwall = Promptwall;
module.exports.PromptwallError = PromptwallError;

// Named exports for fine-grained imports
export { Promptwall, PromptwallError } from './promptwall';
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
  PromptwallOptions,
  PromptwallMiddleware,
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
