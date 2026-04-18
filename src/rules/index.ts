/**
 * Rule exports — each is a factory function for easy plugin usage:
 *   bulwark({ rules: [bulwark.jailbreak(), bulwark.pii(), ...] })
 */

export { BaseRule } from './base';
export { JailbreakRule, jailbreak } from './jailbreak';
export { InjectionRule, injection } from './injection';
export { PiiRule, pii } from './pii';
export { PhiRule, phi } from './phi';
export { PciRule, pci } from './pci';
export { ToxicityRule, toxicity } from './toxicity';

// Convenience: create all default rules
import { jailbreak } from './jailbreak';
import { injection } from './injection';
import { pii } from './pii';
import { phi } from './phi';
import { pci } from './pci';
import { toxicity } from './toxicity';
import type { Rule } from '../types';

export function defaultRules(): Rule[] {
  return [
    jailbreak(),
    injection(),
    pii(),
    phi(),
    pci(),
    toxicity(),
  ];
}
