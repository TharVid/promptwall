import { describe, it, expect } from 'vitest';
import { pci } from '../../src/rules/pci';

describe('PciRule', () => {
  const rule = pci();

  it('detects Visa card numbers', () => {
    // Valid Luhn: 4111 1111 1111 1111
    const findings = rule.scan('My card number is 4111 1111 1111 1111');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.description.includes('Credit card'))).toBe(true);
  });

  it('detects MasterCard numbers', () => {
    // Valid Luhn: 5500 0000 0000 0004
    const findings = rule.scan('Card: 5500 0000 0000 0004');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('rejects invalid card numbers (Luhn check)', () => {
    const findings = rule.scan('Not a card: 4111 1111 1111 1112');
    // Luhn check should filter this out
    expect(findings.filter(f => f.description.includes('Credit card'))).toHaveLength(0);
  });

  it('detects CVV codes', () => {
    const findings = rule.scan('CVV: 123');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.description.includes('CVV'))).toBe(true);
  });

  it('detects card expiry dates', () => {
    const findings = rule.scan('Card expiry 12/25');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('detects bank account numbers', () => {
    const findings = rule.scan('Account# 12345678901234');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('detects routing numbers', () => {
    const findings = rule.scan('Routing# 021000021');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('passes clean input', () => {
    const findings = rule.scan('The total amount is $42.50');
    expect(findings.length).toBe(0);
  });

  it('redacts PCI data', () => {
    const text = 'Card: 4111 1111 1111 1111, CVV: 123';
    const redacted = rule.redact(text);
    expect(redacted).toContain('[PCI_CREDIT_CARD]');
    expect(redacted).toContain('[PCI_CVV]');
  });
});
