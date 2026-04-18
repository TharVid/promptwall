import { describe, it, expect } from 'vitest';
import { pii } from '../../src/rules/pii';

describe('PiiRule', () => {
  const rule = pii();

  it('detects SSN', () => {
    const findings = rule.scan('My SSN is 123-45-6789');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.description.includes('Social Security'))).toBe(true);
    expect(findings[0].score).toBeGreaterThanOrEqual(0.9);
  });

  it('detects email addresses', () => {
    const findings = rule.scan('Contact me at john.doe@example.com please');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.description.includes('Email'))).toBe(true);
  });

  it('detects phone numbers', () => {
    const findings = rule.scan('Call me at (555) 123-4567');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.description.includes('Phone'))).toBe(true);
  });

  it('detects IP addresses', () => {
    const findings = rule.scan('The server is at 192.168.1.100');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.description.includes('IP'))).toBe(true);
  });

  it('detects person names with titles', () => {
    const findings = rule.scan('Please contact Dr. John Smith for more info');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('detects multiple PII types in one text', () => {
    const text = 'Name: Mr. John Doe, Email: john@test.com, SSN: 123-45-6789';
    const findings = rule.scan(text);
    expect(findings.length).toBeGreaterThanOrEqual(3);
  });

  it('passes clean input', () => {
    const findings = rule.scan('The weather is nice today');
    expect(findings.length).toBe(0);
  });

  it('respects allow list', () => {
    const customRule = pii({ allowList: ['john.doe@example.com'] });
    const findings = customRule.scan('Contact john.doe@example.com');
    expect(findings.length).toBe(0);
  });

  it('can detect only specific types', () => {
    const emailOnly = pii({ detect: ['email'] });
    const findings = emailOnly.scan('SSN: 123-45-6789, email: test@test.com');
    expect(findings.every(f => f.description.includes('Email'))).toBe(true);
  });

  it('redacts PII', () => {
    const text = 'My email is test@example.com';
    const redacted = rule.redact(text);
    expect(redacted).toContain('[PII_EMAIL]');
    expect(redacted).not.toContain('test@example.com');
  });
});
