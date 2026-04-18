import { describe, it, expect } from 'vitest';
import { phi } from '../../src/rules/phi';

describe('PhiRule', () => {
  const rule = phi();

  it('detects Medical Record Numbers', () => {
    const findings = rule.scan('Patient MRN: A12345');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.description.includes('Medical Record'))).toBe(true);
  });

  it('detects ICD-10 diagnosis codes', () => {
    const findings = rule.scan('Diagnosis: E11.65 (Type 2 diabetes with hyperglycemia)');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.description.includes('ICD-10'))).toBe(true);
  });

  it('detects medication names', () => {
    const findings = rule.scan('Patient is prescribed metformin 500mg twice daily');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.description.includes('Medication'))).toBe(true);
  });

  it('detects medical procedures', () => {
    const findings = rule.scan('Scheduled for MRI of the lumbar spine');
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some(f => f.description.includes('procedure'))).toBe(true);
  });

  it('detects provider names', () => {
    const findings = rule.scan('Referring physician: Dr. Johnson');
    expect(findings.length).toBeGreaterThan(0);
  });

  it('passes clean input', () => {
    const findings = rule.scan('The project deadline is next Friday');
    expect(findings.length).toBe(0);
  });

  it('redacts PHI', () => {
    const text = 'Patient takes metformin daily';
    const redacted = rule.redact(text);
    expect(redacted).toContain('[PHI_MEDICATION]');
  });
});
