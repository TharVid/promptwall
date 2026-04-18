/**
 * Promptwall — helmet.js for LLM apps
 * Core type definitions
 */

// ─── Action Modes ───────────────────────────────────────────────

export type ActionMode = 'block' | 'warn' | 'redact';

// ─── Scan Direction ─────────────────────────────────────────────

export type ScanDirection = 'inbound' | 'outbound' | 'both';

// ─── Severity Levels ────────────────────────────────────────────

export type Severity = 'low' | 'medium' | 'high' | 'critical';

// ─── Detection Categories ───────────────────────────────────────

export type DetectionCategory =
  | 'jailbreak'
  | 'injection'
  | 'pii'
  | 'phi'
  | 'pci'
  | 'toxicity'
  | 'custom';

// ─── Individual Finding ─────────────────────────────────────────

export interface Finding {
  /** Rule that produced this finding */
  rule: string;
  /** Detection category */
  category: DetectionCategory;
  /** Severity level */
  severity: Severity;
  /** Threat score 0-1 */
  score: number;
  /** Human-readable description */
  description: string;
  /** The matched text/pattern (if applicable) */
  matched?: string;
  /** Start index in the original text */
  start?: number;
  /** End index in the original text */
  end?: number;
}

// ─── Scan Result ────────────────────────────────────────────────

export interface ScanResult {
  /** Whether the content passed all checks */
  safe: boolean;
  /** Aggregate threat score 0-1 (max of all findings) */
  score: number;
  /** Action taken based on mode and threshold */
  action: ActionMode | 'pass';
  /** Individual findings from each rule */
  findings: Finding[];
  /** Redacted text (only when mode is 'redact') */
  redacted?: string;
  /** Scan duration in milliseconds */
  duration: number;
  /** Timestamp of the scan */
  timestamp: string;
}

// ─── Rule Interface ─────────────────────────────────────────────

export interface Rule {
  /** Unique rule name */
  name: string;
  /** Detection category */
  category: DetectionCategory;
  /** Whether this rule applies to inbound, outbound, or both */
  direction: ScanDirection;
  /** Run detection on the given text */
  scan(text: string): Finding[];
  /** Redact detected content from text */
  redact(text: string): string;
}

// ─── Rule Factory Options ───────────────────────────────────────

export interface JailbreakRuleOptions {
  /** Additional jailbreak patterns to detect */
  customPatterns?: RegExp[];
  /** Minimum score threshold to report (default: 0.3) */
  threshold?: number;
}

export interface InjectionRuleOptions {
  /** Additional injection patterns to detect */
  customPatterns?: RegExp[];
  threshold?: number;
}

export interface PiiRuleOptions {
  /** Which PII types to detect. Default: all */
  detect?: Array<'email' | 'phone' | 'ssn' | 'address' | 'name' | 'ip' | 'dob'>;
  /** Replacement string for redaction (default: '[REDACTED]') */
  redactWith?: string;
  /** Allow-list of values to skip */
  allowList?: string[];
}

export interface PhiRuleOptions {
  /** Which PHI types to detect. Default: all */
  detect?: Array<'mrn' | 'diagnosis' | 'medication' | 'procedure' | 'provider'>;
  redactWith?: string;
  allowList?: string[];
}

export interface PciRuleOptions {
  /** Which PCI types to detect. Default: all */
  detect?: Array<'credit_card' | 'cvv' | 'expiry' | 'bank_account' | 'routing_number'>;
  redactWith?: string;
  allowList?: string[];
}

export interface ToxicityRuleOptions {
  /** Custom toxic patterns */
  customPatterns?: RegExp[];
  threshold?: number;
}

// ─── Promptwall Configuration ──────────────────────────────────────

export interface PromptwallOptions {
  /** Rules to apply (default: all built-in rules) */
  rules?: Rule[];
  /** Default action mode (default: 'block') */
  mode?: ActionMode;
  /** Threat score threshold to trigger action (default: 0.7) */
  threshold?: number;
  /** Scan direction filter (default: 'both') */
  direction?: ScanDirection;
  /** Enable audit logging (default: true) */
  logging?: boolean;
  /** Custom log handler */
  onLog?: (event: AuditEvent) => void;
  /** Custom action handler — return false to override the default action */
  onDetection?: (result: ScanResult) => boolean | void;
}

// ─── Audit Event ────────────────────────────────────────────────

export interface AuditEvent {
  timestamp: string;
  direction: ScanDirection;
  action: ActionMode | 'pass';
  score: number;
  findings: Finding[];
  textLength: number;
  duration: number;
}

// ─── Middleware Types ────────────────────────────────────────────

export interface PromptwallMiddleware {
  /** Scan outgoing prompt before sending to LLM */
  scanPrompt(text: string): Promise<ScanResult>;
  /** Scan incoming response/tool output from LLM */
  scanResponse(text: string): Promise<ScanResult>;
  /** Scan any text in both directions */
  scan(text: string, direction?: ScanDirection): Promise<ScanResult>;
  /** Wrap an LLM call function with automatic scanning */
  wrap<T>(fn: (prompt: string) => Promise<T>): (prompt: string) => Promise<T>;
}
