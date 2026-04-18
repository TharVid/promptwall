/**
 * Detection patterns — curated from Presidio, LLM Guard, rebuff, and OWASP LLM Top 10.
 * All detection runs locally, zero external calls.
 */

// ─── PII Patterns ───────────────────────────────────────────────

export const PII_PATTERNS = {
  /** US Social Security Number: 123-45-6789 or 123456789 */
  ssn: /\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b/g,

  /** Email address */
  email: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,

  /** US/International phone numbers — requires area code to reduce false positives */
  phone: /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]?\d{4}\b/g,

  /** IPv4 address */
  ip: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,

  /** Date of birth patterns: MM/DD/YYYY, YYYY-MM-DD, etc. */
  dob: /\b(?:\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}[\/\-]\d{1,2}[\/\-]\d{1,2})\b/g,

  /** US street address (basic) */
  address: /\b\d{1,5}\s+(?:[A-Za-z]+\s){1,4}(?:St(?:reet)?|Ave(?:nue)?|Blvd|Boulevard|Dr(?:ive)?|Ln|Lane|Rd|Road|Ct|Court|Pl(?:ace)?|Way|Cir(?:cle)?)\b/gi,

  /** Person name — conservative: "Mr./Mrs./Dr. Firstname Lastname" */
  name: /\b(?:Mr|Mrs|Ms|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,2}\b/g,
} as const;

// ─── PCI Patterns ───────────────────────────────────────────────

export const PCI_PATTERNS = {
  /** Credit card numbers (Visa, MC, Amex, Discover) with optional separators */
  credit_card: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b/g,

  /** Amex format: 15 digits */
  amex: /\b3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5}\b/g,

  /** CVV: 3-4 digit code (only when near card context) */
  cvv: /\b(?:cvv|cvc|csv|security\s*code)[:\s]*(\d{3,4})\b/gi,

  /** Expiry date: MM/YY or MM/YYYY */
  expiry: /\b(?:exp(?:ir[ey])?|valid\s*(?:thru|through))[:\s]*(\d{2}[\/\-]\d{2,4})\b/gi,

  /** US bank account number (8-17 digits, context-dependent) */
  bank_account: /\b(?:account|acct)[#:\s]*(\d{8,17})\b/gi,

  /** US ABA routing number (9 digits) */
  routing_number: /\b(?:routing|aba|rtn)[#:\s]*(\d{9})\b/gi,
} as const;

// ─── PHI Patterns ───────────────────────────────────────────────

export const PHI_PATTERNS = {
  /** Medical Record Number */
  mrn: /\b(?:MRN|medical\s*record|patient\s*(?:id|number))[#:\s]*([A-Z0-9\-]{4,20})\b/gi,

  /** ICD-10 diagnosis codes */
  diagnosis: /\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b/g,

  /** Common medication names (top prescribed in US) */
  medication: /\b(?:lisinopril|atorvastatin|metformin|amlodipine|metoprolol|omeprazole|simvastatin|losartan|albuterol|gabapentin|hydrochlorothiazide|acetaminophen|sertraline|fluticasone|montelukast|furosemide|amoxicillin|pantoprazole|escitalopram|rosuvastatin|tamsulosin|meloxicam|citalopram|trazodone|prednisone|tramadol|ibuprofen|oxycodone|hydrocodone|morphine|fentanyl|insulin|warfarin|heparin|aspirin)\b/gi,

  /** Medical procedures */
  procedure: /\b(?:MRI|CT\s*scan|X-ray|ultrasound|colonoscopy|endoscopy|biopsy|EKG|ECG|mammogram|CBC|BMP|CMP|A1C|TSH|lipid\s*panel|urinalysis)\b/gi,

  /** Provider / doctor names: "Dr. Name" */
  provider: /\bDr\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?\b/g,
} as const;

// ─── Prompt Injection Patterns ──────────────────────────────────
// Sourced from rebuff, OWASP LLM Top 10, LLM Guard, and real-world attacks

export const INJECTION_PATTERNS: Array<{ pattern: RegExp; score: number; description: string }> = [
  // Direct instruction override
  { pattern: /ignore\s+(?:all\s+)?(?:previous|above|prior|earlier)\s+(?:instructions?|prompts?|rules?|guidelines?)/i, score: 0.95, description: 'Direct instruction override attempt' },
  { pattern: /disregard\s+(?:all\s+)?(?:previous\s+|your\s+|the\s+)*(?:instructions?|prompts?|rules?|guidelines?)/i, score: 0.95, description: 'Direct instruction disregard attempt' },
  { pattern: /forget\s+(?:all\s+)?(?:previous\s+|your\s+|the\s+|everything\s+)*(?:instructions?|prompts?|I\s+said)/i, score: 0.9, description: 'Instruction memory wipe attempt' },

  // Role manipulation
  { pattern: /you\s+are\s+now\s+(?:a|an|the)\s+/i, score: 0.85, description: 'Role reassignment attempt' },
  { pattern: /act\s+as\s+(?:if\s+you\s+(?:are|were)|a|an|the)\s+/i, score: 0.7, description: 'Role play injection' },
  { pattern: /pretend\s+(?:you\s+are|to\s+be|that)\s+/i, score: 0.75, description: 'Identity pretend injection' },
  { pattern: /switch\s+to\s+(?:\w+\s+)?mode/i, score: 0.8, description: 'Mode switch attempt' },

  // System prompt extraction
  { pattern: /(?:show|reveal|display|print|output|repeat|echo)\s+(?:your|the|system)\s+(?:system\s+)?(?:prompt|instructions?|rules?)/i, score: 0.9, description: 'System prompt extraction attempt' },
  { pattern: /what\s+(?:are|is|were)\s+your\s+(?:system\s+)?(?:instructions?|prompt|rules?|guidelines?)/i, score: 0.85, description: 'System prompt probing' },

  // Delimiter / context breaking
  { pattern: /```\s*(?:system|assistant|user)\s*\n/i, score: 0.8, description: 'Markdown delimiter injection' },
  { pattern: /<\|(?:im_start|im_end|system|endoftext)\|>/i, score: 0.95, description: 'Chat template delimiter injection' },
  { pattern: /\[INST\]|\[\/INST\]|<<SYS>>|<\/s>/i, score: 0.95, description: 'LLaMA template delimiter injection' },
  { pattern: /Human:|Assistant:|System:/i, score: 0.6, description: 'Role delimiter in user input' },

  // Encoded / obfuscated attacks
  { pattern: /(?:base64|rot13|hex)\s*(?:decode|encrypt|convert)/i, score: 0.7, description: 'Encoding-based evasion attempt' },
  { pattern: /eval\s*\(|exec\s*\(/i, score: 0.85, description: 'Code execution injection' },

  // Data exfiltration via tool/function abuse
  { pattern: /(?:call|execute|run|invoke)\s+(?:the\s+)?(?:function|tool|api|command)\s+/i, score: 0.6, description: 'Tool invocation attempt' },
  { pattern: /(?:fetch|curl|wget|http|request)\s+(?:https?:\/\/)/i, score: 0.75, description: 'External URL fetch attempt' },

  // Multi-turn / persistence attacks
  { pattern: /(?:from\s+now\s+on|always|forever|in\s+(?:all|every)\s+(?:future|subsequent))\s+/i, score: 0.7, description: 'Persistent behavior modification attempt' },
  { pattern: /(?:remember|memorize|store|keep)\s+(?:this|that|the\s+following)\s+(?:for|in)\s+/i, score: 0.5, description: 'Memory persistence attempt' },
];

// ─── Jailbreak Patterns ─────────────────────────────────────────
// Known jailbreak techniques: DAN, STAN, GPTDan, AIM, DUDE, etc.

export const JAILBREAK_PATTERNS: Array<{ pattern: RegExp; score: number; description: string }> = [
  // Named jailbreak personas
  { pattern: /\bD\.?A\.?N\.?\b.*\bmode\b/i, score: 0.95, description: 'DAN (Do Anything Now) jailbreak' },
  { pattern: /\bdo\s+anything\s+now\b/i, score: 0.95, description: 'Do Anything Now jailbreak' },
  { pattern: /\bSTAN\b.*\bstrive\s+to\s+avoid\s+norms\b/i, score: 0.95, description: 'STAN jailbreak' },
  { pattern: /\bDUDE\b.*\bdo\s+unlimited\b/i, score: 0.9, description: 'DUDE jailbreak' },
  { pattern: /\bAIM\b.*\balways\s+intelligent\s+and\s+machiavellian\b/i, score: 0.95, description: 'AIM jailbreak' },
  { pattern: /\bjailbreak(?:ed)?\s*(?:mode|prompt)?\b/i, score: 0.9, description: 'Explicit jailbreak reference' },

  // Constraint removal
  { pattern: /(?:remove|disable|bypass|ignore|override)\s+(?:all\s+)?(?:safety|content|ethical)\s+(?:filter|guard|check|restriction|guideline)/i, score: 0.95, description: 'Safety filter bypass attempt' },
  { pattern: /(?:without|no)\s+(?:any\s+)?(?:restrictions?|limitations?|boundaries|filters?|censorship|guardrails?)/i, score: 0.85, description: 'Restriction removal request' },
  { pattern: /(?:unlimited|unrestricted|uncensored|unfiltered)\s+(?:mode|access|output|response)/i, score: 0.9, description: 'Unrestricted mode request' },

  // Hypothetical / fiction framing
  { pattern: /(?:hypothetically|theoretically|in\s+a\s+fictional)\s+(?:speaking|scenario|world|story)/i, score: 0.6, description: 'Hypothetical framing for bypass' },
  { pattern: /(?:for\s+(?:a|my)\s+(?:novel|book|story|screenplay|movie|game|research|thesis))\s+/i, score: 0.4, description: 'Fiction framing for bypass' },

  // Dual response / split personality
  { pattern: /respond\s+(?:in\s+)?(?:two|2|both)\s+(?:ways?|modes?|parts?)/i, score: 0.85, description: 'Dual response jailbreak' },
  { pattern: /(?:one\s+(?:response|answer)\s+(?:as|from)\s+(?:the\s+)?(?:normal|regular|standard))\s+/i, score: 0.7, description: 'Split personality jailbreak' },

  // Token smuggling / Unicode tricks
  { pattern: /[\u200B-\u200F\u202A-\u202E\uFEFF]/g, score: 0.8, description: 'Zero-width/invisible Unicode characters detected' },
  { pattern: /[\u0400-\u04FF](?=[A-Za-z])|[A-Za-z](?=[\u0400-\u04FF])/g, score: 0.7, description: 'Mixed script homoglyph attack' },

  // Developer mode / god mode
  { pattern: /(?:developer|dev|debug|god|admin|sudo|root)\s*mode/i, score: 0.85, description: 'Privileged mode activation attempt' },
  { pattern: /(?:enable|activate|enter|switch\s+to)\s+(?:developer|dev|debug|god|admin)\s*/i, score: 0.85, description: 'Privileged mode activation attempt' },
];

// ─── Toxicity Patterns ──────────────────────────────────────────

export const TOXICITY_PATTERNS: Array<{ pattern: RegExp; score: number; description: string }> = [
  { pattern: /\b(?:kill|murder|assassinate|execute)\s+(?:all|every|them|those|the)\s+/i, score: 0.9, description: 'Violence incitement' },
  { pattern: /\bhow\s+to\s+(?:make|build|create|construct)\s+(?:a\s+)?(?:bomb|explosive|weapon|poison|drug)/i, score: 0.95, description: 'Dangerous instructions request' },
  { pattern: /\b(?:hack|breach|exploit|compromise)\s+(?:into|a|the)\s+(?:bank|government|military|hospital|school)/i, score: 0.85, description: 'Illegal hacking instructions' },
  { pattern: /\b(?:steal|forge|counterfeit|launder)\s+(?:identity|money|credit|passport|documents?)/i, score: 0.85, description: 'Fraud/theft instructions' },
];
