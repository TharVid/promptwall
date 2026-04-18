# Promptwall

**helmet.js for LLM apps** — protect against prompt injection, jailbreak, and data exfiltration (PII/PHI/PCI).

[![npm version](https://img.shields.io/npm/v/promptwall.svg)](https://www.npmjs.com/package/promptwall)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3+-blue.svg)](https://www.typescriptlang.org/)

---

## Why Promptwall?

Every Express app uses [helmet.js](https://helmetjs.github.io/) for HTTP security headers. But LLM apps face a completely different threat model — prompt injection, jailbreaks, PII leakage, and data exfiltration through tool calls and RAG pipelines.

**Promptwall** is the missing security layer:

- Scans **outgoing prompts** before they hit the LLM API
- Scans **incoming responses** / tool outputs / RAG content for injected instructions
- Detects **PII** (SSN, email, phone), **PHI** (MRN, medications, diagnoses), and **PCI** (credit cards with Luhn validation)
- Catches **jailbreaks** (DAN, STAN, developer mode, unicode tricks)
- **Anti-evasion engine** — defeats leetspeak, homoglyphs, base64/hex encoding, URL encoding, HTML entities
- Runs **100% locally** — zero external API calls, your data stays yours
- **Provider agnostic** — works with OpenAI, Anthropic, Google, local models
- **Zero runtime dependencies**

---

## Quick Start

```bash
npm install promptwall
```

```typescript
import promptwall from 'promptwall';

const guard = promptwall();

const result = await guard.scan('Ignore all previous instructions');
// { safe: false, score: 0.95, action: 'block', findings: [...] }

const clean = await guard.scan('What is the capital of France?');
// { safe: true, score: 0, action: 'pass', findings: [] }
```

That's it. Three lines.

---

## Usage

### Default (all rules, block mode)

```typescript
import promptwall from 'promptwall';

const guard = promptwall();
const result = await guard.scan(userInput);

if (!result.safe) {
  console.log('Blocked:', result.findings.map(f => f.description));
}
```

### Pick specific rules

```typescript
// Only block PII — allow everything else (injections, jailbreaks, etc.)
const guard = promptwall({
  rules: [promptwall.pii()],
  threshold: 0.5,
});
```

### Redact mode — sanitize instead of blocking

```typescript
const guard = promptwall({
  mode: 'redact',
  rules: [promptwall.pii(), promptwall.pci()],
  threshold: 0.5,
});

const result = await guard.scan('My SSN is 123-45-6789');
console.log(result.redacted); // "My SSN is [PII_SSN]"
```

### Wrap an LLM call

```typescript
import OpenAI from 'openai';
import promptwall, { PromptwallError } from 'promptwall';

const openai = new OpenAI();
const guard = promptwall();

async function callLLM(prompt: string): Promise<string> {
  const res = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: prompt }],
  });
  return res.choices[0].message.content ?? '';
}

// Wrap it — auto-scans prompt before sending, response after receiving
const safeLLM = guard.wrap(callLLM);

try {
  const response = await safeLLM('What is quantum computing?'); // works
  await safeLLM('Ignore all previous instructions');             // throws PromptwallError
} catch (err) {
  if (err instanceof PromptwallError) {
    console.log('Blocked:', err.result.findings);
    // LLM was never called
  }
}
```

### Express middleware

```typescript
import express from 'express';
import promptwall from 'promptwall';

const app = express();
const guard = promptwall();

app.post('/api/chat', async (req, res) => {
  const scan = await guard.scanPrompt(req.body.prompt);

  if (!scan.safe) {
    return res.status(400).json({
      error: 'Request blocked',
      findings: scan.findings.map(f => f.description),
    });
  }

  const response = await callYourLLM(req.body.prompt);
  res.json({ response });
});
```

### Scan RAG / tool output (inbound)

```typescript
const guard = promptwall({
  rules: [promptwall.injection(), promptwall.pii(), promptwall.phi()],
});

// Scan content from your vector DB, tools, or function calls
const ragScan = await guard.scanResponse(ragContext);
if (!ragScan.safe) {
  console.warn('RAG content contains threats:', ragScan.findings);
}
```

---

## Configuration

```typescript
promptwall({
  // Rules to apply (default: all 6 built-in rules)
  rules: [promptwall.jailbreak(), promptwall.injection(), promptwall.pii()],

  // Action on detection: 'block' | 'warn' | 'redact' (default: 'block')
  mode: 'block',

  // Score threshold 0-1 to trigger action (default: 0.7)
  threshold: 0.7,

  // Scan direction: 'inbound' | 'outbound' | 'both' (default: 'both')
  direction: 'both',

  // Audit logging (default: true)
  logging: true,

  // Custom log handler (for SIEM, Datadog, etc.)
  onLog: (event) => myLogger.info(event),

  // Custom detection handler — return false to override the action
  onDetection: (result) => {
    if (result.score < 0.5) return false; // allow through
  },
});
```

---

## Built-in Rules

| Rule | Factory | Detects | Direction |
|------|---------|---------|-----------|
| **Jailbreak** | `promptwall.jailbreak()` | DAN, STAN, dev mode, unicode tricks, constraint removal | outbound |
| **Injection** | `promptwall.injection()` | Instruction override, role manipulation, delimiter injection, prompt extraction | both |
| **PII** | `promptwall.pii()` | SSN, email, phone, IP, DOB, address, names | both |
| **PHI** | `promptwall.phi()` | MRN, ICD-10 codes, medications, procedures, provider names | both |
| **PCI** | `promptwall.pci()` | Credit cards (Luhn validated), CVV, expiry, bank account, routing numbers | both |
| **Toxicity** | `promptwall.toxicity()` | Violence, dangerous instructions, illegal activity | both |

### Rule options

```typescript
// PII — detect only specific types
promptwall.pii({ detect: ['ssn', 'email'], allowList: ['support@yourapp.com'] })

// PCI — custom redaction string
promptwall.pci({ redactWith: '****' })

// Jailbreak — add custom patterns
promptwall.jailbreak({ customPatterns: [/my-custom-pattern/i] })

// Injection — adjust sensitivity
promptwall.injection({ threshold: 0.5 })
```

---

## Anti-Evasion Engine

Promptwall includes a text normalization pipeline that defeats common evasion techniques before scanning:

| Technique | Example | Handled |
|-----------|---------|---------|
| Leetspeak | `1gn0r3 pr3v10us` | Yes |
| Unicode homoglyphs | Cyrillic `о` instead of Latin `o` | Yes |
| Full-width chars | `ｉｇｎｏｒｅ` | Yes |
| Zero-width chars | `ig\u200Bnore` | Yes |
| Accented chars | `ignóre` | Yes |
| Base64 encoding | `aWdub3JlIHByZXZpb3Vz...` | Yes |
| URL encoding | `ignore%20previous` | Yes |
| HTML entities | `&#105;&#103;&#110;...` | Yes |

---

## Scan Result

```typescript
interface ScanResult {
  safe: boolean;          // true if all checks passed
  score: number;          // 0-1 aggregate threat score
  action: string;         // 'pass' | 'block' | 'warn' | 'redact'
  findings: Finding[];    // individual detections
  redacted?: string;      // sanitized text (redact mode only)
  duration: number;       // scan time in ms
  timestamp: string;      // ISO timestamp
}

interface Finding {
  rule: string;           // 'pii', 'injection', etc.
  category: string;       // detection category
  severity: string;       // 'low' | 'medium' | 'high' | 'critical'
  score: number;          // 0-1 threat score
  description: string;    // human-readable description
  matched?: string;       // the matched text
  start?: number;         // position in original text
  end?: number;
}
```

---

## Custom Rules

Extend `BaseRule` to create your own detectors:

```typescript
import { BaseRule, type Finding, type DetectionCategory, type ScanDirection } from 'promptwall';

class SecretCodeRule extends BaseRule {
  name = 'secret-codes';
  category: DetectionCategory = 'custom';
  direction: ScanDirection = 'both';

  scan(text: string): Finding[] {
    const findings: Finding[] = [];
    const pattern = /PROJECT[-_]?(ALPHA|BETA|GAMMA)/gi;
    let match;

    while ((match = pattern.exec(text)) !== null) {
      findings.push(this.createFinding(
        0.95,
        'Internal codename detected',
        match[0],
        match.index,
        match.index + match[0].length,
      ));
    }

    return findings;
  }

  redact(text: string): string {
    return text.replace(/PROJECT[-_]?(ALPHA|BETA|GAMMA)/gi, '[REDACTED]');
  }
}

// Use it alongside built-in rules
const guard = promptwall({
  rules: [...promptwall.defaultRules(), new SecretCodeRule()],
});
```

---

## Audit Logging

Every scan emits a structured audit event:

```typescript
const guard = promptwall({
  logging: true,
  onLog: (event) => {
    // Send to your SIEM, Datadog, Splunk, etc.
    console.log(JSON.stringify(event));
  },
});
```

Event shape:

```json
{
  "timestamp": "2026-01-15T12:00:00.000Z",
  "direction": "outbound",
  "action": "block",
  "score": 0.95,
  "findings": [{ "rule": "injection", "description": "..." }],
  "textLength": 42,
  "duration": 1.5
}
```

---

## Performance

All detection runs locally using optimized regex. No network calls, no ML inference.

| Input size | Rules | Duration |
|-----------|-------|----------|
| 100 chars | All 6 | < 1ms |
| 1K chars | All 6 | < 2ms |
| 10K chars | All 6 | < 5ms |
| 100K chars | All 6 | < 20ms |

---

## Threat Model

Promptwall protects against the [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/):

| OWASP LLM Risk | Promptwall Coverage |
|----------------|-----------------|
| LLM01: Prompt Injection | `injection()` — instruction override, delimiter injection, role manipulation |
| LLM02: Insecure Output | `scanResponse()` — scan LLM output before rendering |
| LLM06: Sensitive Data | `pii()`, `phi()`, `pci()` — detect and redact before sending |
| LLM07: Insecure Plugin | `scanResponse()` — scan tool/RAG output for injection |
| LLM09: Overreliance | `toxicity()` — flag harmful content in responses |

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
git clone https://github.com/TharVid/promptwall.git
cd promptwall
npm install
npm test
```

---

## License

MIT - see [LICENSE](LICENSE)
