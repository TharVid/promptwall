# Contributing to Promptwall

Thanks for your interest in contributing! Here's how to get started.

## Setup

```bash
git clone https://github.com/TharVid/promptwall.git
cd promptwall
npm install
```

## Development

```bash
npm test          # run tests
npm run build     # compile TypeScript
npm run test:watch # watch mode
```

## Project Structure

```
src/
  index.ts          # main entry point and exports
  promptwall.ts     # core Promptwall class
  scanner.ts        # rule orchestration engine
  logger.ts         # structured audit logging
  redactor.ts       # redaction engine
  types.ts          # TypeScript interfaces
  rules/            # detection rules
    base.ts         # base rule class
    jailbreak.ts    # jailbreak detection
    injection.ts    # prompt injection detection
    pii.ts          # PII detection (SSN, email, phone, etc.)
    phi.ts          # PHI detection (HIPAA)
    pci.ts          # PCI detection (credit cards, Luhn)
    toxicity.ts     # toxic content detection
  utils/
    patterns.ts     # regex pattern library
    normalizer.ts   # anti-evasion text normalization
    scoring.ts      # threat score aggregation
tests/              # test suite (99 tests)
examples/           # usage examples
```

## Adding a New Rule

1. Create `src/rules/your-rule.ts` extending `BaseRule`
2. Implement `scan()` and `redact()` methods
3. Export from `src/rules/index.ts`
4. Add factory function to `src/index.ts`
5. Write tests in `tests/rules/your-rule.test.ts`

## Pull Requests

- Keep PRs focused — one feature or fix per PR
- Add tests for new detection patterns
- Run `npm test` before submitting
- Update README if adding user-facing features

## Reporting Vulnerabilities

If you find a security issue (bypass, evasion technique, etc.), please open an issue or email directly. We take bypass reports seriously — they make the project better for everyone.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
