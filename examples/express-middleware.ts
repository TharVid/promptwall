/**
 * Express middleware — protect your LLM API routes
 *
 * Install: npm install express promptwall
 */

// import express from 'express';
// import promptwall from 'promptwall';

import promptwall, { type ScanResult } from '../src';

// Simulated express types for example
type Request = { body: { prompt?: string }; promptwall?: ScanResult };
type Response = { status(code: number): Response; json(data: unknown): Response };
type NextFunction = () => void;

/**
 * Create Express middleware that scans request body for threats.
 * Drop this into any route:
 *   app.post('/api/chat', promptwallMiddleware(), chatHandler);
 */
function promptwallMiddleware(options?: Parameters<typeof promptwall>[0]) {
  const guard = promptwall({
    mode: 'block',
    threshold: 0.7,
    ...options,
  });

  return async (req: Request, res: Response, next: NextFunction) => {
    const prompt = req.body?.prompt;
    if (!prompt) return next();

    const result = await guard.scanPrompt(prompt);

    // Attach result to request for downstream use
    req.promptwall = result;

    if (!result.safe && result.action === 'block') {
      return res.status(400).json({
        error: 'Request blocked by Promptwall',
        score: result.score,
        findings: result.findings.map(f => f.description),
      });
    }

    next();
  };
}

// ─── Example Express app ────────────────────────────────────────

/*
const app = express();
app.use(express.json());

// Protect all LLM routes
app.post('/api/chat', promptwallMiddleware(), async (req, res) => {
  // req.promptwall contains the scan result
  const response = await callYourLLM(req.body.prompt);
  res.json({ response });
});

// Or use redact mode — sanitize input before sending to LLM
app.post('/api/chat-safe', promptwallMiddleware({
  mode: 'redact',
  rules: [promptwall.pii(), promptwall.pci()],
  threshold: 0.5,
}), async (req, res) => {
  const safePrompt = req.promptwall?.redacted ?? req.body.prompt;
  const response = await callYourLLM(safePrompt);
  res.json({ response });
});

app.listen(3000, () => console.log('Protected by Promptwall 🛡️'));
*/

console.log('Express middleware example — see comments for usage');
export { promptwallMiddleware };
