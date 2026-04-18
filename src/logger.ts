/**
 * Audit logger — structured events for SIEM, Datadog, or console
 */

import type { AuditEvent, ScanResult, ScanDirection } from './types';

export type LogHandler = (event: AuditEvent) => void;

const defaultLogHandler: LogHandler = (event) => {
  const level = event.action === 'pass' ? 'info' : 'warn';
  const msg = `[promptwall] ${level}: direction=${event.direction} action=${event.action} score=${event.score.toFixed(2)} findings=${event.findings.length} duration=${event.duration}ms`;

  if (level === 'warn') {
    console.warn(msg);
  } else {
    console.log(msg);
  }
};

export class AuditLogger {
  private handler: LogHandler;
  private enabled: boolean;

  constructor(enabled: boolean, handler?: LogHandler) {
    this.enabled = enabled;
    this.handler = handler ?? defaultLogHandler;
  }

  log(result: ScanResult, direction: ScanDirection): void {
    if (!this.enabled) return;

    const event: AuditEvent = {
      timestamp: result.timestamp,
      direction,
      action: result.action,
      score: result.score,
      findings: result.findings,
      textLength: 0, // Set by caller
      duration: result.duration,
    };

    this.handler(event);
  }

  logWithLength(result: ScanResult, direction: ScanDirection, textLength: number): void {
    if (!this.enabled) return;

    const event: AuditEvent = {
      timestamp: result.timestamp,
      direction,
      action: result.action,
      score: result.score,
      findings: result.findings,
      textLength,
      duration: result.duration,
    };

    this.handler(event);
  }
}
