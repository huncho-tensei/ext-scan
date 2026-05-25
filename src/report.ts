import { Finding, ScanResult, Severity } from "./types";

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "\x1b[31m",
  high: "\x1b[91m",
  medium: "\x1b[33m",
  low: "\x1b[36m",
  info: "\x1b[90m",
};

const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";

export function formatReport(result: ScanResult): string {
  const lines: string[] = [];

  lines.push(`${BOLD}ext-scan${RESET} ${DIM}v0.1.0${RESET}`);
  lines.push(`Scanned ${result.extensions.length} extensions at ${result.scannedAt}`);
  lines.push("");

  if (result.findings.length === 0) {
    lines.push("\x1b[32m✓ No findings.\x1b[0m");
    return lines.join("\n");
  }

  const sorted = [...result.findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );

  const grouped = new Map<string, Finding[]>();
  for (const f of sorted) {
    const existing = grouped.get(f.extensionId) || [];
    existing.push(f);
    grouped.set(f.extensionId, existing);
  }

  for (const [extId, findings] of grouped) {
    const worst = findings[0].severity;
    const color = SEVERITY_COLOR[worst];
    lines.push(`${color}${BOLD}${extId}${RESET} ${DIM}(${findings.length} finding${findings.length > 1 ? "s" : ""})${RESET}`);

    for (const f of findings) {
      const c = SEVERITY_COLOR[f.severity];
      const loc = f.file ? ` ${DIM}${f.file}${f.line ? `:${f.line}` : ""}${RESET}` : "";
      lines.push(`  ${c}${f.severity.toUpperCase().padEnd(8)}${RESET} [${f.layer}/${f.rule}] ${f.message}${loc}`);
    }
    lines.push("");
  }

  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of result.findings) counts[f.severity]++;

  const summary = Object.entries(counts)
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${SEVERITY_COLOR[s as Severity]}${n} ${s}${RESET}`)
    .join(", ");

  lines.push(`${BOLD}Total:${RESET} ${summary}`);

  return lines.join("\n");
}

export function formatJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
