#!/usr/bin/env node

import { discoverExtensions } from "./discover";
import { loadCatalog, matchCatalog } from "./catalog";
import { analyzeExtension } from "./static";
import { formatReport, formatJson } from "./report";
import { Finding, ScanResult } from "./types";

async function main() {
  const args = process.argv.slice(2);
  const jsonOutput = args.includes("--json");
  const skipStatic = args.includes("--catalog-only");
  const verbose = args.includes("--verbose");

  if (args.includes("--help")) {
    console.log(`ext-scan — local extension security scanner

Usage: ext-scan [options]

Options:
  --json           Output JSON instead of formatted text
  --catalog-only   Skip static analysis, only check known-bad catalog
  --verbose        Show progress during scan
  --help           Show this message`);
    process.exit(0);
  }

  if (verbose) console.error("Discovering extensions...");
  const extensions = await discoverExtensions();

  if (extensions.length === 0) {
    console.error("No extensions found.");
    process.exit(0);
  }

  if (verbose) console.error(`Found ${extensions.length} extensions.`);

  const findings: Finding[] = [];

  if (verbose) console.error("Checking catalog...");
  const catalog = loadCatalog();
  findings.push(...matchCatalog(extensions, catalog));

  if (!skipStatic) {
    for (const ext of extensions) {
      if (verbose) console.error(`  Scanning ${ext.id}...`);
      const staticFindings = await analyzeExtension(ext);
      findings.push(...staticFindings);
    }
  }

  const result: ScanResult = {
    extensions,
    findings,
    scannedAt: new Date().toISOString(),
  };

  if (jsonOutput) {
    console.log(formatJson(result));
  } else {
    console.log(formatReport(result));
  }

  const hasCritical = findings.some((f) => f.severity === "critical");
  const hasHigh = findings.some((f) => f.severity === "high");
  process.exit(hasCritical ? 2 : hasHigh ? 1 : 0);
}

main().catch((err) => {
  console.error("ext-scan error:", err.message);
  process.exit(1);
});
