#!/usr/bin/env node

import "dotenv/config";
import { discoverExtensions } from "./discover";
import { loadCatalog, matchCatalog } from "./catalog";
import { analyzeExtension } from "./static";
import { aiScanExtension } from "./ai";
import { formatReport, formatJson } from "./report";
import { Finding, ScanResult } from "./types";

async function main() {
  const args = process.argv.slice(2);
  const jsonOutput = args.includes("--json");
  const skipStatic = args.includes("--catalog-only");
  const deepScan = args.includes("--deep");
  const noInfo = args.includes("--no-info");
  const verbose = args.includes("--verbose");

  if (args.includes("--help")) {
    console.log(`ext-scan — local extension security scanner

Usage: ext-scan [options]

Options:
  --json           Output JSON instead of formatted text
  --catalog-only   Skip static analysis, only check known-bad catalog
  --deep           Run AI deep scan on untrusted extensions (needs ANTHROPIC_API_KEY)
  --no-info        Hide info-level findings (trusted publisher noise)
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

  if (deepScan) {
    if (!process.env.ANTHROPIC_API_KEY) {
      console.error("Error: --deep requires ANTHROPIC_API_KEY to be set.");
      process.exit(1);
    }
    const untrusted = extensions.filter(
      (e) => findings.some((f) => f.extensionId === e.id && f.severity !== "info")
    );
    if (untrusted.length === 0) {
      if (verbose) console.error("No untrusted extensions with findings — skipping AI scan.");
    } else {
      if (verbose) console.error(`Running AI deep scan on ${untrusted.length} extension(s)...`);
      for (const ext of untrusted) {
        if (verbose) console.error(`  AI scanning ${ext.id}...`);
        try {
          const aiFindings = await aiScanExtension(ext);
          findings.push(...aiFindings);
        } catch (err: any) {
          console.error(`  AI scan failed for ${ext.id}: ${err.message}`);
        }
      }
    }
  }

  const filtered = noInfo
    ? findings.filter((f) => f.severity !== "info")
    : findings;

  const result: ScanResult = {
    extensions,
    findings: filtered,
    scannedAt: new Date().toISOString(),
  };

  if (jsonOutput) {
    console.log(formatJson(result));
  } else {
    console.log(formatReport(result));
  }

  const hasCritical = filtered.some((f) => f.severity === "critical");
  const hasHigh = filtered.some((f) => f.severity === "high");
  process.exit(hasCritical ? 2 : hasHigh ? 1 : 0);
}

main().catch((err) => {
  console.error("ext-scan error:", err.message);
  process.exit(1);
});
