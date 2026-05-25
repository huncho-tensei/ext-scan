import * as fs from "fs";
import * as path from "path";
import { CatalogEntry, ExtensionInfo, Finding } from "./types";

export function loadCatalog(
  catalogPath?: string
): CatalogEntry[] {
  const resolved =
    catalogPath || path.join(__dirname, "..", "catalog", "known-bad.json");
  const raw = fs.readFileSync(resolved, "utf-8");
  return JSON.parse(raw);
}

export function matchCatalog(
  extensions: ExtensionInfo[],
  catalog: CatalogEntry[]
): Finding[] {
  const findings: Finding[] = [];

  for (const ext of extensions) {
    for (const entry of catalog) {
      if (ext.id !== entry.id) continue;

      if (entry.versions && entry.versions.length > 0) {
        if (!entry.versions.includes(ext.version)) continue;
      }

      findings.push({
        extensionId: ext.id,
        layer: "catalog",
        severity: entry.severity,
        rule: "known-compromised",
        message: entry.description,
      });
    }
  }

  return findings;
}
