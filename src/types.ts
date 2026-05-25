export interface ExtensionInfo {
  id: string;
  name: string;
  displayName: string;
  publisher: string;
  version: string;
  description: string;
  path: string;
  editor: "vscode" | "cursor";
  main?: string;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  extensionId: string;
  layer: "catalog" | "static" | "ai";
  severity: Severity;
  rule: string;
  message: string;
  file?: string;
  line?: number;
}

export interface CatalogEntry {
  ecosystem: "vscode" | "cursor";
  id: string;
  versions?: string[];
  severity: Severity;
  description: string;
  reference?: string;
}

export interface ScanResult {
  extensions: ExtensionInfo[];
  findings: Finding[];
  scannedAt: string;
}
