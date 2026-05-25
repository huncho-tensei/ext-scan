import * as fs from "fs";
import * as path from "path";
import { ExtensionInfo, Finding, Severity } from "./types";

interface Rule {
  id: string;
  severity: Severity;
  pattern: RegExp;
  message: string;
}

// Detection rules for suspicious patterns in extension source code.
// These regexes match patterns we want to FLAG in scanned extensions,
// not patterns we execute ourselves.
export const RULES: Rule[] = [
  {
    id: "shell-exec",
    severity: "high",
    pattern: /\b(?:child_process|cp)\s*[\.\[]\s*['"]?exec(?:Sync)?['"]?\s*\(/,
    message: "Shell execution via child_process — can run arbitrary commands",
  },
  {
    id: "env-access",
    severity: "medium",
    pattern: /process\.env\b/,
    message: "Reads environment variables — may harvest credentials or tokens",
  },
  {
    id: "eval-usage",
    severity: "high",
    pattern: /\beval\s*\(/,
    message: "Uses eval() — can execute arbitrary code at runtime",
  },
  {
    id: "network-ip",
    severity: "high",
    pattern: /['"`]https?:\/\/(?!127\.0\.0\.1|0\.0\.0\.0|localhost)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
    message: "Network request to raw IP address — common exfiltration pattern",
  },
  {
    id: "sensitive-file-read",
    severity: "high",
    pattern: /[\/\\]\.ssh[\/\\]|[\/\\]\.gnupg[\/\\]|[\/\\]\.aws[\/\\]|[\/\\]\.netrc\b|[\/\\]\.npmrc\b|[\/\\]\.docker[\/\\]|id_rsa\b|id_ed25519\b|[\/\\]\.env\b|[\/\\]credentials\b/,
    message: "References sensitive file paths — may read keys, tokens, or credentials",
  },
  {
    id: "base64-decode",
    severity: "medium",
    pattern: /Buffer\.from\s*\(\s*['"][A-Za-z0-9+\/=]{20,}['"]\s*,\s*['"]base64['"]\s*\)/,
    message: "Decodes hardcoded base64 string — possible obfuscated payload",
  },
  {
    id: "crypto-wallet",
    severity: "high",
    pattern: /\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b/,
    message: "Contains cryptocurrency wallet address — possible drain target",
  },
  {
    id: "clipboard-read",
    severity: "medium",
    pattern: /clipboard\.readText|navigator\.clipboard/,
    message: "Reads clipboard contents — may harvest copied credentials or keys",
  },
];

const TRUSTED_PUBLISHERS = new Set([
  "ms-python", "ms-vscode", "vscjava", "redhat",
  "github", "microsoft", "visualstudioexptteam",
  "anthropic", "dbaeumer", "esbenp",
]);

const SKIP_DIRS = new Set(["node_modules", ".git", ".vscode"]);
const SCAN_EXTENSIONS = new Set([".js", ".ts", ".mjs", ".cjs"]);
const MAX_FILE_SIZE = 2 * 1024 * 1024;

function collectFiles(dir: string): string[] {
  const results: string[] = [];

  function walk(current: string) {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (SKIP_DIRS.has(entry.name)) continue;

      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile() && SCAN_EXTENSIONS.has(path.extname(entry.name))) {
        results.push(full);
      }
    }
  }

  walk(dir);
  return results;
}

export async function analyzeExtension(ext: ExtensionInfo): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = collectFiles(ext.path);
  const trusted = TRUSTED_PUBLISHERS.has(ext.publisher);

  for (const filePath of files) {
    let stat: fs.Stats;
    try {
      stat = fs.statSync(filePath);
    } catch {
      continue;
    }
    if (stat.size > MAX_FILE_SIZE) continue;

    let content: string;
    try {
      content = fs.readFileSync(filePath, "utf-8");
    } catch {
      continue;
    }

    const lines = content.split("\n");

    for (const rule of RULES) {
      for (let i = 0; i < lines.length; i++) {
        if (rule.pattern.test(lines[i])) {
          findings.push({
            extensionId: ext.id,
            layer: "static",
            severity: trusted ? "info" : rule.severity,
            rule: rule.id,
            message: trusted
              ? `[trusted publisher] ${rule.message}`
              : rule.message,
            file: path.relative(ext.path, filePath),
            line: i + 1,
          });
          break;
        }
      }
    }
  }

  return findings;
}
