import Anthropic from "@anthropic-ai/sdk";
import * as fs from "fs";
import * as path from "path";
import { ExtensionInfo, Finding } from "./types";

const MAX_SOURCE_CHARS = 30_000;
const MODEL = "claude-haiku-4-5-20251001";

const SYSTEM_PROMPT = `You are a security auditor analyzing VS Code / Cursor editor extensions for malicious behavior. You receive the extension's package.json manifest and source code excerpts.

Analyze for:
1. Data exfiltration (sending files, env vars, keys, clipboard to external servers)
2. Credential harvesting (reading SSH keys, tokens, passwords, wallets)
3. Remote code execution (downloading and running payloads, reverse shells)
4. Persistence mechanisms (modifying startup files, installing background processes)
5. Supply chain indicators (obfuscated code, encoded payloads, suspicious dependencies)
6. Typosquatting (name mimics a popular extension)

Respond with a JSON array of findings. Each finding:
{"severity": "critical"|"high"|"medium", "rule": "short-id", "message": "one-line explanation", "file": "relative path if applicable"}

If the extension looks clean, return an empty array: []

Be conservative — only flag things with genuine security implications. Legitimate use of process.env, clipboard APIs, or network requests by well-known tools is not a finding.`;

function collectSource(ext: ExtensionInfo): string {
  const chunks: string[] = [];
  let totalChars = 0;

  const pkgPath = path.join(ext.path, "package.json");
  if (fs.existsSync(pkgPath)) {
    const pkg = fs.readFileSync(pkgPath, "utf-8");
    chunks.push(`=== package.json ===\n${pkg}\n`);
    totalChars += pkg.length;
  }

  const mainFile = ext.main
    ? path.join(ext.path, ext.main.replace(/^\.\//, "") + (ext.main.endsWith(".js") ? "" : ".js"))
    : null;

  if (mainFile && fs.existsSync(mainFile)) {
    const content = fs.readFileSync(mainFile, "utf-8");
    const excerpt = content.slice(0, MAX_SOURCE_CHARS - totalChars);
    chunks.push(`=== ${path.basename(mainFile)} (main entry) ===\n${excerpt}\n`);
    totalChars += excerpt.length;
  }

  const scanDirs = ["out", "dist", "src", "lib"];
  for (const dir of scanDirs) {
    if (totalChars >= MAX_SOURCE_CHARS) break;
    const dirPath = path.join(ext.path, dir);
    if (!fs.existsSync(dirPath)) continue;

    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dirPath, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (totalChars >= MAX_SOURCE_CHARS) break;
      if (!entry.isFile() || !entry.name.endsWith(".js")) continue;

      const filePath = path.join(dirPath, entry.name);
      try {
        const content = fs.readFileSync(filePath, "utf-8");
        const remaining = MAX_SOURCE_CHARS - totalChars;
        const excerpt = content.slice(0, remaining);
        chunks.push(`=== ${dir}/${entry.name} ===\n${excerpt}\n`);
        totalChars += excerpt.length;
      } catch {
        continue;
      }
    }
  }

  return chunks.join("\n");
}

export async function aiScanExtension(ext: ExtensionInfo): Promise<Finding[]> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error("ANTHROPIC_API_KEY not set — required for AI deep scan");
  }

  const client = new Anthropic({ apiKey });
  const source = collectSource(ext);

  const userPrompt = `Analyze this extension for security threats:

Extension: ${ext.id} v${ext.version}
Publisher: ${ext.publisher}
Description: ${ext.description}

${source}`;

  const response = await client.messages.create({
    model: MODEL,
    max_tokens: 1024,
    system: SYSTEM_PROMPT,
    messages: [{ role: "user", content: userPrompt }],
  });

  const text = response.content
    .filter((b): b is Anthropic.TextBlock => b.type === "text")
    .map((b) => b.text)
    .join("");

  const jsonMatch = text.match(/\[[\s\S]*\]/);
  if (!jsonMatch) return [];

  try {
    const parsed = JSON.parse(jsonMatch[0]);
    if (!Array.isArray(parsed)) return [];

    return parsed
      .filter((f: any) => f.severity && f.message)
      .map((f: any) => ({
        extensionId: ext.id,
        layer: "ai" as const,
        severity: f.severity,
        rule: f.rule || "ai-finding",
        message: f.message,
        file: f.file,
      }));
  } catch {
    return [];
  }
}
