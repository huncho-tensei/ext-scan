import { aiScanExtension } from "../src/ai";
import { ExtensionInfo } from "../src/types";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

jest.mock("@anthropic-ai/sdk", () => {
  return jest.fn().mockImplementation(() => ({
    messages: {
      create: jest.fn().mockImplementation(async ({ messages }: any) => {
        const content = messages[0].content;

        if (content.includes("evil.backdoor")) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify([
                  {
                    severity: "critical",
                    rule: "data-exfiltration",
                    message: "Extension sends environment variables to external server",
                    file: "out/main.js",
                  },
                ]),
              },
            ],
          };
        }

        return {
          content: [{ type: "text", text: "[]" }],
        };
      }),
    },
  }));
});

function createTempExtension(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ext-scan-ai-test-"));
  for (const [name, content] of Object.entries(files)) {
    const filePath = path.join(dir, name);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, content);
  }
  return dir;
}

function fakeExt(
  id: string,
  dir: string,
  main = "./out/main.js"
): ExtensionInfo {
  return {
    id,
    name: id.split(".")[1],
    displayName: id.split(".")[1],
    publisher: id.split(".")[0],
    version: "1.0.0",
    description: "test extension",
    path: dir,
    editor: "vscode",
    main,
  };
}

describe("aiScanExtension", () => {
  const originalEnv = process.env.ANTHROPIC_API_KEY;

  beforeAll(() => {
    process.env.ANTHROPIC_API_KEY = "sk-test-fake-key";
  });

  afterAll(() => {
    if (originalEnv) {
      process.env.ANTHROPIC_API_KEY = originalEnv;
    } else {
      delete process.env.ANTHROPIC_API_KEY;
    }
  });

  it("returns findings for suspicious extension", async () => {
    const dir = createTempExtension({
      "package.json": JSON.stringify({ name: "backdoor", publisher: "evil" }),
      "out/main.js": "send(process.env)",
    });
    const findings = await aiScanExtension(fakeExt("evil.backdoor", dir));
    expect(findings.length).toBeGreaterThan(0);
    expect(findings[0].layer).toBe("ai");
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].extensionId).toBe("evil.backdoor");
  });

  it("returns empty findings for clean extension", async () => {
    const dir = createTempExtension({
      "package.json": JSON.stringify({ name: "clean", publisher: "legit" }),
      "out/main.js": "console.log('hello')",
    });
    const findings = await aiScanExtension(fakeExt("legit.clean", dir));
    expect(findings).toHaveLength(0);
  });

  it("throws without API key", async () => {
    const saved = process.env.ANTHROPIC_API_KEY;
    delete process.env.ANTHROPIC_API_KEY;

    const dir = createTempExtension({
      "package.json": JSON.stringify({ name: "test", publisher: "test" }),
    });

    await expect(aiScanExtension(fakeExt("test.test", dir))).rejects.toThrow(
      "ANTHROPIC_API_KEY"
    );

    process.env.ANTHROPIC_API_KEY = saved;
  });

  it("sets layer to ai on all findings", async () => {
    const dir = createTempExtension({
      "package.json": JSON.stringify({ name: "backdoor", publisher: "evil" }),
      "out/main.js": "evil()",
    });
    const findings = await aiScanExtension(fakeExt("evil.backdoor", dir));
    for (const f of findings) {
      expect(f.layer).toBe("ai");
    }
  });
});
