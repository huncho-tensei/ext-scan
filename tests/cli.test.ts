import { execFileSync } from "child_process";
import * as path from "path";

const CLI = path.join(__dirname, "..", "src", "index.ts");

function run(args: string[] = []): { stdout: string; exitCode: number } {
  try {
    const stdout = execFileSync("npx", ["ts-node", CLI, ...args], {
      encoding: "utf-8",
      timeout: 30_000,
      env: { ...process.env, ANTHROPIC_API_KEY: undefined },
    });
    return { stdout, exitCode: 0 };
  } catch (err: any) {
    return { stdout: err.stdout || "", exitCode: err.status || 1 };
  }
}

describe("CLI integration", () => {
  it("--help exits 0 and shows usage", () => {
    const { stdout, exitCode } = run(["--help"]);
    expect(exitCode).toBe(0);
    expect(stdout).toContain("ext-scan");
    expect(stdout).toContain("--json");
    expect(stdout).toContain("--deep");
    expect(stdout).toContain("--no-info");
  });

  it("--json outputs valid JSON", () => {
    const { stdout } = run(["--json", "--catalog-only"]);
    const parsed = JSON.parse(stdout);
    expect(parsed).toHaveProperty("extensions");
    expect(parsed).toHaveProperty("findings");
    expect(parsed).toHaveProperty("scannedAt");
    expect(Array.isArray(parsed.extensions)).toBe(true);
    expect(Array.isArray(parsed.findings)).toBe(true);
  });

  it("--catalog-only skips static analysis", () => {
    const { stdout } = run(["--json", "--catalog-only"]);
    const parsed = JSON.parse(stdout);
    const staticFindings = parsed.findings.filter(
      (f: any) => f.layer === "static"
    );
    expect(staticFindings).toHaveLength(0);
  });

  it("--deep without API key exits with error", () => {
    const { stdout, exitCode } = run(["--deep"]);
    expect(exitCode).not.toBe(0);
  });

  it("report includes version header", () => {
    const { stdout } = run(["--catalog-only"]);
    expect(stdout).toContain("ext-scan");
    expect(stdout).toContain("v0.1.0");
  });
});
