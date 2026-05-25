import { discoverExtensions, getExtensionDirs } from "../src/discover";
import { ExtensionInfo } from "../src/types";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";

describe("getExtensionDirs", () => {
  it("returns vscode dir when it exists", () => {
    const dirs = getExtensionDirs();
    const vscodeDir = dirs.find((d) => d.editor === "vscode");
    expect(vscodeDir).toBeDefined();
    expect(vscodeDir!.path).toContain(".vscode/extensions");
  });

  it("each returned dir actually exists on disk", () => {
    const dirs = getExtensionDirs();
    for (const dir of dirs) {
      expect(fs.existsSync(dir.path)).toBe(true);
    }
  });
});

describe("discoverExtensions", () => {
  it("finds installed vscode extensions", async () => {
    const extensions = await discoverExtensions();
    expect(extensions.length).toBeGreaterThan(0);
  });

  it("returns well-formed ExtensionInfo for each extension", async () => {
    const extensions = await discoverExtensions();
    for (const ext of extensions) {
      expect(ext.id).toMatch(/^.+\..+$/);
      expect(ext.publisher).toBeTruthy();
      expect(ext.name).toBeTruthy();
      expect(ext.version).toBeTruthy();
      expect(ext.path).toBeTruthy();
      expect(["vscode", "cursor"]).toContain(ext.editor);
    }
  });

  it("finds ms-python.python if installed", async () => {
    const extensions = await discoverExtensions();
    const python = extensions.find((e) => e.id === "ms-python.python");
    if (python) {
      expect(python.publisher).toBe("ms-python");
      expect(python.name).toBe("python");
      expect(python.editor).toBe("vscode");
    }
  });

  it("skips directories without package.json", async () => {
    const extensions = await discoverExtensions();
    for (const ext of extensions) {
      const pkgPath = path.join(ext.path, "package.json");
      expect(fs.existsSync(pkgPath)).toBe(true);
    }
  });
});
