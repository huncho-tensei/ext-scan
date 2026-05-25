import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { ExtensionInfo } from "./types";

interface EditorDir {
  editor: "vscode" | "cursor";
  path: string;
}

const EDITOR_PATHS: Record<string, Array<{ editor: "vscode" | "cursor"; relPath: string }>> = {
  darwin: [
    { editor: "vscode", relPath: ".vscode/extensions" },
    { editor: "cursor", relPath: ".cursor/extensions" },
  ],
  linux: [
    { editor: "vscode", relPath: ".vscode/extensions" },
    { editor: "cursor", relPath: ".cursor/extensions" },
  ],
};

export function getExtensionDirs(): EditorDir[] {
  const home = os.homedir();
  const platform = process.platform;
  const candidates = EDITOR_PATHS[platform] || EDITOR_PATHS["linux"];

  return candidates
    .map((c) => ({ editor: c.editor, path: path.join(home, c.relPath) }))
    .filter((d) => fs.existsSync(d.path));
}

export async function discoverExtensions(): Promise<ExtensionInfo[]> {
  const dirs = getExtensionDirs();
  const extensions: ExtensionInfo[] = [];

  for (const dir of dirs) {
    const entries = fs.readdirSync(dir.path, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;

      const extPath = path.join(dir.path, entry.name);
      const pkgPath = path.join(extPath, "package.json");

      if (!fs.existsSync(pkgPath)) continue;

      try {
        const raw = fs.readFileSync(pkgPath, "utf-8");
        const pkg = JSON.parse(raw);

        const publisher = pkg.publisher || "";
        const name = pkg.name || "";

        extensions.push({
          id: `${publisher}.${name}`,
          name,
          displayName: pkg.displayName || name,
          publisher,
          version: pkg.version || "unknown",
          description: pkg.description || "",
          path: extPath,
          editor: dir.editor,
          main: pkg.main,
        });
      } catch {
        // malformed package.json — skip
      }
    }
  }

  return extensions;
}
