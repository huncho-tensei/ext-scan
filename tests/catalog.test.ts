import { matchCatalog, loadCatalog } from "../src/catalog";
import { ExtensionInfo, CatalogEntry, Finding } from "../src/types";

const fakeExt = (id: string, version = "1.0.0"): ExtensionInfo => ({
  id,
  name: id.split(".")[1],
  displayName: id.split(".")[1],
  publisher: id.split(".")[0],
  version,
  description: "",
  path: `/fake/${id}`,
  editor: "vscode",
});

describe("loadCatalog", () => {
  it("loads the built-in catalog", () => {
    const catalog = loadCatalog();
    expect(catalog.length).toBeGreaterThan(0);
    expect(catalog[0].id).toBeTruthy();
    expect(catalog[0].severity).toBeTruthy();
  });
});

describe("matchCatalog", () => {
  const catalog: CatalogEntry[] = [
    {
      ecosystem: "vscode",
      id: "evil.malware",
      severity: "critical",
      description: "Known malware",
    },
    {
      ecosystem: "vscode",
      id: "ok.but-bad-version",
      versions: ["1.2.0", "1.2.1"],
      severity: "high",
      description: "Compromised versions only",
    },
  ];

  it("flags an exact match", () => {
    const findings = matchCatalog([fakeExt("evil.malware")], catalog);
    expect(findings).toHaveLength(1);
    expect(findings[0].severity).toBe("critical");
    expect(findings[0].layer).toBe("catalog");
  });

  it("ignores clean extensions", () => {
    const findings = matchCatalog([fakeExt("legit.extension")], catalog);
    expect(findings).toHaveLength(0);
  });

  it("flags version-specific match", () => {
    const findings = matchCatalog(
      [fakeExt("ok.but-bad-version", "1.2.0")],
      catalog
    );
    expect(findings).toHaveLength(1);
  });

  it("skips safe version of version-specific entry", () => {
    const findings = matchCatalog(
      [fakeExt("ok.but-bad-version", "2.0.0")],
      catalog
    );
    expect(findings).toHaveLength(0);
  });

  it("handles multiple extensions with mixed results", () => {
    const exts = [
      fakeExt("evil.malware"),
      fakeExt("legit.extension"),
      fakeExt("ok.but-bad-version", "1.2.1"),
    ];
    const findings = matchCatalog(exts, catalog);
    expect(findings).toHaveLength(2);
  });
});
