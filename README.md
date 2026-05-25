# ext-scan

[![CI](https://github.com/huncho-tensei/ext-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/huncho-tensei/ext-scan/actions/workflows/ci.yml)

Local security scanner for VS Code and Cursor extensions. Checks what's already installed on your machine against known-compromised packages, suspicious code patterns, and optionally runs an AI deep analysis.

## Why

VS Code and Cursor extensions run with full access to your terminal, filesystem, environment variables, and clipboard. There's no sandboxing. In 2026 alone: 73 fake extensions delivered GlassWorm malware, a poisoned extension led to GitHub's internal repos being stolen, and a Cursor extension drained $500K from a developer's crypto wallet.

Existing tools scan the marketplace or scan your code. Nothing scans the extensions themselves on your machine. ext-scan fills that gap.

## Install

```bash
npm install -g ext-scan
```

Or run without installing:

```bash
npx ext-scan
```

## Usage

```bash
# Standard scan (catalog + static analysis)
ext-scan

# Clean output — hide trusted publisher noise
ext-scan --no-info

# AI deep scan on flagged extensions (needs API key)
export ANTHROPIC_API_KEY=sk-ant-...
ext-scan --deep

# JSON output for piping to other tools
ext-scan --json

# Catalog check only (fastest)
ext-scan --catalog-only

# Verbose progress
ext-scan --verbose
```

## How it works

Three layers, run in order:

### Layer 1 — Catalog matching

Checks installed extensions against a maintained list of known-compromised packages. Exact ID + version matching. Zero false positives.

### Layer 2 — Static analysis

Scans extension source code for 8 suspicious patterns:

| Rule | Severity | What it catches |
|------|----------|----------------|
| `shell-exec` | high | Shell command execution via child process APIs |
| `eval-usage` | high | Runtime code execution via eval |
| `network-ip` | high | HTTP requests to raw IP addresses |
| `sensitive-file-read` | high | References to SSH keys, AWS credentials, env files |
| `crypto-wallet` | high | Hardcoded cryptocurrency wallet addresses |
| `base64-decode` | medium | Hardcoded base64 strings being decoded |
| `env-access` | medium | Environment variable reads |
| `clipboard-read` | medium | Clipboard API access |

Extensions from trusted publishers (Microsoft, Red Hat, etc.) are still scanned but findings are downgraded to `info` severity.

### Layer 3 — AI deep scan

Sends extension manifest and source excerpts to Claude for behavioral analysis. Catches things regex can't: obfuscated code, suspicious capability combinations, typosquatting, persistence mechanisms.

Only runs on untrusted extensions that already have static findings. Requires `ANTHROPIC_API_KEY`.

## Example output

```
ext-scan v0.1.0
Scanned 16 extensions at 2026-05-26T00:03:28.876Z

cweijan.vscode-office (12 findings)
  HIGH     [static/crypto-wallet] Contains cryptocurrency wallet address
  HIGH     [static/eval-usage] Uses eval — can execute arbitrary code
  HIGH     [ai/obfuscated-minified-code] Extension main entry point is heavily minified
  HIGH     [ai/suspicious-activation-event] Activates on every VS Code startup
  MEDIUM   [static/env-access] Reads environment variables
  MEDIUM   [ai/remote-code-execution-capability] Includes puppeteer-core dependency
  ...

tomoki1207.pdf (2 findings)
  HIGH     [static/eval-usage] Uses eval — pdf.js sandbox (likely benign)

Total: 6 high, 8 medium
```

## Supported editors

- VS Code (`~/.vscode/extensions/`)
- Cursor (`~/.cursor/extensions/`)

macOS and Linux. Windows support not yet implemented.

## Extending the catalog

Add entries to `catalog/known-bad.json`:

```json
{
  "ecosystem": "vscode",
  "id": "publisher.extension-name",
  "versions": ["1.2.0"],
  "severity": "critical",
  "description": "What this extension does that's malicious",
  "reference": "https://link-to-advisory"
}
```

Omit `versions` to flag all versions of an extension.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | No high or critical findings |
| 1 | High-severity findings present |
| 2 | Critical-severity findings present |

## License

Apache-2.0
