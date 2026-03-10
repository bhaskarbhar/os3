# OS³ Security for VS Code

Bring the power of **Open-Source Security Score (OS³)** directly into your editor. Stop malicious and vulnerable packages at **Intent-Time**.

## 🛡️ Features

- **Inline Security Scoring**: Hover over any import statement in Python, JS/TS, or Maven to see real-time safety scores.
- **Deep Explanations**: Understand *why* a package is risky (CVEs, Maintainer Activity, Transitive Depth).
- **Safer Alternatives**: Get data-driven suggestions to switch to better-maintained, more secure libraries.
- **Quick Fixes**: Suppress known false positives or automatically run scans.
- **Artifact Scanning**: Automatically scans `package.json`, `requirements.txt`, and `pom.xml` on save.

## 🚀 Getting Started

### 1. Install OS³ CLI
Ensure you have the OS³ CLI installed on your system:
```bash
py -m os3 --help
```

### 2. Build the Extension
```bash
cd packages/vscode-os3
npm install
npm run build
```

### 3. Install from VSIX
You can package the extension and install it manually:
```bash
npx vsce package
```
Then, in VS Code, go to Extensions → `...` → `Install from VSIX...`.

## ⚙️ Configuration

- `os3.warnIfScoreBelow`: Score threshold for warnings (default: 70).
- `os3.errorIfScoreBelow`: Score threshold for errors (default: 40).
- `os3.cliPath`: Path to your `os3` executable if not in PATH.

---
*Built for the Deepmind Advanced Agentic Coding project.*
