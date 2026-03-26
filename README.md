# OS³ (Open-Source Security Score) 🛡️

**OS³** is a high-performance, intent-time security scoring engine designed to stop malicious and vulnerable open-source packages *before* they enter your supply chain. It provides data-saturated security audits for **PyPI, NPM, and Maven** ecosystems.

Built for the **Advanced Agentic Coding** era, OS³ integrates directly into your CLI and IDE to provide real-time risk assessments, smart alternatives, and developer-centric suppression.

---

## ✨ Core Features

- **Multi-Ecosystem Scoring**: Unified security signals for Python (PyPI), JavaScript (NPM), and Java (Maven).
- **Composite Health Signals**:
    - **CVE Detection**: Real-time vulnerability lookup via OSV.dev.
    - **Maintainer Activity**: Analysis of release frequency and maintenance status.
    - **Dependency Depth**: Analysis of transitive risk (depth calculation via `pipdeptree` or `mvn dependency:tree`).
    - **Popularity Anomalies**: Detection of suspicious download spikes or activity drops.
    - **License Compliance**: Automatic SPDX validation against OSI-approved licenses.
- **Smart Alternatives**: Data-driven suggestions for safer, better-maintained libraries (e.g., suggesting `httpx` over `requests` or `Logback` over vulnerable `Log4j`).
- **Developer Suppression**: Explicitly override risks with reasons and expiration dates via global or project-level `suppress.toml`.
- **VS Code Extension**: Intent-time security with inline hovers, diagnostic warnings, and quick-fixes.

---

## 🚀 CLI Setup & Installation

### 1. Prerequisites
- Python 3.9+
- [Optional] Maven (for Java dependency depth calculation)
- [Optional] Node.js (for NPM ecosystem support)

### 2. Installation
Clone the repository and install the dependencies:
```bash
git clone https://github.com/bhaskarbhar/os3.git
cd os3
py -m pip install -e .
```

### 3. CLI Commands
- **Score a package**:
  ```bash
  os3 score flask --ecosystem pypi
  os3 score requests --json  # Deep JSON output for automation
  ```
- **Scan a project artifact**:
  ```bash
  os3 scan requirements.txt
  os3 scan package.json
  os3 scan pom.xml
  ```
- **Sync vulnerability cache**:
  ```bash
  os3 sync --full
  ```
- **Manage suppressions**:
  ```bash
  os3 suppress add requests --reason "Internal review complete" --all
  os3 suppress list
  ```

---

## 💻 VS Code Extension Setup

The OS³ extension provides **intent-time security** by analyzing imports as you type.

### 1. Build the Extension
```bash
cd packages/vscode-os3
npm install
npm run build
```

### 2. Install
Package the extension as a VSIX file:
```bash
npx vsce package
```
Then, install the generated `.vsix` file in VS Code via **Extensions -> ... -> Install from VSIX**.

### 3. Features in Editor
- **Hovers**: Hover over an `import` or `require` to see the OS³ score and audit audit journal.
- **Diagnostics**: Packages with scores below your threshold (default 70) appear as warnings in the **Problems** tab.
- **Quick Fixes**: Click the lightbulb to instantly suppress a package or view alternatives.

---

## ⚙️ Configuration

OS³ stores its configuration and encrypted cache in your user home directory:
- **Cache**: `~/.cache/os3/cache.db` (SQLite, encrypted via Fernet)
- **Global Suppressions**: `~/.os3/suppress.toml`
- **Settings**: Adjust thresholds in VS Code via `os3.warnIfScoreBelow`.

---

## 🛠️ Tech Stack

- **Backend**: Python, Typer (CLI), Rich (TUI), SQLite (Cache), Fernet (Encryption).
- **Frontend (IDE)**: TypeScript, VS Code Extension API.
- **APIs**: OSV.dev, PyPI JSON API, NPM Registry/Downloads, Maven Central Solr API, deps.dev.

---

## 📄 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---
*Built with ❤️ by the OS³ Team.*
