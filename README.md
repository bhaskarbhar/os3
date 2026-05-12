# OS³ (Open-Source Security Score)

**OS³** is a high-performance, intent-time security scoring engine designed to stop malicious and vulnerable open-source packages *before* they enter your supply chain. It provides data-saturated security audits for **PyPI, NPM, and Maven** ecosystems.

Built for the **Advanced Agentic Coding** era, OS³ integrates directly into your CLI and IDE to provide real-time risk assessments, smart alternatives, and developer-centric suppression.

---

## 📚 Documentation

Detailed documentation for OS³ can be found below:

- **[Core Features](docs/features.md)**: Explore the security signals and scoring logic.
- **[CLI Installation & Usage](docs/installation.md)**: How to install and use the `os3` command-line tool.
- **[VS Code Extension](docs/vscode_extension.md)**: Setup and features for the VS Code integration.
- **[Configuration](docs/configuration.md)**: Managing cache, suppressions, and settings.
- **[Development](docs/development.md)**: Guidelines for contributing and running tests.

---

## Tech Stack

- **Backend**: Python, Typer (CLI), Rich (TUI), SQLite (Cache), Fernet (Encryption).
- **Frontend (IDE)**: TypeScript, VS Code Extension API.
- **APIs**: OSV.dev, PyPI JSON API, NPM Registry/Downloads, Maven Central Solr API, deps.dev.

---

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

---
*Built with ❤️ by the OS³ Team.*

