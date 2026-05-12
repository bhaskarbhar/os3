# Core Features

**OS³** provides a comprehensive set of security signals and tools to protect your supply chain.

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
