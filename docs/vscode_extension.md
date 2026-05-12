# VS Code Extension Setup

The OS³ extension provides **intent-time security** by analyzing imports as you type.

## 1. Build the Extension
```bash
cd packages/vscode-os3
npm install
npm run build
```

## 2. Install
Package the extension as a VSIX file:
```bash
npx vsce package
```
Then, install the generated `.vsix` file in VS Code via **Extensions -> ... -> Install from VSIX**.

## 3. Features in Editor
- **Hovers**: Hover over an `import` or `require` to see the OS³ score and audit audit journal.
- **Diagnostics**: Packages with scores below your threshold (default 70) appear as warnings in the **Problems** tab.
- **Quick Fixes**: Click the lightbulb to instantly suppress a package or view alternatives.
