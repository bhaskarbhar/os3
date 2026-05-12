# Contributing to OS³

Thank you for your interest in contributing to OS³! We welcome contributions from the community to help make open-source software more secure for everyone.

## Table of Contents
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Testing Guidelines](#testing-guidelines)
- [Style Guide](#style-guide)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)

## How Can I Contribute?
You can contribute in many ways:
- Reporting bugs
- Suggesting new features
- Improving documentation
- Submitting pull requests for code changes
- Adding support for new ecosystems

## Development Setup

OS³ is a multi-language project consisting of a Python backend/CLI and a TypeScript VS Code extension.

### Backend (Python)
1. Clone the repository:
   ```bash
   git clone https://github.com/bhaskarbhar/os3.git
   cd os3
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install dependencies in editable mode:
   ```bash
   pip install -r requirements.txt
   pip install -e .
   ```

### VS Code Extension (TypeScript)
1. Navigate to the extension directory:
   ```bash
   cd packages/vscode-os3
   ```
2. Install dependencies:
   ```bash
   npm install
   ```
3. Build the extension:
   ```bash
   npm run build
   ```

## Testing Guidelines

We use `pytest` for testing the Python backend. All new features and bug fixes should include appropriate tests.

1. Install testing dependencies:
   ```bash
   pip install -r requirements-test.txt
   ```
2. Run the tests:
   ```bash
   pytest
   ```
3. Check code coverage:
   ```bash
   pytest --cov=src/os3 --cov-report=term-missing
   ```

## Style Guide

### Python
- Follow PEP 8 style guidelines.
- Use meaningful variable and function names.
- Include docstrings for all public modules, classes, and functions.
- We use `rich` for CLI output formatting; maintain consistent styling using the existing theme.

### TypeScript
- Use `npm run lint` if configured (or follow existing project patterns).
- Use clear, descriptive names.
- Maintain the asynchronous nature of VS Code extension operations where necessary.

## Pull Request Process

1. Fork the repository and create your branch from `main`.
2. Ensure the test suite passes locally.
3. Update the documentation if you are adding new features or changing existing behavior.
4. Ensure your code follows the project's style guide.
5. Submit a pull request with a clear description of the changes and the problem they solve.

## Reporting Issues

If you find a bug or have a feature request, please open an issue on GitHub.
- Use a clear and descriptive title.
- Describe the steps to reproduce the bug.
- Include information about your environment (OS, Python version, etc.).
- If possible, include screenshots or logs.

---
*Thank you for helping us build a more secure open-source ecosystem!*
