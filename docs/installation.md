# CLI Setup & Installation

Follow these steps to set up the OS³ CLI on your local machine.

## 1. Prerequisites
- Python 3.9+
- [Optional] Maven (for Java dependency depth calculation)
- [Optional] Node.js (for NPM ecosystem support)

## 2. Installation
Clone the repository and install the dependencies:
```bash
git clone https://github.com/bhaskarbhar/os3.git
cd os3
py -m pip install -e .
```

## 3. CLI Commands
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
