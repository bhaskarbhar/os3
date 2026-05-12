# Development & Testing

OS³ uses `pytest` for testing. To set up the development environment and run tests:

## 1. Install Dependencies (including testing tools)
```bash
py -m pip install -r requirements.txt
py -m pip install -e .
```

## 2. Run Tests
```bash
pytest
```

## 3. Generate Coverage Report
```bash
pytest --cov=src/os3 --cov-report=html
```
The report will be available in `htmlcov/index.html`.
