import pytest
from typer.testing import CliRunner
from os3.cli import app
import json

runner = CliRunner()

def test_cli_version():
    """Test the --version flag."""
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "Version" in result.stdout

def test_cli_score_basic(mock_responses, sample_pypi_data):
    """Test the score command."""
    package = "requests"
    
    # Mock APIs
    mock_responses.add(
        responses.GET,
        f"https://pypi.org/pypi/{package}/json",
        json=sample_pypi_data,
        status=200
    )
    mock_responses.add(responses.POST, "https://api.osv.dev/v1/query", json={}, status=200)
    
    result = runner.invoke(app, ["score", package])
    assert result.exit_code == 0
    assert "Score Report" in result.stdout
    assert "requests" in result.stdout

def test_cli_score_json(mock_responses, sample_pypi_data):
    """Test the score command with --json output."""
    package = "requests"
    
    mock_responses.add(
        responses.GET,
        f"https://pypi.org/pypi/{package}/json",
        json=sample_pypi_data,
        status=200
    )
    mock_responses.add(responses.POST, "https://api.osv.dev/v1/query", json={}, status=200)
    
    result = runner.invoke(app, ["score", package, "--json"])
    assert result.exit_code == 0
    
    # Verify it's valid JSON
    data = json.loads(result.stdout)
    assert "score" in data
    assert data["ecosystem"] == "pypi"

def test_cli_suppress_add_list(mock_storage):
    """Test adding and listing suppressions via CLI."""
    package = "test-pkg"
    
    # Add
    add_result = runner.invoke(app, ["suppress", "add", package, "--reason", "Test reason"])
    assert add_result.exit_code == 0
    assert "Added suppression" in add_result.stdout
    
    # List
    list_result = runner.invoke(app, ["suppress", "list"])
    assert list_result.exit_code == 0
    assert package in list_result.stdout
    assert "Test reason" in list_result.stdout

def test_cli_scan_missing_file():
    """Test scanning a non-existent file."""
    result = runner.invoke(app, ["scan", "non_existent_file.txt"])
    assert result.exit_code == 1
    assert "File not found" in result.stdout

import responses # Need to import for mock_responses to work with decorator if needed, but fixture handles it.
