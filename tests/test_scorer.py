import pytest
from unittest.mock import MagicMock
import responses
import json
from os3.scorer import ScoringEngine

def test_score_package_pypi_healthy(mock_responses, sample_pypi_data):
    """Test scoring a healthy PyPI package."""
    engine = ScoringEngine()
    package = "requests"
    
    # Mock PyPI API
    mock_responses.add(
        responses.GET,
        f"https://pypi.org/pypi/{package}/json",
        json=sample_pypi_data,
        status=200
    )
    
    # Mock OSV API
    mock_responses.add(
        responses.POST,
        "https://api.osv.dev/v1/query",
        json={"vulns": []},
        status=200
    )
    
    # Mock deps.dev
    mock_responses.add(
        responses.GET,
        "https://api.deps.dev/v1alpha/systems/pypi/packages/requests",
        json={},
        status=200
    )
    
    result = engine.score_package(ecosystem="pypi", name=package)
    
    assert result["score"] >= 80
    assert result["risk_level"] == "LOW"
    assert any("vulnerabilities" in exp.lower() for exp in result["explanations"])
    assert len(result["vulns"]) == 0

def test_score_package_vulnerable(mock_responses, sample_pypi_data, sample_osv_data):
    """Test scoring a package with vulnerabilities."""
    engine = ScoringEngine()
    package = "vulnerable-pkg"
    
    mock_responses.add(
        responses.GET,
        f"https://pypi.org/pypi/{package}/json",
        json=sample_pypi_data,
        status=200
    )
    
    mock_responses.add(
        responses.POST,
        "https://api.osv.dev/v1/query",
        json=sample_osv_data,
        status=200
    )
    
    result = engine.score_package(ecosystem="pypi", name=package)
    
    assert result["score"] < 70
    assert result["risk_level"] in ["MEDIUM", "HIGH"]
    assert len(result["vulns"]) > 0

def test_score_package_not_found(mock_responses):
    """Test scoring a package that doesn't exist."""
    engine = ScoringEngine()
    package = "does-not-exist-at-all-12345"
    
    mock_responses.add(
        responses.GET,
        f"https://pypi.org/pypi/{package}/json",
        status=404
    )
    
    mock_responses.add(
        responses.POST,
        "https://api.osv.dev/v1/query",
        json={},
        status=200
    )
    
    result = engine.score_package(ecosystem="pypi", name=package)
    
    assert result["score"] <= 20
    assert result["risk_level"] == "HIGH"
    assert "not found" in result["explanations"][0].lower()

def test_score_builtin_module(mocker):
    """Test scoring a Python standard library module."""
    engine = ScoringEngine()
    
    # Mock importlib.util.find_spec
    mock_find_spec = mocker.patch("importlib.util.find_spec")
    mock_spec = MagicMock()
    mock_spec.origin = "/usr/lib/python3.10/os.py"
    mock_find_spec.return_value = mock_spec
    
    mocker.patch("sys.base_prefix", "/usr/lib/python3.10")
    
    result = engine.score_package(ecosystem="pypi", name="json")
    
    assert result["score"] == 100
    assert result["source"] == "builtin"

def test_score_dangerous_builtin():
    """Test scoring a dangerous Python standard library module."""
    engine = ScoringEngine()
    
    # 'pickle' is dangerous
    result = engine.score_package(ecosystem="pypi", name="pickle")
    
    assert result["score"] < 50
    assert result["risk_level"] == "HIGH"
    assert "dangerous built-in" in result["explanations"][0].lower()
