import pytest
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock
import responses

@pytest.fixture(autouse=True)
def mock_storage(monkeypatch):
    """Mock storage paths to avoid affecting user data."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        
        # Mock paths in os3.cache
        monkeypatch.setattr("os3.cache.DB_PATH", str(tmp_path / "cache.db"))
        
        # Mock paths in os3.suppress
        monkeypatch.setattr("os3.suppress.GLOBAL_SUPPRESS_PATH", tmp_path / "global_suppress.toml")
        monkeypatch.setattr("os3.suppress.LOCAL_SUPPRESS_PATH", tmp_path / "local_suppress.toml")
        
        # Mock paths in os3.config if it exists
        try:
            monkeypatch.setattr("os3.config.CONFIG_PATH", tmp_path / "config.json")
        except (ImportError, AttributeError):
            pass
            
        yield tmp_path

@pytest.fixture
def mock_responses():
    """Fixture to mock HTTP responses."""
    with responses.RequestsMock() as rsps:
        yield rsps

@pytest.fixture
def sample_pypi_data():
    """Sample PyPI JSON API response."""
    return {
        "info": {
            "name": "requests",
            "version": "2.31.0",
            "summary": "Python HTTP for Humans.",
            "author": "Kenneth Reitz",
            "license": "Apache 2.0",
            "classifiers": [
                "License :: OSI Approved :: Apache Software License",
            ],
            "requires_dist": ["urllib3", "certifi"],
            "project_urls": {
                "Homepage": "https://github.com/psf/requests"
            }
        },
        "releases": {
            "2.31.0": [
                {"upload_time": "2026-05-01T12:00:00"}
            ]
        }
    }

@pytest.fixture
def sample_osv_data():
    """Sample OSV API response."""
    return {
        "vulns": [
            {
                "id": "GHSA-j8q9-p94v-78wf",
                "summary": "Sample vulnerability",
                "severity": [{"type": "CVSS_V3", "score": "7.5"}]
            }
        ]
    }
