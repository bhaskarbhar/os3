import pytest
from os3 import suppress
from pathlib import Path

def test_suppression_add_and_check(mock_storage):
    """Test adding and checking suppressions."""
    ecosystem = "pypi"
    package = "vulnerable-pkg"
    reason = "False positive"
    
    # Not suppressed initially
    is_sup, res = suppress.is_suppressed(ecosystem, package)
    assert is_sup is False
    
    # Add suppression
    item = {
        "package": package,
        "ecosystem": ecosystem,
        "reason": reason,
        "suppress_all": True
    }
    suppress.save_suppression(item)
    
    # Check again
    is_sup, res = suppress.is_suppressed(ecosystem, package)
    assert is_sup is True
    assert res == reason

def test_suppression_cve_specific(mock_storage):
    """Test suppressing specific CVEs."""
    ecosystem = "npm"
    package = "pkg-with-vuln"
    cve_id = "CVE-2023-1234"
    
    item = {
        "package": package,
        "ecosystem": ecosystem,
        "reason": "Risk accepted",
        "cves": [cve_id],
        "suppress_all": False,
        "version_range": "1.2.3" # Specific version
    }
    suppress.save_suppression(item)
    
    # Package itself not suppressed for "latest" (default)
    is_sup, res = suppress.is_suppressed(ecosystem, package)
    assert is_sup is False
    
    # Specific CVE suppressed
    is_sup, res = suppress.is_suppressed(ecosystem, package, cve_id=cve_id)
    assert is_sup is True
    assert "Risk accepted" in res

def test_suppression_expiration(mock_storage):
    """Test that expired suppressions are ignored."""
    from datetime import datetime, timedelta
    
    ecosystem = "maven"
    package = "expired-pkg"
    past_date = (datetime.now() - timedelta(days=1)).isoformat()
    
    item = {
        "package": package,
        "ecosystem": ecosystem,
        "reason": "Should be expired",
        "suppress_all": True,
        "expires": past_date
    }
    suppress.save_suppression(item)
    
    is_sup, res = suppress.is_suppressed(ecosystem, package)
    assert is_sup is False

def test_suppression_remove(mock_storage):
    """Test removing suppressions."""
    package = "to-remove"
    suppress.save_suppression({
        "package": package,
        "ecosystem": "pypi",
        "reason": "Test",
        "suppress_all": True
    })
    
    assert suppress.is_suppressed("pypi", package)[0] is True
    
    suppress.remove_suppression(package)
    
    assert suppress.is_suppressed("pypi", package)[0] is False
