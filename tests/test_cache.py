import pytest
from os3 import cache

def test_cache_set_get(mock_storage):
    """Test basic cache storage and retrieval."""
    ecosystem = "pypi"
    name = "test-pkg"
    version = "1.0.0"
    data = {"score": 85, "risk_level": "LOW"}
    
    # Cache the data
    cache.cache_score(ecosystem, name, version, data)
    
    # Retrieve it
    retrieved = cache.get_cached_score(ecosystem, name, version)
    assert retrieved == data

def test_cache_missing_entry(mock_storage):
    """Test retrieving a non-existent entry."""
    assert cache.get_cached_score("npm", "non-existent", "1.0.0") is None

def test_cache_stale_data(mock_storage, monkeypatch):
    """Test that stale data is not returned unless requested."""
    from datetime import datetime, timedelta
    
    ecosystem = "pypi"
    name = "stale-pkg"
    version = "1.0.0"
    data = {"score": 50}
    
    cache.cache_score(ecosystem, name, version, data)
    
    # Mock time to be 10 days in the future
    future_time = (datetime.now() + timedelta(days=10)).isoformat()
    
    # We need to manually update the timestamp in the DB because cache_score uses datetime.now()
    conn = cache._get_db()
    conn.execute("UPDATE package_scores SET timestamp = ?", ( (datetime.now() - timedelta(days=10)).isoformat(), ))
    conn.commit()
    conn.close()
    
    # Should be None (stale)
    assert cache.get_cached_score(ecosystem, name, version) is None
    
    # Should be returned if allow_stale=True
    assert cache.get_cached_score(ecosystem, name, version, allow_stale=True) == data

def test_clear_cache(mock_storage):
    """Test clearing the cache."""
    cache.cache_score("pypi", "pkg1", "1.0.0", {"s": 1})
    cache.cache_deps_dev("pypi", "pkg1", {"d": 1})
    
    assert cache.get_cached_score("pypi", "pkg1", "1.0.0") is not None
    
    cache.clear_all_cache()
    
    assert cache.get_cached_score("pypi", "pkg1", "1.0.0") is None
    assert cache.get_cached_deps_dev("pypi", "pkg1") is None
