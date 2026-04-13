import sqlite3
import json
import os
from datetime import datetime, timedelta
import appdirs

# Database path
DB_PATH = os.path.join(appdirs.user_data_dir("os3", "os3"), "cache.db")

def _get_db():
    """Get database connection with proper setup."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS package_scores (
            ecosystem TEXT,
            name TEXT,
            version TEXT,
            data TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (ecosystem, name, version)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS deps_dev_data (
            ecosystem TEXT,
            package_name TEXT,
            data TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (ecosystem, package_name)
        )
    """)
    conn.commit()
    return conn

def get_cached_score(ecosystem: str, name: str, version: str | None, allow_stale: bool = False) -> dict | None:
    """Get cached package score data."""
    if version is None:
        version = "latest"

    conn = _get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT data, timestamp FROM package_scores
            WHERE ecosystem = ? AND name = ? AND version = ?
        """, (ecosystem, name, version))

        row = cursor.fetchone()
        if row:
            data_str, timestamp_str = row
            # Check if data is stale (older than 7 days unless allow_stale=True)
            if not allow_stale:
                timestamp = datetime.fromisoformat(timestamp_str)
                if datetime.now() - timestamp > timedelta(days=7):
                    return None
            return json.loads(data_str)
    finally:
        conn.close()
    return None

def cache_score(ecosystem: str, name: str, version: str, data: dict):
    """Cache package score data."""
    conn = _get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO package_scores (ecosystem, name, version, data, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (ecosystem, name, version, json.dumps(data), datetime.now().isoformat()))
        conn.commit()
    finally:
        conn.close()

def get_cached_deps_dev(ecosystem: str, package_name: str) -> dict | None:
    """Get cached deps.dev data."""
    conn = _get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT data, timestamp FROM deps_dev_data
            WHERE ecosystem = ? AND package_name = ?
        """, (ecosystem, package_name))

        row = cursor.fetchone()
        if row:
            data_str, timestamp_str = row
            # Check if data is stale (older than 7 days)
            timestamp = datetime.fromisoformat(timestamp_str)
            if datetime.now() - timestamp > timedelta(days=7):
                return None
            return json.loads(data_str)
    finally:
        conn.close()
    return None

def cache_deps_dev(ecosystem: str, package_name: str, data: dict):
    """Cache deps.dev data."""
    conn = _get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO deps_dev_data (ecosystem, package_name, data, timestamp)
            VALUES (?, ?, ?, ?)
        """, (ecosystem, package_name, json.dumps(data), datetime.now().isoformat()))
        conn.commit()
    finally:
        conn.close()

def get_stale_packages(days: int = 7) -> list[tuple[str, str, str]]:
    """Get packages that haven't been updated in the specified number of days."""
    conn = _get_db()
    try:
        cursor = conn.cursor()
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        cursor.execute("""
            SELECT ecosystem, name, version FROM package_scores
            WHERE timestamp < ?
        """, (cutoff,))

        return [(eco, name, ver) for eco, name, ver in cursor.fetchall()]
    finally:
        conn.close()

def get_cache_stats() -> dict:
    """Get cache statistics."""
    conn = _get_db()
    try:
        cursor = conn.cursor()

        # Total packages
        cursor.execute("SELECT COUNT(*) FROM package_scores")
        total_packages = cursor.fetchone()[0]

        # Ecosystem breakdown
        cursor.execute("""
            SELECT ecosystem, COUNT(*) FROM package_scores
            GROUP BY ecosystem
        """)
        ecosystems = dict(cursor.fetchall())

        # Last sync (most recent timestamp)
        cursor.execute("SELECT MAX(timestamp) FROM package_scores")
        last_sync_row = cursor.fetchone()
        last_sync = last_sync_row[0] if last_sync_row[0] else "Never"

        return {
            "total_packages": total_packages,
            "ecosystems": ecosystems,
            "last_sync": last_sync
        }
    finally:
        conn.close()

def clear_all_cache():
    """Clear all cached data."""
    conn = _get_db()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM package_scores")
        cursor.execute("DELETE FROM deps_dev_data")
        conn.commit()
    finally:
        conn.close()