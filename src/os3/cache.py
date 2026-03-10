import json
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import appdirs

# Configuration
APP_NAME = "os3"
CACHE_DIR = Path(appdirs.user_cache_dir(APP_NAME))
DB_PATH = CACHE_DIR / "cache.db"
KEY_PATH = CACHE_DIR / "key.bin"

# Ensure cache directory exists
CACHE_DIR.mkdir(parents=True, exist_ok=True)

def get_crypto_key() -> bytes:
    """Get or generate a Fernet encryption key."""
    if KEY_PATH.exists():
        return KEY_PATH.read_bytes()
    else:
        key = Fernet.generate_key()
        KEY_PATH.write_bytes(key)
        return key

def encrypt(data: str) -> bytes:
    """Encrypt a string into bytes."""
    f = Fernet(get_crypto_key())
    return f.encrypt(data.encode())

def decrypt(ciphertext: bytes) -> str:
    """Decrypt ciphertext bytes back into a string."""
    f = Fernet(get_crypto_key())
    return f.decrypt(ciphertext).decode()

def init_db():
    """Initialize the SQLite database and create the 'packages' and 'deps_dev_cache' tables."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS packages (
                ecosystem TEXT,
                name TEXT,
                version TEXT,
                score INTEGER,
                risk_level TEXT,
                explanations TEXT,
                alternatives TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                raw_metadata BLOB,
                dep_depth INTEGER DEFAULT 0,
                popularity_anomaly FLOAT DEFAULT 0.0,
                license_spdx TEXT,
                provenance_score INTEGER DEFAULT 0,
                PRIMARY KEY (ecosystem, name, version)
            )
        """)
        
        # Migration: Add columns if they don't exist
        cursor.execute("PRAGMA table_info(packages)")
        columns = [info[1] for info in cursor.fetchall()]
        if "dep_depth" not in columns:
            cursor.execute("ALTER TABLE packages ADD COLUMN dep_depth INTEGER DEFAULT 0")
        if "popularity_anomaly" not in columns:
            cursor.execute("ALTER TABLE packages ADD COLUMN popularity_anomaly FLOAT DEFAULT 0.0")
        if "license_spdx" not in columns:
            cursor.execute("ALTER TABLE packages ADD COLUMN license_spdx TEXT")
        if "provenance_score" not in columns:
            cursor.execute("ALTER TABLE packages ADD COLUMN provenance_score INTEGER DEFAULT 0")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS deps_dev_cache (
                ecosystem TEXT,
                name TEXT,
                json_data TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (ecosystem, name)
            )
        """)
        conn.commit()

def cache_score(ecosystem: str, name: str, version: str, score_data: dict):
    """Save or update a score report in the cache database."""
    init_db()
    version = version or "latest"
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        
        # Prepare data for storage
        # We store the full score_data as encrypted JSON in raw_metadata
        encrypted_metadata = encrypt(json.dumps(score_data))
        
        cursor.execute("""
            INSERT OR REPLACE INTO packages (
                ecosystem, name, version, score, risk_level, explanations, alternatives, raw_metadata, 
                dep_depth, popularity_anomaly, license_spdx, provenance_score, last_updated
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            ecosystem,
            name,
            version,
            score_data.get("score", 0),
            score_data.get("risk_level", "UNKNOWN"),
            json.dumps(score_data.get("explanations", [])),
            json.dumps(score_data.get("alternatives", [])),
            encrypted_metadata,
            score_data.get("dep_depth", 0),
            score_data.get("popularity_anomaly", 0.0),
            score_data.get("license_spdx"),
            score_data.get("provenance_score", 0)
        ))
        conn.commit()

def get_cached_score(ecosystem: str, name: str, version: str = None, allow_stale: bool = False) -> dict:
    """Retrieve a cached score report if it exists."""
    init_db()
    version = version or "latest"
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT raw_metadata, last_updated FROM packages 
            WHERE ecosystem = ? AND name = ? AND version = ?
        """, (ecosystem, name, version))
        
        row = cursor.fetchone()
        if row:
            raw_metadata_blob, last_updated_str = row
            
            # Decrypt
            try:
                decrypted_data = decrypt(raw_metadata_blob)
                data = json.loads(decrypted_data)
            except Exception:
                return None

            # Check if stale (older than 7 days)
            last_updated = datetime.fromisoformat(last_updated_str.replace("Z", "+00:00"))
            if not allow_stale and datetime.now() - last_updated > timedelta(days=7):
                return None
            
            data["is_stale"] = datetime.now() - last_updated > timedelta(days=7)
            data["last_updated"] = last_updated_str
            if "explanations" not in data or not isinstance(data["explanations"], list):
                data["explanations"] = []
            return data
    return None

def cache_deps_dev(ecosystem: str, name: str, data: dict):
    """Save deps.dev API response to cache."""
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO deps_dev_cache (ecosystem, name, json_data, last_updated)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        """, (ecosystem.lower(), name.lower(), json.dumps(data)))
        conn.commit()

def get_cached_deps_dev(ecosystem: str, name: str) -> dict:
    """Retrieve cached deps.dev data if not stale (30 days)."""
    init_db()
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT json_data, last_updated FROM deps_dev_cache
            WHERE ecosystem = ? AND name = ?
        """, (ecosystem.lower(), name.lower()))
        
        row = cursor.fetchone()
        if row:
            json_data, last_updated_str = row
            last_updated = datetime.fromisoformat(last_updated_str.replace("Z", "+00:00"))
            if datetime.now() - last_updated > timedelta(days=30):
                return None
            return json.loads(json_data)
    return None

def get_stale_packages(days: int = 7) -> list:
    """Return list of (ecosystem, name, version) that are older than specified days."""
    init_db()
    stale_date = datetime.now() - timedelta(days=days)
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT ecosystem, name, version FROM packages 
            WHERE last_updated < ?
        """, (stale_date.isoformat(),))
        return cursor.fetchall()

def get_cache_stats() -> dict:
    """Return counts and health data for the cache."""
    init_db()
    stats = {}
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM packages")
        stats["total_packages"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT MAX(last_updated) FROM packages")
        stats["last_sync"] = cursor.fetchone()[0]
        
        cursor.execute("SELECT ecosystem, COUNT(*) FROM packages GROUP BY ecosystem")
        stats["ecosystems"] = dict(cursor.fetchall())
        
    return stats
