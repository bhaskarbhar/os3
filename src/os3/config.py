import os
import tomli
from pathlib import Path

CONFIG_DIR = Path.home() / ".os3"
CONFIG_PATH = CONFIG_DIR / "config.toml"

DEFAULT_CONFIG = {
    "sync": {
        "interval_hours": 24,
        "popular_only": True,
    },
    "popular": {
        "pypi": ["requests", "flask", "fastapi", "django", "httpx", "aiohttp", "pydantic", "sqlalchemy", "numpy", "pandas"],
        "npm": ["express", "lodash", "axios", "react", "vue", "next", "typescript", "jest", "fastify", "zod"],
    }
}

def load_config():
    conf = DEFAULT_CONFIG.copy()
    
    # Load curated popular lists if available
    popular_json = Path(__file__).parent / "data" / "popular.json"
    if popular_json.exists():
        import json
        try:
            with open(popular_json, "r") as f:
                conf["popular"] = json.load(f)
        except Exception:
            pass

    if not CONFIG_PATH.exists():
        return conf
    
    try:
        with open(CONFIG_PATH, "rb") as f:
            user_conf = tomli.load(f)
            # Merge user config
            for key, value in user_conf.items():
                if isinstance(value, dict) and key in conf:
                    conf[key].update(value)
                else:
                    conf[key] = value
            return conf
    except Exception:
        return conf

def ensure_config():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if not CONFIG_PATH.exists():
        # We could use tomli-w here if installed, or just write a simple string
        import tomli_w
        with open(CONFIG_PATH, "wb") as f:
            tomli_w.dump(DEFAULT_CONFIG, f)

config = load_config()
