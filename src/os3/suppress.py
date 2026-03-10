import json
from pathlib import Path
from datetime import datetime
import tomli
import tomli_w

GLOBAL_SUPPRESS_PATH = Path.home() / ".os3" / "suppress.toml"
LOCAL_SUPPRESS_PATH = Path(".os3/suppress.toml")

def load_suppressions():
    """Load suppressions from global and local TOML files."""
    suppressions = []
    
    paths = [GLOBAL_SUPPRESS_PATH, LOCAL_SUPPRESS_PATH]
    for path in paths:
        if path.exists():
            try:
                with open(path, "rb") as f:
                    data = tomli.load(f)
                    suppressions.extend(data.get("suppressions", []))
            except Exception:
                pass
                
    return suppressions

def save_suppression(item, local=False):
    """Save a suppression item to TOML."""
    path = LOCAL_SUPPRESS_PATH if local else GLOBAL_SUPPRESS_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    
    data = {"suppressions": []}
    if path.exists():
        try:
            with open(path, "rb") as f:
                loaded = tomli.load(f)
                if isinstance(loaded, dict) and "suppressions" in loaded:
                    data["suppressions"] = loaded["suppressions"]
        except Exception:
            pass
            
    data["suppressions"].append(item)
    
    # 3. Clean any None values from all items before dumping
    for entry in data.get("suppressions", []):
        for k, v in list(entry.items()):
            if v is None:
                del entry[k]
                
    with open(path, "wb") as f:
        tomli_w.dump(data, f)

def remove_suppression(package_name, ecosystem=None):
    """Remove suppressions matching a package name."""
    # We'll check both for simplicity in this MVP
    for path in [GLOBAL_SUPPRESS_PATH, LOCAL_SUPPRESS_PATH]:
        if path.exists():
            try:
                with open(path, "rb") as f:
                    data = tomli.load(f)
                
                filtered = [
                    s for s in data.get("suppressions", [])
                    if s.get("package") != package_name or (ecosystem and s.get("ecosystem") != ecosystem)
                ]
                
                data["suppressions"] = filtered
                with open(path, "wb") as f:
                    tomli_w.dump(data, f)
            except Exception:
                pass

def is_suppressed(ecosystem, package, version=None, cve_id=None):
    """Check if a package or specific CVE is suppressed."""
    suppressions = load_suppressions()
    now = datetime.now().isoformat()
    
    for s in suppressions:
        # Check ecosystem and package name
        if s.get("ecosystem", "").lower() != ecosystem.lower():
            continue
        if s.get("package", "").lower() != package.lower():
            continue
            
        # Check expiration
        expires = s.get("expires")
        if expires and expires < now:
            continue
            
        # Check if suppressing all for this package
        if s.get("suppress_all", False):
            return True, s.get("reason", "Global package suppression")
            
        # Check specific CVE
        if cve_id and cve_id in s.get("cves", []):
            return True, s.get("reason", f"Suppressed CVE {cve_id}")
            
        # Check version range (placeholder for real range logic)
        # For now, exact match or any
        v_range = s.get("version_range", "*")
        if v_range == "*" or v_range == version:
            return True, s.get("reason", "Suppressed via version match")
            
    return False, None
