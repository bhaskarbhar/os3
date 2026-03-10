import json
from pathlib import Path

def parse_npm_files(base_path: str = ".") -> list[dict]:
    """Parse NPM manifest or lock files to extract dependencies."""
    base = Path(base_path)
    package_json_path = base / "package.json"
    lock_path = base / "package-lock.json"
    
    deps = []
    
    # Priority 1: package-lock.json (more accurate versions)
    if lock_path.exists():
        try:
            with open(lock_path, "r", encoding="utf-8") as f:
                lock = json.load(f)
            
            # Use 'packages' key introduced in lockfile version 2
            packages = lock.get("packages", {})
            if packages:
                for pkg_path, pkg_data in packages.items():
                    # Skip the root package ('') and link/dev/peer check if needed
                    if pkg_path == "" or "node_modules/" not in pkg_path:
                        continue
                    
                    name = pkg_data.get("name") or pkg_path.split("node_modules/")[-1]
                    version = pkg_data.get("version")
                    
                    # Deduplicate: only take top-level deps OR handle nested?
                    # For a basic scan, let's keep it simple
                    deps.append({
                        "name": name,
                        "version": version,
                        "source": "lock",
                        "ecosystem": "npm"
                    })
            else:
                # Fallback for lockfile v1
                dependencies = lock.get("dependencies", {})
                for name, data in dependencies.items():
                    deps.append({
                        "name": name,
                        "version": data.get("version"),
                        "source": "lock",
                        "ecosystem": "npm"
                    })
        except Exception:
            pass # Fallback to package.json if lock fails
            
    # Priority 2: package.json (if no lock or empty deps)
    if not deps and package_json_path.exists():
        try:
            with open(package_json_path, "r", encoding="utf-8") as f:
                pj = json.load(f)
            
            for section in ["dependencies", "devDependencies"]:
                if section in pj:
                    for name, spec in pj[section].items():
                        deps.append({
                            "name": name,
                            "version": None, # Specific version unknown from manifest
                            "spec": spec,
                            "source": "manifest",
                            "ecosystem": "npm"
                        })
        except Exception:
            pass
            
    return deps
