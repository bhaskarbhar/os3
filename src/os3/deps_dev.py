import requests
from os3 import cache

def query_deps_dev(package_name: str, ecosystem: str = 'pypi') -> dict | None:
    """Query deps.dev API for package data and health signals."""
    ecosystem = ecosystem.lower()
    cached = cache.get_cached_deps_dev(ecosystem, package_name)
    if cached:
        return cached

    # The official API follows this pattern: api.deps.dev/v1alpha/systems/{system}/packages/{package}
    # However, the user suggested https://deps.dev/v1alpha/packages/{ecosystem}/{package_name}
    # We will try the user's suggestion first, then fallback to api.deps.dev
    url_found = False
    urls = [
        f"https://api.deps.dev/v1alpha/systems/{ecosystem}/packages/{package_name}",
        f"https://deps.dev/v1alpha/packages/{ecosystem}/{package_name}"
    ]
    
    data = None
    for url in urls:
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                url_found = True
                break
        except Exception:
            continue
            
    if data:
        cache.cache_deps_dev(ecosystem, package_name, data)
        return data
    return None

def get_package_score_from_deps_dev(data: dict) -> int | None:
    """Extract health/score signals from deps.dev data."""
    if not data:
        return None
        
    score = 100
    explanations = []
    
    # Check for advisories in the latest/default version
    versions = data.get("versions", [])
    default_version = next((v for v in versions if v.get("isDefault")), None) or (versions[0] if versions else None)
    
    if default_version:
        advisories = default_version.get("advisoryKeys", [])
        if advisories:
            penalty = min(40, len(advisories) * 10)
            score -= penalty
            explanations.append(f"deps.dev: {len(advisories)} advisories detected.")
            
        licenses = default_version.get("licenses", [])
        if licenses:
            # We assume most common OSI licenses for this check
            osi_list = ["MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "GPL-3.0", "LGPL-3.0", "MPL-2.0", "ISC"]
            is_osi = any(any(osi in l for osi in osi_list) for l in licenses)
            if not is_osi:
                score -= 10
                explanations.append(f"deps.dev: Non-OSI or unknown license ({', '.join(licenses)}).")
        else:
            score -= 10
            explanations.append("deps.dev: No license info found.")
            
    return score, explanations
