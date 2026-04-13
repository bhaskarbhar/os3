import difflib
import requests
import json
import subprocess
import os
from datetime import datetime
import xml.etree.ElementTree as ET
from os3 import cache, suppress, deps_dev

class ScoringEngine:
    def __init__(self):
        self.osv_url = "https://api.osv.dev/v1/query"
        self.pypi_url = "https://pypi.org/pypi/{name}/json"
        self.npm_url = "https://registry.npmjs.org/{name}"
        self.npm_downloads_url = "https://api.npmjs.org/downloads/range/last-year/{name}"
        self.maven_search_url = "https://search.maven.org/solrsearch/select?q=g:\"{gid}\"+AND+a:\"{aid}\"&wt=json"
        self.top_packages = [
            "requests", "flask", "django", "numpy", "pandas", "setuptools",
            "urllib3", "pytest", "aiohttp", "boto3", "pyyaml", "werkzeug",
            "jinja2", "pillow", "scipy", "six", "cryptography", "httpx",
            "matplotlib", "sqlalchemy", "seaborn", "scikit-learn", "tensorflow",
            "pytorch", "keras", "pytest", "sphinx", "wheel"
        ]
        
        self.osi_licenses = {
            "MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "GPL-3.0", "LGPL-3.0", 
            "MPL-2.0", "ISC", "EPL-2.0", "Artistic-2.0", "AGPL-3.0", "Zlib", 
            "Unlicense", "CC0-1.0", "PostgreSQL", "PHP-3.01", "Python-2.0",
            "PSF", "Python Software Foundation License"
        }
        
        # Dangerous built-in Python modules that can lead to RCE or critical vulnerabilities
        self.dangerous_modules = {
            "pickle": "Deserialization can lead to Remote Code Execution (RCE) via pickle.loads()",
            "subprocess": "Can execute system commands (command injection risk via shell=True)",
            "os": "Direct OS command execution possible (os.system, os.popen)",
            "eval": "Executes arbitrary Python code - critical RCE vector",
            "exec": "Executes dynamic code - critical RCE vector",
            "marshal": "Unsafe serialization/deserialization similar to pickle",
            "__import__": "Dynamic module import can load malicious code",
            "compile": "Can compile arbitrary code for execution",
        }
        
        # Scoring Weights (Total 1.0)
        self.weights = {
            'cve': 0.40,
            'maintainer': 0.20,
            'depth': 0.15,
            'popularity': 0.10,
            'license': 0.10,
            'provenance': 0.05
        }
        
    def score_package(self, ecosystem: str = 'pypi', name: str = None, version: str | None = None, force_refresh: bool = False, skip_alternatives: bool = False) -> dict:
        """Score a package's security health using real data with offline fallback."""
        if not name:
            return None

        suppressed, s_reason = suppress.is_suppressed(ecosystem, name, version)
        if suppressed:
            return {
                "score": 100,
                "risk_level": "SUPPRESSED",
                "explanations": [f"[dim blue][SUPPRESSED] {s_reason}[/]"],
                "alternatives": [],
                "vulns": [],
                "last_release": None,
                "source": "suppressed",
                "ecosystem": ecosystem,
                "dep_depth": 0,
                "popularity_anomaly": 1.0,
                "license_spdx": "Unknown",
                "provenance_score": 100,
                "signal_breakdown": {
                    "cve_penalty": 0,
                    "maintainer_penalty": 0,
                    "depth_penalty": 0,
                    "popularity_penalty": 0,
                    "license_penalty": 0,
                    "provenance_penalty": 0
                }
            }
        
        # Check if this is a built-in Python module - BE MORE SPECIFIC
        if ecosystem.lower() == 'pypi':
            try:
                import importlib
                import sys
                spec = importlib.util.find_spec(name)
                if spec and spec.origin:
                    # Only consider it built-in if it's in the core Python library path
                    # and not in site-packages (third-party installs)
                    is_stdlib = (
                        spec.origin and 
                        'Python' in spec.origin and
                        'site-packages' not in spec.origin and
                        spec.origin.startswith(sys.base_prefix)
                    )
                    if is_stdlib:
                        # Check if this is a dangerous built-in module
                        if name.lower() in self.dangerous_modules:
                            danger_desc = self.dangerous_modules[name.lower()]
                            return {
                                "score": 35,
                                "risk_level": "HIGH",
                                "explanations": [
                                    f"[red][CRITICAL] Dangerous built-in module: {danger_desc}[/]",
                                    "[red][WARN] While part of the standard library, this module can lead to critical vulnerabilities if misused.[/]",
                                    "[red][WARN] Avoid using in untrusted contexts or with untrusted data.[/]"
                                ],
                                "alternatives": [],
                                "vulns": [],
                                "last_release": None,
                                "source": "builtin-dangerous",
                                "ecosystem": ecosystem,
                                "dep_depth": 0,
                                "popularity_anomaly": 1.0,
                                "license_spdx": "Python Software Foundation License",
                                "provenance_score": 100,
                                "signal_breakdown": {
                                    "cve_penalty": -65,
                                    "maintainer_penalty": 0,
                                    "depth_penalty": 0,
                                    "popularity_penalty": 0,
                                    "license_penalty": 0,
                                    "provenance_penalty": 0
                                }
                            }
                        else:
                            # This is a safe built-in/standard library module
                            return {
                                "score": 100,
                                "risk_level": "LOW",
                                "explanations": [
                                    "[green][OK] Built-in Python standard library module (+0 pts).[/]",
                                    "[dim]Standard library modules are inherently secure and don't require external scoring.[/]"
                                ],
                                "alternatives": [],
                                "vulns": [],
                                "last_release": None,
                                "source": "builtin",
                                "ecosystem": ecosystem,
                                "dep_depth": 0,
                                "popularity_anomaly": 1.0,
                                "license_spdx": "Python Software Foundation License",
                                "provenance_score": 100,
                                "signal_breakdown": {
                                    "cve_penalty": 0,
                                    "maintainer_penalty": 0,
                                    "depth_penalty": 0,
                                    "popularity_penalty": 0,
                                    "license_penalty": 0,
                                    "provenance_penalty": 0
                                }
                            }
            except ImportError:
                pass
        
        # 1. Try local cache (only if fresh)
        if not force_refresh:
            cached = cache.get_cached_score(ecosystem, name, version, allow_stale=False)
            if cached:
                cached["source"] = "cache"
                return cached
        
        # 2. Try to fetch fresh data
        network_error = False
        vulns = []
        try:
            # Check OSV
            osv_eco = ecosystem.upper() if ecosystem.lower() != 'maven' else 'Maven'
            payload = {"package": {"name": name, "ecosystem": osv_eco}}
            if version:
                payload["version"] = version
                
            response = requests.post(self.osv_url, json=payload, timeout=5)
            if response.status_code == 200:
                vulns = response.json().get("vulns", [])
        except (requests.ConnectionError, requests.Timeout):
            network_error = True
        except Exception:
            pass
            
        # 3. Fetch Metadata
        info = {}
        last_release_date = None
        if not network_error:
            try:
                if ecosystem.lower() == 'pypi':
                    pypi_api_url = self.pypi_url.format(name=name)
                    if version:
                        pypi_api_url = f"https://pypi.org/pypi/{name}/{version}/json"
                    
                    pypi_response = requests.get(pypi_api_url, timeout=5)
                    if pypi_response.status_code == 200:
                        pypi_data = pypi_response.json()
                        info = pypi_data.get("info", {})
                        releases = pypi_data.get("releases", {})
                        upload_times = []
                        for rel_version, file_list in releases.items():
                            for file_info in file_list:
                                if "upload_time" in file_info:
                                    upload_times.append(file_info["upload_time"])
                        if upload_times:
                            last_release_date = max(upload_times)
                
                elif ecosystem.lower() == 'npm':
                    npm_api_url = self.npm_url.format(name=name)
                    npm_response = requests.get(npm_api_url, timeout=5)
                    if npm_response.status_code == 200:
                        npm_data = npm_response.json()
                        times = npm_data.get("time", {})
                        if "modified" in times:
                            last_release_date = times["modified"]
                        elif "latest" in times:
                            last_release_date = times["latest"]
                
                elif ecosystem.lower() == 'maven':
                    # groupId:artifactId format
                    if ":" in name:
                        gid, aid = name.split(":", 1)
                        # Metadata from search.maven.org (Solr API)
                        maven_res = requests.get(self.maven_search_url.format(gid=gid, aid=aid), timeout=5)
                        if maven_res.status_code == 200:
                            m_data = maven_res.json().get("response", {}).get("docs", [])
                            if m_data:
                                doc = m_data[0]
                                info = doc # Reuse 'info' for Maven metadata too
                                # Solr returns timestamp as integer
                                if "timestamp" in doc:
                                    ts = doc["timestamp"] / 1000.0
                                    last_release_date = datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            except (requests.ConnectionError, requests.Timeout):
                network_error = True
            except Exception:
                pass

        # 4. Handle Offline Fallback
        if network_error:
            stale = cache.get_cached_score(ecosystem, name, version, allow_stale=True)
            if stale:
                stale["source"] = "cache (offline)"
                stale["explanations"].append("⚠️ Network error: Showing cached data which may be stale.")
                return stale
            else:
                raise Exception("Network error and no cached data available.")

        # 4.5 CRITICAL: Check if package actually exists
        package_exists = False
        if ecosystem.lower() == 'pypi':
            package_exists = bool(info and info.get("name"))
        elif ecosystem.lower() == 'npm':
            package_exists = bool(info and info.get("name"))
        elif ecosystem.lower() == 'maven':
            package_exists = bool(info and info.get("id"))

        if not package_exists and not network_error:
            # Package not found - HIGH RISK (possible typosquat/malicious)
            return {
                "score": 20,
                "risk_level": "HIGH",
                "explanations": [
                    "[red][CRITICAL] Package not found in repository (possible typosquat/malicious) (-80 pts).[/]",
                    "[red][FAIL] No package metadata available (-60 pts).[/]",
                    "[yellow][WARN] No vulnerability data available (-30 pts).[/]"
                ],
                "alternatives": [],
                "vulns": [],
                "last_release": None,
                "source": "api",
                "ecosystem": ecosystem,
                "dep_depth": 0,
                "popularity_anomaly": 1.0,
                "license_spdx": "Unknown",
                "provenance_score": 20,
                "signal_breakdown": {
                    "cve_penalty": -30,
                    "maintainer_penalty": -50,
                    "depth_penalty": 0,
                    "popularity_penalty": 0,
                    "license_penalty": -15,
                    "provenance_penalty": -80
                }
            }

        # 5. Compute Signals
        # 5.1 CVE Penalty (0-100)
        cve_score = 100
        explanations = []
        
        suppressed, s_reason = suppress.is_suppressed(ecosystem, name, version)
        valid_vulns = []
        for v_id in [v.get("id") for v in vulns]:
            v_suppressed, v_reason = suppress.is_suppressed(ecosystem, name, version, cve_id=v_id)
            if not v_suppressed:
                valid_vulns.append(v_id)
            else:
                explanations.append(f"[dim blue]SUPPRESSED vulnerability {v_id}: {v_reason}[/]")

        if valid_vulns:
            high_severity_count = sum(1 for v in vulns if v.get("id") in valid_vulns and any(s.get("type") == "CVSS_V3" for s in v.get("severity", [])))
            # STRONGER PENALTY: 40 per vuln, +20 for high severity (was 15)
            penalty = (len(valid_vulns) * 40) + (high_severity_count * 20)
            cve_score = max(0, 100 - penalty)
            explanations.append(f"[red][FAIL] Found {len(valid_vulns)} active vulnerabilities (-{100-cve_score} pts).[/]")
        else:
            explanations.append("[green][OK] No active vulnerabilities found (+0 pts).[/]")
            
        # Penalize "no CVE data available" - but less for established packages
        if not vulns and not network_error:
            # For well-maintained packages, OSV coverage gaps don't indicate risk
            days_since_release_placeholder = 0
            try:
                if last_release_date:
                    if "-" in last_release_date and " " in last_release_date:
                        release_dt = datetime.strptime(last_release_date, "%Y-%m-%d %H:%M:%S")
                    else:
                        release_dt = datetime.fromisoformat(last_release_date.replace("Z", ""))
                    days_since_release_placeholder = (datetime.utcnow() - release_dt).days
            except:
                pass
            
            if days_since_release_placeholder < 365:
                # Recently maintained package → OSV gap is not as concerning
                cve_penalty = 10
            elif days_since_release_placeholder < 1000:
                # Old but not ancient → still some concern
                cve_penalty = 20
            else:
                # Very old package → missing CVE data is more concerning
                cve_penalty = 30
                
            explanations.append(f"[yellow][WARN] No vulnerability data available (-{cve_penalty} pts).[/]")
            cve_score = max(0, cve_score - cve_penalty)

        # 5.2 Maintainer Activity (0-100) - STRONGER PENALTIES
        maintainer_score = 30
        days_since_release = None
        if last_release_date:
            try:
                if "-" in last_release_date and " " in last_release_date:
                    release_dt = datetime.strptime(last_release_date, "%Y-%m-%d %H:%M:%S")
                else:
                    release_dt = datetime.fromisoformat(last_release_date.replace("Z", ""))
                days_since_release = (datetime.utcnow() - release_dt).days
                if days_since_release > 1000:  # Very old packages
                    maintainer_score = 20
                    explanations.append(f"[red][FAIL] Extremely outdated: Last release was {days_since_release} days ago (-80 pts).[/]")
                elif days_since_release > 365:  # Old packages
                    maintainer_score = 45
                    explanations.append(f"[yellow][WARN] Activity: Last release was {days_since_release} days ago (-55 pts).[/]")
                else:
                    maintainer_score = 70
                    explanations.append("[green][OK] Active maintenance: Recent release found (+0 pts).[/]")
            except Exception:
                pass
        else:
            maintainer_score = 25  # STRONGER penalty for no release date
            explanations.append("[red][FAIL] Activity: No release date found (-75 pts).[/]")

        if ecosystem.lower() == 'pypi':
            maintainer_fields = [
                info.get("author"), info.get("author_email"),
                info.get("maintainer"), info.get("maintainer_email")
            ]
            if any(maintainer_fields):
                maintainer_score = min(100, maintainer_score + 10)
                explanations.append("[green][OK] Maintainer metadata present (+10 pts).[/]")
            else:
                maintainer_score = min(40, maintainer_score)
                explanations.append("[yellow][WARN] No maintainer metadata available (-10 pts).[/]")

        # 5.2.5 Typosquatting Detection (CRITICAL for supply chain security)
        provenance_score = 30  # Default provenance is low for unknown packages
        if ecosystem.lower() == 'pypi':
            # Basic heuristics for typosquatting detection
            typosquat_risk = 0
            if len(name) < 4:  # Very short names are suspicious
                typosquat_risk += 25
            if name.count('-') > 3 or name.count('_') > 3:  # Too many separators
                typosquat_risk += 20
            if any(char.isdigit() for char in name[-3:]):  # Numbers at end
                typosquat_risk += 25
            if name.endswith(('s', 'es', 'ed', 'ing', 'er', 'ly')) == False and len(name) > 6:
                # Doesn't end with common English suffixes - possible typo
                typosquat_risk += 15

            close_match = difflib.get_close_matches(name.lower(), self.top_packages, n=1, cutoff=0.75)
            if close_match and close_match[0] != name.lower():
                typosquat_risk += 35
                explanations.append(f"[red][WARN] Likely typosquat of popular package '{close_match[0]}' (-35 pts).[/]")

            if typosquat_risk > 20:
                provenance_score = max(0, provenance_score - typosquat_risk)
                explanations.append(f"[red][WARN] Possible typosquatting pattern detected (-{typosquat_risk} pts).[/]")

        # 5.3 Dependency Depth (0-100)
        depth_score = 100
        depth = 0
        try:
            if ecosystem.lower() == 'pypi':
                # subprocess pipdeptree if installed, else stub
                cmd = ["py", "-m", "pipdeptree", "-p", name, "--json"]
                try:
                    pdt_raw = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=5)
                    pdt_data = json.loads(pdt_raw)
                    # Simple depth is count of transitive packages
                    depth = len(pdt_data) 
                except:
                    # Fallback: count direct requirements from pypi JSON
                    depth = len(info.get("requires_dist", []) or [])
                    if depth == 0: depth = 1
            elif ecosystem.lower() == 'maven':
                # subprocess mvn dependency:tree if project exists or parse count levels from it
                # For a specific package, we'd ideally need a pom to scan. 
                # Stubbing: parse count levels from 'mvn dependency:tree' if pom.xml exists in current dir
                if os.path.exists("pom.xml"):
                    try:
                        cmd = ["mvn", "dependency:tree", f"-Dincludes={name}", "-q"]
                        mvn_out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=10).decode()
                        # Count levels by looking at the tree indentation
                        # [INFO] org.example:app:jar:1.0
                        # [INFO] +- org.example:lib:jar:2.0  (depth 1)
                        # [INFO] |  \- org.example:transitive:jar:3.0 (depth 2)
                        depth = 0
                        for line in mvn_out.splitlines():
                            if name in line:
                                depth = (line.count("   ") // 1) + 1 # Rough depth estimate
                                break
                    except:
                        depth = 2
                else:
                    depth = 2
            
            direct_deps = len(info.get("requires_dist", []) or [])
            well_maintained = days_since_release and days_since_release < 365
            
            if well_maintained and depth <= 15:
                # Well-maintained packages with reasonable depth are acceptable
                depth_score = 85
                explanations.append(f"[green][OK] Depth: Manageable transitive complexity ({depth} levels) (+0 pts).[/]")
            elif depth > 20:
                depth_score = 50
                explanations.append(f"[red][WARN] Depth: Extreme transitive risk ({depth} levels) (-50 pts).[/]")
            elif depth > 10:
                depth_score = 70
                explanations.append(f"[yellow][WARN] Depth: High complexity ({depth} levels) (-30 pts).[/]")
            elif depth > 5:
                depth_score = 85
                explanations.append(f"[yellow][WARN] Depth: Moderate complexity ({depth} levels) (-15 pts).[/]")
            else:
                explanations.append(f"[green][OK] Depth: Low transitive risk ({depth}) (+0 pts).[/]")

            if direct_deps > 15:
                depth_score = min(depth_score, 60)
                explanations.append(f"[red][WARN] Many direct dependencies ({direct_deps}) increase supply chain risk (-40 pts).[/]")
            elif direct_deps > 10:
                depth_score = min(depth_score, 75)
                explanations.append(f"[yellow][WARN] Significant direct dependencies ({direct_deps}) increase risk (-25 pts).[/]")
            elif direct_deps > 5:
                depth_score = min(depth_score, 85)
                explanations.append(f"[yellow][WARN] Multiple direct dependencies ({direct_deps}) increase risk (-15 pts).[/]")
        except Exception:
            depth = 1

        # 5.4 Popularity Anomaly (0-100)
        popularity_score = 100
        anomaly_score = 1.0
        if ecosystem.lower() == 'npm' and not network_error:
            try:
                res = requests.get(self.npm_downloads_url.format(name=name), timeout=5)
                if res.status_code == 200:
                    downloads = res.json().get("downloads", [])
                    if len(downloads) >= 2:
                        recent_mo = sum(d["downloads"] for d in downloads[-30:])
                        avg_mo = sum(d["downloads"] for d in downloads) / (len(downloads) / 30)
                        if avg_mo > 0:
                            anomaly_score = recent_mo / avg_mo
                            if anomaly_score > 2.5:
                                popularity_score = 60
                                explanations.append(f"[red][SPIKE] Popularity: Anomaly detected ({anomaly_score:.1f}x spike) (-40 pts).[/]")
                            elif recent_mo < 100:
                                popularity_score = 40
                                explanations.append(f"[red][WARN] Extremely low usage ({recent_mo} downloads/mo) (-60 pts).[/]")
                            elif avg_mo < 500:
                                popularity_score = 70
                                explanations.append(f"[yellow][WARN] Low usage ({int(avg_mo)} avg downloads/mo) (-30 pts).[/]")
                            else:
                                explanations.append(f"[green][OK] Popularity: Stable growth ({anomaly_score:.1f}x) (+0 pts).[/]")
            except:
                pass
        elif ecosystem.lower() == 'pypi' and not network_error:
            # PyPI popularity is opaque; use ecosystem trust and metadata heuristics
            is_popular = name.lower() in self.top_packages
            has_project_url = bool(info.get("project_urls") or info.get("home_page"))
            download_count = info.get("downloads", {}).get("last_month", 0) if isinstance(info.get("downloads"), dict) else 0
            
            popularity_score = 85 if is_popular else 75 if has_project_url else 60
            
            if is_popular:
                explanations.append("[green][OK] Ecosystem trust: Package is well-established and widely used (+10 pts).[/]")
                provenance_score = min(100, provenance_score + 40)  # Boost provenance for known packages
            elif has_project_url:
                explanations.append("[green][OK] Package has project URLs, indicating public presence (+0 pts).[/]")
            else:
                explanations.append("[yellow][WARN] Missing project URLs, low public traceability (-40 pts).[/]")
        else:
            explanations.append("[dim]Popularity analytics skipped or unavailable.[/]")

        # 5.5 License & Provenance
        license_score = 100
        license_spdx = "Unknown"
        
        # License detection
        raw_lic = None
        if ecosystem.lower() == 'pypi':
            raw_lic = info.get("license")
            if isinstance(raw_lic, str):
                raw_lic = raw_lic.strip()
                if len(raw_lic) > 64 or "\n" in raw_lic:
                    classifiers = info.get("classifiers", []) or []
                    license_classifiers = [c for c in classifiers if c.startswith("License ::")]
                    if license_classifiers:
                        raw_lic = license_classifiers[-1].split("::")[-1].strip()
                    else:
                        raw_lic = raw_lic.splitlines()[0].strip()
        elif ecosystem.lower() == 'npm':
            l_data = info.get("license") or info.get("licenses")
            if isinstance(l_data, list):
                lic_names = []
                for l in l_data:
                    if isinstance(l, dict): lic_names.append(l.get("type", "Unknown"))
                    else: lic_names.append(str(l))
                raw_lic = ", ".join(lic_names)
            elif isinstance(l_data, dict):
                raw_lic = l_data.get("type")
            else:
                raw_lic = l_data
        elif ecosystem.lower() == 'maven':
            # Handle list or single string in Maven search result (if any) or look for 'ec' field
            raw_lic = ", ".join(info.get("ec", [])) if isinstance(info.get("ec"), list) else info.get("ec")

        if raw_lic:
            license_spdx = str(raw_lic)
            clean_lic = license_spdx.lower().replace("-", "").replace(" ", "").replace(".", "")
            is_osi = any(osi.lower().replace("-", "").replace(" ", "").replace(".", "") in clean_lic for osi in self.osi_licenses)
            if is_osi:
                license_score = 100
                explanations.append(f"[green][OK] License: {license_spdx} (OSI-approved, +0 pts).[/]")
            else:
                license_score = 90
                explanations.append(f"[yellow][WARN] Non-OSI license: {license_spdx} (-10 pts).[/]")
        else:
            license_score = 85
            explanations.append("[yellow][WARN] No license detected (-15 pts).[/]")

        if not network_error:
            dd_data = deps_dev.query_deps_dev(name, ecosystem)
            if dd_data:
                dd_info = deps_dev.get_package_score_from_deps_dev(dd_data)
                if dd_info:
                    # Adjust provenance based on community signals
                    if dd_data.get("stars", 0) > 100:
                        provenance_score = min(100, provenance_score + 30)
                        explanations.append("[green][OK] Provenance: High community trust (+30 pts).[/]")
                    elif dd_data.get("stars", 0) > 10:
                        provenance_score = min(100, provenance_score + 15)
                        explanations.append("[green][OK] Provenance: Good community signals (+15 pts).[/]")
                    explanations.extend([f"[dim white]deps.dev: {e}[/]" for e in dd_info[1]])

        # 6. Composite Aggregate
        final_score = (
            (cve_score * self.weights['cve']) +
            (maintainer_score * self.weights['maintainer']) +
            (depth_score * self.weights['depth']) +
            (popularity_score * self.weights['popularity']) +
            (license_score * self.weights['license']) +
            (provenance_score * self.weights['provenance'])
        )
        
        final_score = round(final_score)
        
        # 6.5 Apply Suppression
        # Check if the whole package is suppressed or if there's any pending CVE suppression logic 
        # (CVE suppression happens during signal computation above, but we also check for general suppression here)
        suppressed, s_reason = suppress.is_suppressed(ecosystem, name, version)
        if suppressed:
            risk_level = "SUPPRESSED"
            final_score = 100
            explanations.append(f"[dim blue][SUPPRESSED] {s_reason}[/]")
        else:
            risk_level = "LOW" if final_score >= 75 else "MEDIUM" if final_score >= 50 else "HIGH"

        # 7. Final Result
        result = {
            "score": final_score,
            "risk_level": risk_level,
            "explanations": explanations,
            "alternatives": [],
            "vulns": valid_vulns,
            "last_release": last_release_date,
            "source": "api",
            "ecosystem": ecosystem,
            "dep_depth": depth,
            "popularity_anomaly": anomaly_score,
            "license_spdx": license_spdx,
            "provenance_score": provenance_score,
            "signal_breakdown": {
                "cve_penalty": -(100 - cve_score),
                "maintainer_penalty": -(100 - maintainer_score),
                "depth_penalty": -(100 - depth_score),
                "popularity_penalty": -(100 - popularity_score),
                "license_penalty": -(100 - license_score),
                "provenance_penalty": -(100 - provenance_score)
            }
        }
        
        # Alternatives logic
        if not skip_alternatives:
            from os3 import alternatives
            result["alternatives"] = alternatives.get_alternatives(ecosystem, name, final_score, version, engine=self, current_data=result)
            
        cache.cache_score(ecosystem, name, version or "latest", result)
        return result
