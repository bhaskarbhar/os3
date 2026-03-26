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
        
        self.osi_licenses = {
            "MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "GPL-3.0", "LGPL-3.0", 
            "MPL-2.0", "ISC", "EPL-2.0", "Artistic-2.0", "AGPL-3.0", "Zlib", 
            "Unlicense", "CC0-1.0", "PostgreSQL", "PHP-3.01", "Python-2.0"
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
            # Penalty: 15 per vuln, +20 for high severity
            penalty = (len(valid_vulns) * 15) + (high_severity_count * 20)
            cve_score = max(0, 100 - penalty)
            explanations.append(f"[red][FAIL] Found {len(valid_vulns)} active vulnerabilities (-{100-cve_score} pts).[/]")
        else:
            explanations.append("[green][OK] No active vulnerabilities found (+0 pts).[/]")

        # 5.2 Maintainer Activity (0-100)
        maintainer_score = 100
        if last_release_date:
            try:
                if "-" in last_release_date and " " in last_release_date:
                    release_dt = datetime.strptime(last_release_date, "%Y-%m-%d %H:%M:%S")
                else:
                    release_dt = datetime.fromisoformat(last_release_date.replace("Z", ""))
                days_since_release = (datetime.utcnow() - release_dt).days
                if days_since_release > 365:
                    maintainer_score = 50 if days_since_release > 730 else 75
                    explanations.append(f"[yellow][WARN] Activity: Last release was {days_since_release} days ago (-{100-maintainer_score} pts).[/]")
                else:
                    explanations.append("[green][OK] Active maintenance: Recent release found (+0 pts).[/]")
            except Exception:
                pass
        else:
            maintainer_score = 50
            explanations.append("[yellow][WARN] Activity: No release date found (-50 pts).[/]")

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
            
            if depth > 10:
                depth_score = 50
                explanations.append(f"[red][WARN] Depth: Extreme transitive risk ({depth} levels) (-50 pts).[/]")
            elif depth > 5:
                depth_score = 75
                explanations.append(f"[yellow][WARN] Depth: High complexity ({depth} levels) (-25 pts).[/]")
            else:
                explanations.append(f"[green][OK] Depth: Low transitive risk ({depth}) (+0 pts).[/]")
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
                            else:
                                explanations.append(f"[green][OK] Popularity: Stable growth ({anomaly_score:.1f}x) (+0 pts).[/]")
            except:
                pass
        else:
            explanations.append("[dim]Popularity analytics skipped or unavailable.[/]")

        # 5.5 License & Provenance
        license_score = 100
        provenance_score = 80
        license_spdx = "Unknown"
        
        # License detection
        raw_lic = None
        if ecosystem.lower() == 'pypi': raw_lic = info.get("license")
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
                    # Minor adjustment to prov based on dd
                    if dd_data.get("stars", 0) > 100:
                        provenance_score = 100
                        explanations.append("[green][OK] Provenance: High community trust (+20 pts).[/]")
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
            risk_level = "LOW" if final_score >= 80 else "MEDIUM" if final_score >= 55 else "HIGH"

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
