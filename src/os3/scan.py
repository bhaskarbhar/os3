from pathlib import Path
from pip_requirements_parser import RequirementsFile
from os3.scorer import ScoringEngine
from os3 import npm_parser, alternatives, maven_parser

def scan_file(file_path: str, force_refresh: bool = False) -> dict:
    """Generic entry point to scan and score any supported dependency file."""
    path = Path(file_path).name.lower()
    
    # 1. Dispatch to parser to get dependencies
    deps = []
    if "requirements" in path or path.endswith(".txt"):
        deps = parse_pip_requirements(file_path)
    elif "package" in path and path.endswith(".json"):
        # Handle package.json or package-lock.json centrally
        deps = npm_parser.parse_npm_files(Path(file_path).parent)
    elif path == "pom.xml":
        deps = maven_parser.parse_pom_xml(file_path)
    
    if not deps:
        return {"results": [], "summary": {}}
        
    # 2. Batch score each dep using Scoring Engine (single engine for cache reuse)
    engine = ScoringEngine()
    results = []
    for d in deps:
        ecosystem = d.get("ecosystem", "pypi")
        name = d["name"]
        version = d.get("version")
        
        try:
            score_data = engine.score_package(ecosystem, name, version, force_refresh=force_refresh)
            
            # 2.5 Find safer alternatives for risky packages (reuse engine for cached scoring)
            recs = []
            if score_data["score"] < 70 or score_data["risk_level"] == "HIGH":
                recs = alternatives.get_alternatives(
                    ecosystem, name, score_data["score"],
                    current_version=version,
                    engine=engine,
                )
            
            results.append({
                "name": name,
                "version": version or "latest",
                "ecosystem": ecosystem,
                "score_data": score_data,
                "recommendations": recs
            })
        except Exception as e:
            results.append({
                "name": name,
                "version": version or "latest",
                "ecosystem": ecosystem,
                "error": str(e)
            })
            
    # 3. Aggregate results for summary
    scores = [r["score_data"]["score"] for r in results if "score_data" in r]
    avg_score = sum(scores) / len(scores) if scores else 0
    
    risk_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "UNKNOWN": 0}
    ecosystem_counts = {}
    
    for r in results:
        eco = r.get("ecosystem", "pypi")
        ecosystem_counts[eco] = ecosystem_counts.get(eco, 0) + 1
        
        if "score_data" in r:
            risk_level = r["score_data"].get("risk_level", "UNKNOWN")
            if risk_level in risk_counts:
                risk_counts[risk_level] += 1
            else:
                risk_counts["UNKNOWN"] += 1
                
    summary = {
        "total_packages": len(results),
        "ecosystem_counts": ecosystem_counts,
        "avg_score": round(avg_score, 1),
        "risk_counts": risk_counts,
        "high_risk_found": risk_counts["HIGH"] > 0
    }
    
    return {"results": results, "summary": summary}

def parse_pip_requirements(file_path: str) -> list[dict]:
    """Extracted parsing logic for requirements.txt files."""
    path = Path(file_path)
    if not path.exists():
        return []
        
    rf = RequirementsFile.from_file(path)
    deps = []
    for req in rf.requirements:
        name = req.name
        if not name or getattr(req, 'is_url', False) or getattr(req, 'is_vcs', False):
            continue
            
        version = None
        if req.specifier:
            for spec in req.specifier:
                if spec.operator == "==":
                    version = spec.version
                    break
                    
        deps.append({
            "name": name,
            "version": version,
            "ecosystem": "pypi"
        })
    return deps

def scan_requirements_file(file_path: str, force_refresh: bool = False) -> dict:
    """Old entry point maintained for legacy support."""
    return scan_file(file_path, force_refresh)
