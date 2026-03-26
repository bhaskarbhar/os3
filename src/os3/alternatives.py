"""
Data-driven package recommendations using deps.dev and curated category mappings.
"""
from datetime import datetime, timedelta
from rapidfuzz import fuzz
from os3.scorer import ScoringEngine
from os3 import deps_dev

# Curated popular modern ones per ecosystem (20–50 each)
PYPI_POPULAR = [
    "fastapi", "httpx", "uvicorn", "sqlalchemy", "pydantic", "aiohttp",
    "django", "flask", "requests", "numpy", "pandas", "scipy",
    "scikit-learn", "tensorflow", "torch", "black", "pytest", "isort",
    "pylint", "mypy", "rich", "typer", "click", "ansible", "celery",
    "redis", "pymongo", "psycopg2-binary", "alembic", "starlette",
    "anyio", "trio", "websockets", "python-dotenv", "structlog",
    "loguru", "orjson", "ujson", "pyyaml", "toml", "poetry-core",
]

NPM_POPULAR = [
    "fastify", "axios", "zod", "lodash-es", "undici", "node-fetch",
    "express", "koa", "hapi", "react", "vue", "svelte", "angular",
    "typescript", "jest", "vitest", "mocha", "chai", "cypress",
    "playwright", "eslint", "prettier", "webpack", "vite", "rollup",
    "esbuild", "date-fns", "dayjs", "luxon", "next", "nuxt",
    "pinia", "redux", "tanstack-query", "swr", "tailwindcss",
    "daisyui", "faker", "nanoid", "uuid", "dotenv", "zod",
]

MAVEN_POPULAR = [
    "org.springframework:spring-core", "org.springframework.boot:spring-boot-starter-web",
    "com.google.guava:guava", "org.apache.commons:commons-lang3",
    "com.fasterxml.jackson.core:jackson-databind", "org.slf4j:slf4j-api",
    "ch.qos.logback:logback-classic", "org.hibernate.validator:hibernate-validator",
    "junit:junit", "org.junit.jupiter:junit-jupiter-api",
    "org.mockito:mockito-core", "org.assertj:assertj-core",
    "org.apache.logging.log4j:log4j-core", "org.apache.logging.log4j:log4j-api",
]

# Curated candidates per category (expand initial popular lists)
CATEGORY_CANDIDATES = {
    "http-client": ["httpx", "aiohttp", "axios", "undici", "node-fetch"],
    "web-framework": ["fastapi", "flask", "django", "fastify", "koa", "express"],
    "db-orm": ["sqlalchemy", "alembic", "prisma", "sequelize", "typeorm"],
    "validation": ["pydantic", "zod", "joi", "marshmallow"],
    "utils": ["lodash-es", "ramda", "toolz"],
    "date-time": ["date-fns", "dayjs", "luxon", "pendulum"],
    "logging": ["ch.qos.logback:logback-classic", "org.apache.logging.log4j:log4j-core", "loguru", "structlog"],
}

# Map specific packages to categories for smarter lookup
CATEGORY_MAPPING = {
    # PyPI
    "requests": "http-client",
    "flask": "web-framework",
    "django": "web-framework",
    "sqlalchemy": "db-orm",
    # NPM
    "express": "web-framework",
    "axios": "http-client",
    "request": "http-client",
    "moment": "date-time",
    "lodash": "utils",
    # Maven
    "org.apache.logging.log4j:log4j-core": "logging",
}

# Exact high-confidence mappings
KNOWN_SWAPS = {
    "requests": ["httpx", "aiohttp"],
    "flask": ["fastapi"],
    "express": ["fastify"],
    "lodash": ["lodash-es"],
    "moment": ["date-fns", "dayjs"],
    "request": ["axios"],
}

def get_alternatives(
    ecosystem: str,
    current_name: str,
    current_score: int,
    current_version: str | None = None,
    engine: ScoringEngine | None = None,
    current_data: dict | None = None,
) -> list[dict]:
    """Find safer alternatives for a given package using deps.dev signals and OS3 score."""
    if engine is None:
        engine = ScoringEngine()
    
    current_lower = current_name.lower()
    known = KNOWN_SWAPS.get(current_lower, [])
    category = CATEGORY_MAPPING.get(current_lower)
    
    # Prioritize candidates: Known > Category > Fuzzy
    potential_cands = []
    potential_cands.extend(known)
    
    if category:
        category_list = CATEGORY_CANDIDATES.get(category, [])
        for c in category_list:
            if c.lower() == current_lower: continue
            # Basic ecosystem check: Maven has ':', NPM/PyPI don't
            is_maven_cand = ":" in c
            is_maven_curr = ":" in current_name
            if is_maven_cand == is_maven_curr:
                potential_cands.append(c)
    
    # If still low on candidates, add best fuzzy matches
    if len(potential_cands) < 5:
        if ecosystem.lower() == "pypi": popular = PYPI_POPULAR
        elif ecosystem.lower() == "npm": popular = NPM_POPULAR
        else: popular = MAVEN_POPULAR
        fuzzy_matches = []
        for p in popular:
            if p.lower() == current_lower: continue
            ratio = fuzz.ratio(current_lower, p.lower())
            if ratio > 60:
                fuzzy_matches.append((p, ratio))
        fuzzy_matches.sort(key=lambda x: x[1], reverse=True)
        potential_cands.extend([m[0] for m in fuzzy_matches[:3]])

    matches = []
    seen = {current_lower}

    # Limit total audits to top 10 to keep it responsive
    for cand in potential_cands[:10]:
        if cand.lower() in seen:
            continue
        seen.add(cand.lower())
            
        try:
            # Audit the candidate (non-refreshing to keep it fast)
            alt_data = engine.score_package(ecosystem, cand, None, force_refresh=False, skip_alternatives=True)
            alt_score = alt_data["score"]
            
            # Filter: Significantly better (+10) and safe risk
            if alt_score > current_score + 10 and alt_data["risk_level"] in ["LOW", "MEDIUM"]:
                # Compile signals for comparative display
                signals = []
                curr_depth = current_data.get("dep_depth", 0) if current_data else 0
                alt_depth = alt_data.get("dep_depth", 0)
                
                if alt_depth < curr_depth:
                    signals.append(f"Better depth ({alt_depth} vs {curr_depth})")
                elif alt_depth < 5:
                    signals.append("Low depth")
                    
                if "OSI-approved" in str(alt_data["explanations"]):
                    signals.append(f"OSI {alt_data.get('license_spdx', 'License')}")
                if not alt_data.get("vulns"):
                    signals.append("Zero known vulns")
                
                delta = alt_score - current_score
                
                # Refined "Why" based on signals
                why_better = alt_data['explanations'][0]
                if signals:
                    why_better = f"{signals[0]}, {alt_data['license_spdx']} license"
                
                matches.append({
                    "package": cand,
                    "score": alt_score,
                    "delta": f"+{delta} pts",
                    "risk": alt_data["risk_level"],
                    "why": why_better,
                    "smarter_signals": ", ".join(signals[:3]) or "Active & Better Score"
                })
        except Exception:
            continue

    # Sort and refine
    matches.sort(key=lambda x: x["score"], reverse=True)
    return matches[:5]
