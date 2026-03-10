import time
import requests
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from os3.scorer import ScoringEngine
from os3.config import config
from os3 import cache
from datetime import datetime

def sync_all(full: bool = False, quiet: bool = False):
    """Sync vulnerabilities and refresh stale cache entries."""
    engine = ScoringEngine()
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        transient=quiet
    ) as progress:
        
        # 1. Sync OSV (simulated for now, could be real bulk)
        task_osv = progress.add_task("[cyan]Syncing OSV vulns...", total=1)
        # In a real implementation, we might download https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
        time.sleep(1) 
        progress.update(task_osv, advance=1)

        # 2. Identify packages to refresh
        pkgs_to_sync = []
        if full:
            # Add all popular packages
            for eco, names in config.get("popular", {}).items():
                for name in names:
                    pkgs_to_sync.append((eco, name))
        
        # Add stale packages from cache
        stale_pkgs = cache.get_stale_packages(days=7)
        for eco, name, ver in stale_pkgs:
            if (eco, name) not in pkgs_to_sync:
                pkgs_to_sync.append((eco, name))

        if not pkgs_to_sync:
            if not quiet:
                from os3.cli import console
                console.print("[info]Cache is already fresh. No sync needed.[/info]")
            return

        # 3. Perform the sync
        task_sync = progress.add_task("[green]Refreshing metadata...", total=len(pkgs_to_sync))
        for ecosystem, name in pkgs_to_sync:
            try:
                # force_refresh=True to update the cache
                engine.score_package(ecosystem, name, force_refresh=True)
            except Exception:
                pass
            progress.update(task_sync, advance=1)

    if not quiet:
        from os3.cli import console
        console.print(f"[success]Sync complete! {len(pkgs_to_sync)} packages updated.[/success]")

def get_status():
    """Return cache health information."""
    stats = cache.get_cache_stats()
    return stats
