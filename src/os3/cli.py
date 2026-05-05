from rich.console import Console
from rich.panel import Panel
from rich.theme import Theme
from rich.table import Table
from rich.tree import Tree
from rich.columns import Columns
from rich.prompt import Prompt, Confirm
import tomli
from os3 import __version__
from os3 import cache
from os3 import scorer
from os3 import scan as scan_module
from os3 import sync as sync_module
from os3 import suppress
import typer
import json
import requests
import subprocess
import time
import sys
from datetime import datetime
from pathlib import Path
from os3.config import ensure_config

ensure_config()
from rich.live import Live
from rich.prompt import Confirm, Prompt

# Define a premium dark-friendly theme
custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "version": "bold magenta",
})

# Initialize Rich Console with the custom theme
console = Console(theme=custom_theme)

app = typer.Typer(
    name="os3",
    help="🛡️ [bold blue]Open-Source Security Score (OS3) CLI Tool[/bold blue]",
    add_completion=False,
    rich_markup_mode="rich",
)

def display_version():
    """Helper to display version in a nice Rich style."""
    console.print(
        Panel(
            f"[bold info]OS3[/bold info] - [italic white]Open-Source Security Score[/italic white]\n"
            f"[bold info]Version:[/bold info] [version]{__version__}[/version]",
            title="[bold blue]System Information[/bold blue]",
            border_style="blue",
            expand=False,
            padding=(1, 2)
        )
    )

@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        None,
        "--version",
        "-v",
        help="Display the version and exit.",
        is_eager=True,
    ),
):
    """
    🛡️ [bold blue]Open-Source Security Score CLI[/bold blue]

    Evaluate and monitor the security health of open-source projects with style.
    """
    if version:
        display_version()
        raise typer.Exit()
    
    if ctx.invoked_subcommand is None:
        console.print("[yellow]Welcome to OS3![/yellow] Use [bold]--help[/bold] to see available commands.")

@app.command()
def score(
    package: str = typer.Argument(..., help="The package name to score."),
    version: str = typer.Option(None, "--version", "-v", help="Specific version to score."),
    ecosystem: str = typer.Option("pypi", "--ecosystem", "-e", help="The ecosystem (e.g., pypi, npm)."),
    force_refresh: bool = typer.Option(False, "--force-refresh", "-f", help="Ignore cache and fetch fresh data."),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format."),
):
    """
    📊 [bold green]Score a package's security health using real data.[/bold green]
    """
    engine = scorer.ScoringEngine()
    
    with console.status(f"[bold blue]Scoring [info]{package}[/info]...") as status:
        try:
            report_data = engine.score_package(ecosystem, package, version, force_refresh)
        except Exception as e:
            console.print(f"[error]Error fetching data for {package}: {str(e)}[/error]")
            raise typer.Exit(1)
    
        if not report_data:
            console.print(f"[error]Could not find data for {package}[/error]")
            raise typer.Exit(1)
            
        if json_output:
            import json
            print(json.dumps(report_data, indent=2, ensure_ascii=False))
            return
            
        score = report_data.get("score", 0)
        risk_level = report_data.get("risk_level", "UNKNOWN")
        explanations = report_data.get("explanations", [])
        alternatives = report_data.get("alternatives", [])
        vulns = report_data.get("vulns", [])
        source = report_data.get("source", "api")

    # 1. Header & Quick View
    color = "green" if score >= 80 else "yellow" if score >= 55 else "red"
    if risk_level == "SUPPRESSED":
        color = "cyan"
    
    source_tag = "[dim yellow](cached)[/]" if source == "cache" else "[dim green](fresh)[/]"
    
    header = Panel(
        f"[bold info]Package:[/bold info] [info]{package}[/info]@[version]{version or 'latest'}[/version] {source_tag}\n"
        f"Score: [bold {color}]{score}/100[/] | Risk: [bold {color}]{risk_level}[/]",
        title="[bold blue]OS³ Score Report[/bold blue]",
        border_style=color,
        expand=False,
        padding=(0, 2)
    )
    console.print(header)
    console.print()

    # 3. Explanations Tree
    tree = Tree("[bold underline blue]Detailed Security Audit[/]", guide_style="blue")
    
    breakdown = report_data.get("signal_breakdown", {})
    
    # Group Signals under a Node
    if risk_level == "SUPPRESSED":
        signals = tree.add("[bold cyan]Audit status: SUPPRESSED[/]")
        signals.add(f"[dim]Initial score was {score}, but developer suppressed manually.[/]")
    else:
        signals = tree.add("[bold magenta]Signals Breakdown[/]")
        
        # 3.1 CVEs
        penalty_cve = 100 - breakdown.get("cve_score", 100)
        vuln_color = "red" if vulns else "green"
        cve_node = signals.add(f"CVEs: [bold {vuln_color}]{len(vulns)} detected[/] [dim yellow](-{penalty_cve} pts)[/]")
        for v in vulns[:3]:
            cve_node.add(f"[dim red]{v}[/]")
            
        # 3.2 Depth
        depth = report_data.get("dep_depth", 0)
        penalty_depth = 100 - breakdown.get("depth_score", 100)
        depth_color = "red" if depth > 10 else "yellow" if depth > 5 else "green"
        signals.add(f"Depth: [{depth_color}]{depth} levels[/{depth_color}] [dim yellow](-{penalty_depth} pts)[/]")
        
        # 3.3 Popularity
        p_anomaly = report_data.get("popularity_anomaly", 1.0)
        penalty_pop = 100 - breakdown.get("popularity_score", 100)
        p_color = "red" if p_anomaly > 2.5 else "green"
        signals.add(f"Popularity: [{p_color}]{p_anomaly:.1f}x spike[/{p_color}] [dim yellow](-{penalty_pop} pts)[/]")
        
        # 3.4 License
        lic = report_data.get("license_spdx", "Unknown")
        if isinstance(lic, str):
            lic = lic.strip()
            if "\n" in lic:
                lic = lic.splitlines()[0].strip()
            if len(lic) > 60:
                lic = lic[:57].rstrip() + "..."
        penalty_lic = 100 - breakdown.get("license_score", 100)
        # Use simple string check for OSI in explanations
        has_osi = any("OSI-approved" in str(e) for e in explanations)
        lic_color = "green" if has_osi else "yellow"
        signals.add(f"License: [{lic_color}]{lic}[/{lic_color}] [dim yellow](-{penalty_lic} pts)[/]")

    # Detail Logs
    audit_node = tree.add("[bold cyan]Audit Journal[/]")
    for exp in explanations:
        audit_node.add(exp)
        
    console.print(tree)
    if risk_level == "LOW" and score >= 90:
        console.print("[success]Overall: Healthy package - Recommended for usage.[/success]")
    elif risk_level == "SUPPRESSED":
        console.print("[info]Overall: Package suppressed by developer policy.[/info]")
    console.print()

    # 4. Alternatives Table
    table = Table(title="[bold blue]Safer Alternatives[/bold blue]", show_header=True, header_style="bold blue", border_style="blue")
    table.add_column("Package", style="info")
    table.add_column("Score", justify="center")
    table.add_column("Why Better")

    for alt in alternatives:
        alt_color = "green" if alt["score"] >= 80 else "yellow" if alt["score"] >= 60 else "red"
        impact = f"[green]{alt.get('delta', '')}[/]"
        table.add_row(f"{alt['package']} {impact}", f"[{alt_color}]{alt['score']}[/]", alt["why"])
    
    console.print(table)

@app.command()
def scan(
    file_path: str = typer.Argument(..., help="Path to the requirements.txt file to scan."),
    force_refresh: bool = typer.Option(False, "--force-refresh", "-f", help="Ignore cache and fetch fresh data."),
    json_output: bool = typer.Option(False, "--json", help="Output results in JSON format."),
    suppress_generate: bool = typer.Option(False, "--suppress-generate", "-sg", help="Interactively generate suppressions for high-risk items."),
):
    """
    🔍 [bold cyan]Scan a dependency file for security risks.[/bold cyan]
    """
    path = Path(file_path)
    if not path.exists():
        console.print(f"[error]File not found: {file_path}[/error]")
        raise typer.Exit(1)
        
    with console.status(f"[bold blue]Scanning [info]{file_path}[/info]...") as status:
        try:
            scan_data = scan_module.scan_file(file_path, force_refresh)
        except Exception as e:
            console.print(f"[error]Error scanning file: {str(e)}[/error]")
            raise typer.Exit(1)
            
    if json_output:
        import sys
        # Clean the output to ensure only JSON is printed
        console.print_json(data=scan_data)
        return
            
    results = scan_data["results"]
    summary = scan_data["summary"]
    
    # 1. Summary Panel
    avg_score_color = "green" if summary["avg_score"] >= 80 else "yellow" if summary["avg_score"] >= 55 else "red"
    
    ecosystem_str = " | ".join([f"{eco.upper()}: {count}" for eco, count in summary.get("ecosystem_counts", {}).items()])
    
    summary_text = (
        f"Packages Scanned: [bold white]{summary['total_packages']}[/] ({ecosystem_str})\n"
        f"Average Project Score: [bold {avg_score_color}]{summary['avg_score']}/100[/]\n"
        f"Risk Breakdown: [green]LOW: {summary['risk_counts']['LOW']}[/] | "
        f"[yellow]MED: {summary['risk_counts']['MEDIUM']}[/] | "
        f"[red]HIGH: {summary['risk_counts']['HIGH']}[/]"
    )
    
    console.print(
        Panel(
            summary_text,
            title="[bold cyan]OS³ Project Scan Results[/bold cyan]",
            border_style="cyan",
            expand=False,
            padding=(1, 2)
        )
    )
    
    # Critical Risk Warning
    if summary["high_risk_found"]:
        console.print(
            Panel(
                "[bold]⚠️ CRITICAL: High-risk packages detected in your project![/]\n"
                "Check the details below and consider updating or replacing them.",
                style="on red",
                expand=True
            )
        )
    console.print()
    
    # 2. Results Table
    table = Table(title="[bold cyan]Detailed Package Audit[/bold cyan]", show_header=True, header_style="bold cyan", border_style="cyan")
    table.add_column("Package", style="info")
    table.add_column("Ecosystem", style="bold magenta")
    table.add_column("Version", style="version")
    table.add_column("Score", justify="center")
    table.add_column("Risk", justify="center")
    table.add_column("Key Findings")
    
    for r in results:
        ecosystem = r.get("ecosystem", "pypi").upper()
        if "error" in r:
            table.add_row(r["name"], ecosystem, r["version"], "[red]ERR[/]", "[red]ERROR[/]", f"[error]Failed to audit: {r['error']}[/error]")
            continue
            
        sd = r["score_data"]
        score = sd.get("score", 0)
        risk = sd.get("risk_level", "UNKNOWN")
        
        if risk == "SUPPRESSED":
            color = "dim cyan"
            findings = f"[S] {sd.get('explanations', ['Suppressed'])[-1]}"
        else:
            color = "green" if score >= 80 else "yellow" if score >= 55 else "red"
            vuln_count = len(sd.get("vulns", []))
            findings = f"[red]{vuln_count} Vulns Found[/]" if vuln_count > 0 else (sd.get("explanations", ["OK"])[0] if sd.get("explanations") else "No issues")
        
        table.add_row(
            r["name"],
            ecosystem,
            r["version"],
            f"[{color}]{score}[/]",
            f"[{color}]{risk}[/]",
            findings
        )
        
    console.print(table)
    
    # 3. Safer Options: per-package tree with sub-table or tree (green for good alts)
    risky_pkgs = [r for r in results if "score_data" in r and (r["score_data"]["score"] < 70 or r["score_data"]["risk_level"] == "HIGH")]
    if risky_pkgs:
        console.print()
        tree = Tree("[bold yellow]💡 Safer alternative suggestions[/bold yellow]", guide_style="yellow")
        for r in risky_pkgs:
            recs = r.get("recommendations", [])
            score = r["score_data"]["score"]
            node = tree.add(f"[bold info]{r['name']}[/bold info] @ {r['version']} — Score: [red]{score}[/]")
            if recs:
                for alt in recs:
                    delta = alt["score"] - score
                    color = "green" if alt["score"] >= 80 else "yellow"
                    node.add(
                        f"[success]{alt['package']}[/success]  "
                        f"[bold green]+{delta} better[/]  "
                        f"[dim white]{alt['why'][:70]}{'…' if len(alt['why']) > 70 else ''}[/]  "
                        f"[italic cyan]({alt.get('smarter_signals', 'Data-backed')})[/]"
                    )
            else:
                eco = r.get("ecosystem", "pypi").lower()
                if eco == "pypi":
                    node.add("[dim italic]Consider modern alternatives like httpx, fastapi, pydantic, aiohttp.[/]")
                else:
                    node.add("[dim italic]Consider modern alternatives like fastify, axios, zod, undici.[/]")
        console.print(tree)

    # 4. Interactive Suppression Generation
    if suppress_generate:
        high_risks = [r for r in results if r.get("score_data", {}).get("risk_level") == "HIGH"]
        if high_risks:
            console.print("\n[bold yellow]--- Interactive Suppression Generator ---[/bold yellow]")
            for r in high_risks:
                if Confirm.ask(f"Suppress high-risk package [bold]{r['name']}[/]?"):
                    reason = Prompt.ask("Reason for suppression", default="Reviewed safety")
                    item = {
                        "package": r["name"],
                        "ecosystem": r.get("ecosystem", "pypi"),
                        "reason": reason,
                        "suppress_all": True,
                        "cves": [],
                        "version_range": "*"
                    }
                    suppress.save_suppression(item, local=True)
                    console.print(f"[success]Suppression added to .os3/suppress.toml[/success]")
        else:
            console.print("\n[info]No high-risk packages to suppress.[/info]")

@app.command(context_settings={"allow_extra_args": True, "ignore_unknown_options": True})
def install(
    ctx: typer.Context,
    packages: list[str] = typer.Argument(None, help="Package(s) to install, e.g. requests httpx==0.30.0"),
    requirements: str = typer.Option(None, "-r", "--requirements", help="Path to requirements.txt"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Show warning but don't install"),
    no_warn: bool = typer.Option(False, "--no-warn", "-y", "--yes", help="Skip warning and install directly"),
    force_refresh: bool = typer.Option(False, "--force-refresh", help="Ignore cache for scoring"),
):
    """
    📦 [bold yellow]Securely install packages with a pre-install security audit.[/bold yellow]
    Acts as a wrapper for [bold blue]pip install[/bold blue] but scores packages first.
    """
    # 1. Collect all packages to score
    to_score = []
    pip_args = []
    
    # Process -r requirements.txt
    if requirements:
        req_path = Path(requirements)
        if req_path.exists():
            pip_args.extend(["-r", str(req_path)])
            req_deps = scan_module.parse_pip_requirements(str(req_path))
            to_score.extend(req_deps)
        else:
            console.print(f"[error]Requirements file not found: {requirements}[/error]")
            raise typer.Exit(1)
            
    # Process direct package arguments
    if packages:
        pip_args.extend(packages)
        for pkg in packages:
            # Simple parsing for name==version
            name = pkg.split('==')[0].split('>=')[0].split('<=')[0].split('~=')[0].split('[')[0]
            version = None
            if '==' in pkg:
                version = pkg.split('==')[1].split()[0]
            to_score.append({"name": name, "version": version, "ecosystem": "pypi"})

    # Add extra flags passed to os3 install (typer puts them in ctx.args)
    pip_args.extend(ctx.args)
    
    if not to_score:
        console.print("[warning]No packages specified for installation.[/warning]")
        return

    # 2. Score packages
    engine = scorer.ScoringEngine()
    results = []
    with console.status("[bold blue]Performing pre-install security audit...") as status:
        for dep in to_score:
            name = dep["name"]
            version = dep["version"]
            try:
                score_data = engine.score_package("pypi", name, version, force_refresh=force_refresh)
                
                # Check for alternatives if risky
                recs = []
                if score_data["score"] < 70 or score_data["risk_level"] == "HIGH":
                    from os3 import alternatives
                    recs = alternatives.get_alternatives("pypi", name, score_data["score"], engine=engine)
                
                results.append({
                    "name": name,
                    "version": version or "latest",
                    "score_data": score_data,
                    "recommendations": recs
                })
            except Exception as e:
                results.append({"name": name, "version": version or "latest", "error": str(e)})

    # 3. Analyze Risks
    high_risks = [r for r in results if r.get("score_data", {}).get("risk_level") == "HIGH"]
    med_risks = [r for r in results if r.get("score_data", {}).get("risk_level") == "MEDIUM"]
    total_risks = len(high_risks) + len(med_risks)
    
    # If no_warn or no risks, proceed immediately
    if no_warn or total_risks == 0:
        if dry_run:
            console.print("[info]Dry run: Package check passed with no significant risks.[/info]")
            return
        run_pip_install(pip_args)
        return

    # 4. Show Warning UI
    avg_score = sum(r["score_data"]["score"] for r in results if "score_data" in r) / len([r for r in results if "score_data" in r])
    
    summary_panel = Panel(
        f"Security Audit: [bold white]{len(results)} packages[/] | Avg Score: [bold]{avg_score:.1f}[/]\n"
        f"Risks Detected: [red]{len(high_risks)} HIGH[/], [yellow]{len(med_risks)} MEDIUM[/]",
        title="[bold yellow]⚠️ OS³ Security Warning[/bold yellow]",
        border_style="yellow",
        expand=False
    )
    console.print(summary_panel)
    
    # Details table
    table = Table(box=None, show_header=True, header_style="bold")
    table.add_column("Package")
    table.add_column("Score", justify="center")
    table.add_column("Risk")
    table.add_column("Primary Reason")
    
    for r in results:
        sd = r.get("score_data", {})
        score = sd.get("score", 0)
        risk = sd.get("risk_level", "UNKNOWN")
        color = "red" if risk == "HIGH" else "yellow" if risk == "MEDIUM" else "green"
        reason = sd.get("explanations", ["Checked"])[0] if sd.get("explanations") else "OK"
        table.add_row(r["name"], f"[{color}]{score}[/]", f"[{color}]{risk}[/]", reason)
    
    console.print(table)
    
    # Show recommendations if any
    for r in results:
        if r.get("recommendations"):
            console.print(f"\n[bold yellow]Smarter Alternatives for {r['name']}:[/]")
            for alt in r["recommendations"]:
                delta = alt['score'] - r['score_data']['score']
                console.print(f"  ➜ [success]{alt['name']}[/success] (Score: {alt['score']} [green]+{delta}[/]) - {alt['why']}")

    if dry_run:
        console.print("\n[info]Dry run: Installation halted due to detected risks.[/info]")
        return

    # 5. Countdown and Prompt
    console.print()
    proceed = False
    try:
        count = 10
        with Live(console=console, refresh_per_second=4) as live:
            while count > 0:
                live.update(f"[bold yellow]Proceeding with installation in {count} seconds...[/] [dim](Ctrl+C to cancel, Enter to skip wait)[/]")
                time.sleep(1)
                count -= 1
        proceed = True
    except KeyboardInterrupt:
        console.print("\n[red]Installation cancelled by user.[/red]")
        raise typer.Exit(0)

    if proceed:
        action = Prompt.ask("\n[bold]Action?[/]", choices=["y", "n", "s"], default="y")
        if action == "y":
            run_pip_install(pip_args)
        elif action == "s":
            # Switch logic
            pkg_to_replace = Prompt.ask("Which package would you like to replace?")
            new_pkg = Prompt.ask("Enter the alternative package name")
            # Update pip_args
            updated_args = [arg.replace(pkg_to_replace, new_pkg) for arg in pip_args]
            run_pip_install(updated_args)
        else:
            console.print("[yellow]Installation aborted.[/yellow]")

def run_pip_install(args: list[str]):
    """Execute the actual pip install command."""
    cmd = [sys.executable, "-m", "pip", "install"] + args
    console.print(f"[dim]Running: {' '.join(cmd)}[/dim]")
    try:
        # We run as a subprocess and stream output
        subprocess.run(cmd, check=True)
        console.print("\n[success]✨ Installation completed successfully.[/success]")
    except subprocess.CalledProcessError as e:
        console.print(f"\n[error]pip install failed with exit code {e.returncode}[/error]")
        raise typer.Exit(e.returncode)

@app.command()
def reasoning(
    package: str = typer.Argument(..., help="The package name to analyze."),
    ecosystem: str = typer.Option("pypi", "--ecosystem", "-e", help="The ecosystem (e.g., pypi, npm)."),
    force_refresh: bool = typer.Option(False, "--force-refresh", "-f", help="Ignore cache for scoring"),
):
    """
    🧠 [bold info]Deep dive into the security reasoning and signals for a package.[/bold info]
    Provides a granular breakdown of data points from OS3 and deps.dev Insights.
    """
    engine = scorer.ScoringEngine()
    from os3 import deps_dev
    
    with console.status(f"[bold blue]Deeply analyzing [info]{package}[/info]...") as status:
        try:
            os3_data = engine.score_package(ecosystem, package, force_refresh=force_refresh)
            dd_data = deps_dev.query_deps_dev(package, ecosystem)
            dd_score_info = deps_dev.get_package_score_from_deps_dev(dd_data)
        except Exception as e:
            console.print(f"[error]Analysis failed: {str(e)}[/error]")
            raise typer.Exit(1)
            
    if not os3_data:
        console.print(f"[error]Could not find data for {package}[/error]")
        raise typer.Exit(1)

    # 1. Header
    console.print(Panel(f"[bold blue]Deep Reasoning Audit:[/bold blue] [info]{package}[/info]", border_style="blue"))

    # 2. OS3 Signals (Maintenance & Vulns)
    os3_tree = Tree("[bold magenta]🛡️ OS3 Internal Audit[/bold magenta]")
    os_score = os3_data.get('score', 0)
    os3_tree.add(f"Score: [bold green]{os_score}/100[/]")
    os3_tree.add(f"Risk Level: [bold]{os3_data.get('risk_level', 'UNKNOWN')}[/]")
    
    maint_node = os3_tree.add("Maintenance Status")
    if os3_data.get("last_release"):
        maint_node.add(f"Last Release: [cyan]{os3_data['last_release']}[/]")
    for exp in os3_data.get("explanations", []):
        if any(w in exp.lower() for w in ["maintenance", "active", "abandonment"]):
            maint_node.add(exp)
            
    vuln_node = os3_tree.add(f"Vulnerability Signals ([red]{len(os3_data.get('vulns', []))}[/])")
    for v in os3_data.get("vulns", [])[:5]:
        vuln_node.add(f"[dim]{v}[/]")

    console.print(os3_tree)
    console.print()

    # 3. deps.dev Signals (Insights)
    dd_tree = Tree("[bold cyan]🔍 Open Source Insights (deps.dev)[/bold cyan]")
    if dd_score_info:
        dd_score, dd_exps = dd_score_info
        dd_tree.add(f"Data Significance: [bold green]High[/]")
        signals_node = dd_tree.add("Key Signals")
        for exp in dd_exps:
            signals_node.add(exp)
            
        if dd_data:
            versions = dd_data.get("versions", [])
            dd_tree.add(f"Version Count: [white]{len(versions)}[/]")
            if versions:
                default_v = next((v for v in versions if v.get("isDefault")), versions[0])
                dd_tree.add(f"License: [white]{', '.join(default_v.get('licenses', ['Unknown']))}[/]")
    else:
        dd_tree.add("[italic white]No deep insights found in deps.dev database for this package.[/]")

    console.print(dd_tree)
    
    # 4. Final Verdict
    final_score = os_score
    if dd_score_info:
        final_score = round((os_score * 0.7) + (dd_score_info[0] * 0.3))
    
    console.print(f"\n[bold underline]Weighted Intelligence Verdict:[/bold underline] [bold]{final_score}/100[/]")
    if final_score < 70:
        console.print("[red]Verdict: Recommendation is to evaluate alternatives or strictly pin versions.[/red]")
    else:
        console.print("[green]Verdict: Package appears healthy and well-maintained.[/green]")

@app.command()
def sync(
    full: bool = typer.Option(False, "--full", help="Refresh all popular packages in addition to stale ones."),
    quiet: bool = typer.Option(False, "--quiet", help="Suppress progress output."),
):
    """
    🔄 [bold green]Synchronize vulnerabilities and refresh stale cache entries.[/bold green]
    """
    sync_module.sync_all(full=full, quiet=quiet)

# Suppress command group
suppress_app = typer.Typer(help="🛡️ Manage security risk suppressions.")
app.add_typer(suppress_app, name="suppress")

# Cache command group
cache_app = typer.Typer(help="💾 Manage the local package cache.")
app.add_typer(cache_app, name="cache")

@cache_app.command("clear")
def cache_clear(
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt."),
):
    """
    🗑️ [bold red]Clear all cached package data.[/bold red]
    
    This will remove all cached scores and metadata, forcing fresh data on next requests.
    """
    if not confirm:
        if not typer.confirm("Are you sure you want to clear all cached data? This cannot be undone."):
            console.print("[dim]Operation cancelled.[/dim]")
            return
    
    cache.clear_all_cache()
    console.print("[success]Cache cleared successfully![/success]")

@cache_app.command("refresh-all")
def cache_refresh_all(
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress progress output."),
):
    """
    🔄 [bold green]Refresh all cached package data.[/bold green]
    
    This will update all cached packages with fresh data from registries.
    Equivalent to running 'os3 sync --full'.
    """
    sync_module.sync_all(full=True, quiet=quiet)

@suppress_app.command("add")
def suppress_add(
    package: str = typer.Argument(..., help="Package name to suppress."),
    ecosystem: str = typer.Option("pypi", "--ecosystem", "-e", help="Ecosystem (pypi, npm, maven)."),
    reason: str = typer.Option("Reviewed, safe", "--reason", "-r", help="Reason for suppression."),
    cve: list[str] = typer.Option(None, "--cve", help="Specific CVE(s) to suppress."),
    all_versions: bool = typer.Option(False, "--all", help="Suppress all versions of this package."),
    expires: str = typer.Option(None, "--expires", help="Expiration date (YYYY-MM-DD)."),
    local: bool = typer.Option(False, "--local", help="Save to local .os3/suppress.toml instead of global."),
):
    """Add a new security suppression."""
    item = {
        "package": package,
        "ecosystem": ecosystem,
        "reason": reason,
        "suppress_all": all_versions,
        "version_range": "*" if all_versions else "latest"
    }
    if cve: item["cves"] = cve
    if expires: item["expires"] = expires
    
    suppress.save_suppression(item, local=local)
    console.print(f"[success]Added suppression for [bold]{package}[/bold] ({ecosystem})[/success]")

@suppress_app.command("list")
def suppress_list(
    ecosystem: str = typer.Option(None, "--ecosystem", "-e", help="Filter by ecosystem."),
    project_only: bool = typer.Option(False, "--project", help="Show only local project suppressions.")
):
    """List all active suppressions."""
    if project_only:
        items = []
        if Path(".os3/suppress.toml").exists():
             with open(".os3/suppress.toml", "rb") as f:
                 import tomli
                 items = tomli.load(f).get("suppressions", [])
    else:
        items = suppress.load_suppressions()
    if not items:
        console.print("[dim]No suppressions found.[/dim]")
        return
        
    table = Table(title="Security Suppressions", show_header=True, header_style="bold cyan")
    table.add_column("Package")
    table.add_column("Ecosystem")
    table.add_column("Reason")
    table.add_column("Type")
    
    for s in items:
        if ecosystem and s.get("ecosystem") != ecosystem:
            continue
        stype = "All versions" if s.get("suppress_all") else (f"CVEs: {', '.join(s.get('cves', []))}" if s.get("cves") else "Selected version")
        table.add_row(s.get("package"), s.get("ecosystem"), s.get("reason"), stype)
        
    console.print(table)

@suppress_app.command("remove")
def suppress_remove(
    package: str = typer.Argument(..., help="Package name to remove suppressions for."),
    ecosystem: str = typer.Option(None, "--ecosystem", "-e"),
):
    """Remove suppressions for a package."""
    suppress.remove_suppression(package, ecosystem)
    console.print(f"[success]Removed suppressions for [bold]{package}[/bold][/success]")

@suppress_app.command("generate")
def suppress_generate(
    scan_file: str = typer.Option(None, "--from-scan", help="Scan a file and interactively suppress high-risk findings.")
):
    """Interactively generate suppressions from a scan file."""
    if not scan_file:
        console.print("[warning]Please provide a scan file via --from-scan[/warning]")
        return
        
    path = Path(scan_file)
    if not path.exists():
        console.print(f"[error]File not found: {scan_file}[/error]")
        return
        
    with console.status(f"[bold blue]Scanning [info]{scan_file}[/info]...") as status:
        scan_data = scan_module.scan_file(scan_file)
        
    high_risks = [r for r in scan_data["results"] if r.get("score_data", {}).get("risk_level") == "HIGH"]
    if not high_risks:
        console.print("[success]No high-risk packages to suppress![/success]")
        return
        
    for r in high_risks:
        if Confirm.ask(f"Suppress high-risk package [bold]{r['name']}[/]?"):
            reason = Prompt.ask("Reason for suppression", default="Developer reviewed, safe")
            expires = Prompt.ask("Expiration date (YYYY-MM-DD, Optional)", default="")
            item = {
                "package": r["name"],
                "ecosystem": r.get("ecosystem", "pypi"),
                "reason": reason,
                "suppress_all": True,
                "cves": [],
                "version_range": "*",
                "expires": expires if expires else None
            }
            suppress.save_suppression(item, local=True)
            console.print(f"[success]Suppression added locally.[/success]")

@app.command()
def status():
    """
    📊 [bold blue]Display current cache height and synchronization status.[/bold blue]
    """
    stats = sync_module.get_status()
    
    last_sync = stats.get("last_sync", "Never")
    if last_sync and last_sync != "Never":
        try:
            ls_dt = datetime.fromisoformat(last_sync.replace("Z", "+00:00"))
            time_diff = datetime.now() - ls_dt
            last_sync = f"{last_sync} ({time_diff.days}d ago)"
        except Exception:
            pass

    panel_content = (
        f"Cache Path: [dim]{cache.DB_PATH}[/dim]\n"
        f"Total Packages: [bold]{stats['total_packages']}[/]\n"
        f"Last Activity: [white]{last_sync}[/]\n"
        "\n[bold underline]Ecosystem Coverage:[/bold underline]\n"
    )
    
    for eco, count in stats.get("ecosystems", {}).items():
        panel_content += f"  - {eco.upper()}: {count}\n"
        
    console.print(Panel(panel_content, title="[bold blue]OS³ Cache Status[/bold blue]", border_style="blue", expand=False))

@app.command()
def tui():
    """
    🖥️ [bold magenta]Launch the OS³ Terminal User Interface.[/bold magenta]
    """
    from os3.tui import OS3Tui
    app_tui = OS3Tui()
    app_tui.run()

@app.command()
def version():
    """
    Display the current version of os3.
    """
    display_version()

if __name__ == "__main__":
    app()
