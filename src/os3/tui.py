import json
import requests
import traceback
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Input, Button, Static, Markdown, ListItem, ListView, Label, TabbedContent, TabPane, DataTable
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual import work
from rich.panel import Panel
from rich.tree import Tree
from rich.table import Table
from rich.text import Text
from rich.console import Group

from os3.scorer import ScoringEngine
from os3 import scan as scan_module
from os3 import suppress
from os3 import sync as sync_module
from os3 import deps_dev

class PackageReport(Static):
    """A widget to display the scoring report for a package."""
    pass

class ScanReport(Static):
    """A widget to display the scan summary."""
    pass

class StatusReport(Static):
    """A widget to display the status."""
    pass

class OS3Tui(App):
    """The TUI for OS³ Security Dashboard."""
    
    TITLE = "OS³ Security Dashboard"
    CSS = """
    Screen {
        background: $surface-darken-1;
    }
    
    #main-container {
        height: 100%;
        width: 100%;
    }

    #sidebar {
        width: 30;
        height: 100%;
        dock: left;
        background: $panel;
        border-right: solid $primary;
    }

    #sidebar-title {
        padding: 1 2;
        text-style: bold;
        color: $accent;
        background: $surface-lighten-1;
    }

    .action-area {
        height: auto;
        padding: 1 2;
        background: $surface;
        border-bottom: solid $primary-lighten-2;
    }

    .form-row {
        height: auto;
        width: 100%;
        align: center middle;
    }

    .stretch-input {
        width: 1fr;
        margin-right: 1;
    }
    
    .short-input {
        width: 20%;
        margin-right: 1;
    }

    .action-button {
        width: 15%;
        background: $primary;
        color: $text;
        margin-right: 1;
    }
    
    #reasoning-button {
        background: $accent;
    }

    .scroll-area {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    
    .status-msg {
        text-align: center;
        padding: 2;
        color: $text-muted;
    }
    
    #scan-table {
        margin-top: 1;
        height: 1fr;
    }
    
    #suppress-table {
        margin-top: 1;
        height: 1fr;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("d", "toggle_dark", "Toggle Dark Mode"),
        ("ctrl+c", "quit", "Quit"),
    ]

    def __init__(self):
        super().__init__()
        self.history = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        
        with Horizontal(id="main-container"):
            # Sidebar
            with Vertical(id="sidebar"):
                yield Label("Recent Scans", id="sidebar-title")
                yield ListView(id="history-list")
            
            # Main Area
            with Vertical(id="content-area"):
                with TabbedContent(initial="tab-score"):
                    # Tab 1: Score & Reasoning
                    with TabPane("Score Dashboard", id="tab-score"):
                        with Vertical(classes="action-area"):
                            with Horizontal(classes="form-row"):
                                yield Input(placeholder="Package name (e.g. requests)", id="package-input", classes="stretch-input")
                                yield Input(value="pypi", placeholder="Ecosystem", id="ecosystem-input", classes="short-input")
                                yield Button("Score", id="score-button", classes="action-button", variant="primary")
                                yield Button("Reasoning", id="reasoning-button", classes="action-button")
                        
                        with VerticalScroll(classes="scroll-area"):
                            yield Static("Welcome! Enter a package above to begin security analysis.", classes="status-msg", id="welcome-msg")
                            yield PackageReport(id="report-container")
                    
                    # Tab 2: Project Scan
                    with TabPane("Project Scan", id="tab-scan"):
                        with Vertical(classes="action-area"):
                            with Horizontal(classes="form-row"):
                                yield Input(value="requirements.txt", placeholder="Path to requirements.txt", id="scan-input", classes="stretch-input")
                                yield Button("Scan Project", id="scan-button", classes="action-button", variant="primary")
                        
                        with VerticalScroll(classes="scroll-area"):
                            yield ScanReport(id="scan-report-container")
                            yield DataTable(id="scan-table")
                    
                    # Tab 3: Suppressions
                    with TabPane("Suppressions", id="tab-suppress"):
                        with Vertical(classes="action-area"):
                            with Horizontal(classes="form-row", id="suppress-row-1"):
                                yield Input(placeholder="Package name", id="sup-pkg", classes="stretch-input")
                                yield Input(placeholder="Reason", value="Reviewed, safe", id="sup-reason", classes="stretch-input")
                            with Horizontal(classes="form-row", id="suppress-row-2"):
                                yield Input(value="pypi", placeholder="Ecosystem", id="sup-eco", classes="short-input")
                                yield Button("Add Suppression", id="sup-add-button", classes="action-button", variant="success")
                                yield Button("Remove Package", id="sup-rem-button", classes="action-button", variant="error")
                        
                        with VerticalScroll(classes="scroll-area"):
                            yield DataTable(id="suppress-table")
                            
                    # Tab 4: System Status
                    with TabPane("System Status", id="tab-status"):
                        with Vertical(classes="action-area"):
                            with Horizontal(classes="form-row"):
                                yield Button("Refresh Stats", id="status-refresh-button", classes="action-button")
                                yield Button("Force Sync DB", id="status-sync-button", classes="action-button", variant="warning")
                                
                        with VerticalScroll(classes="scroll-area"):
                            yield StatusReport(id="status-container")
                    
        yield Footer()

    def on_mount(self):
        self.query_one("#package-input").focus()
        
        # Setup Scan Table
        scan_table = self.query_one("#scan-table", DataTable)
        scan_table.add_columns("Package", "Version", "Score", "Risk Level", "Findings")
        
        # Setup Suppress Table
        sup_table = self.query_one("#suppress-table", DataTable)
        sup_table.add_columns("Package", "Ecosystem", "Reason", "Type")
        
        # Initial loads
        self.refresh_suppress_table()
        self.refresh_status()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "score-button":
            self.trigger_score(reasoning=False)
        elif btn_id == "reasoning-button":
            self.trigger_score(reasoning=True)
        elif btn_id == "scan-button":
            self.trigger_scan()
        elif btn_id == "sup-add-button":
            self.trigger_suppress_add()
        elif btn_id == "sup-rem-button":
            self.trigger_suppress_remove()
        elif btn_id == "status-refresh-button":
            self.refresh_status()
        elif btn_id == "status-sync-button":
            self.trigger_sync()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id in ["package-input", "ecosystem-input"]:
            self.trigger_score(reasoning=False)
        elif event.input.id == "scan-input":
            self.trigger_scan()

    # --- SCORE & REASONING LOGIC ---
    
    def trigger_score(self, reasoning=False) -> None:
        package = self.query_one("#package-input", Input).value.strip()
        ecosystem = self.query_one("#ecosystem-input", Input).value.strip()
        
        if not package:
            return
            
        try:
            self.query_one("#welcome-msg").remove()
        except Exception:
            pass
            
        report_container = self.query_one("#report-container", PackageReport)
        action = "Deep analyzing" if reasoning else "Auditing"
        report_container.update(Panel(f"{action} [bold cyan]{package}[/bold cyan] in {ecosystem}...", border_style="cyan", padding=(1, 2)))
        
        self.run_score(package, ecosystem, reasoning)

    @work(exclusive=True, thread=True)
    def run_score(self, package: str, ecosystem: str, reasoning: bool) -> None:
        try:
            engine = ScoringEngine()
            report_data = engine.score_package(ecosystem, package, force_refresh=True)
            if not report_data:
                self.call_from_thread(self.show_error, "#report-container", f"Could not find data for {package} in {ecosystem}")
                return
                
            if reasoning:
                try:
                    dd_data = deps_dev.query_deps_dev(package, ecosystem)
                    dd_score_info = deps_dev.get_package_score_from_deps_dev(dd_data)
                    self.call_from_thread(self.show_reasoning_results, package, ecosystem, report_data, dd_data, dd_score_info)
                except Exception as e:
                    self.call_from_thread(self.show_error, "#report-container", f"Reasoning API Error: {e}")
            else:
                self.call_from_thread(self.show_results, package, ecosystem, report_data)
        except Exception as e:
            self.call_from_thread(self.show_error, "#report-container", f"Error calculating score: {e}\n{traceback.format_exc()}")

    def show_error(self, container_id: str, message: str) -> None:
        container = self.query_one(container_id)
        container.update(Panel(f"[bold red]Error:[/bold red] {message}", border_style="red", padding=(1, 2)))

    def show_results(self, package: str, ecosystem: str, report_data: dict) -> None:
        try:
            score = report_data.get("score", 0)
            risk_level = report_data.get("risk_level", "UNKNOWN")
            explanations = report_data.get("explanations", [])
            alternatives = report_data.get("alternatives", [])
            vulns = report_data.get("vulns", [])

            # Color coding
            color = "green" if score >= 80 else "yellow" if score >= 55 else "red"
            if risk_level == "SUPPRESSED":
                color = "cyan"

            renderables = []

            # 1. Header Panel
            header = Panel(
                f"[bold info]Package:[/bold info] [info]{package}[/info]  |  [bold info]Ecosystem:[/bold info] [info]{ecosystem}[/info]\n"
                f"Overall Score: [bold {color}]{score}/100[/] | Risk Level: [bold {color}]{risk_level}[/]",
                title="[bold blue]OS³ Real-Time Security Audit[/bold blue]",
                border_style=color,
                padding=(1, 2)
            )
            renderables.append(header)
            renderables.append(Text("")) # Spacer

            # 2. Detailed Tree
            tree = Tree(f"[bold underline blue]Signals Blueprint[/bold underline blue]", guide_style="blue")
            if risk_level == "SUPPRESSED":
                tree.add("[bold cyan]Audit status: SUPPRESSED by policy[/]")
            else:
                signals = tree.add(f"[bold magenta]Health Vectors[/bold magenta]")
                # CVE
                vuln_color = "red" if vulns else "green"
                cve_node = signals.add(f"CVEs: [bold {vuln_color}]{len(vulns)} detected[/]")
                for v in vulns[:5]:
                    cve_node.add(f"[dim red]{v}[/]")
                # Depth
                depth = report_data.get("dep_depth", 0)
                depth_color = "red" if depth > 10 else "yellow" if depth > 5 else "green"
                signals.add(f"Graph Depth: [{depth_color}]{depth} levels[/{depth_color}]")
                # Popularity
                p_anomaly = report_data.get("popularity_anomaly", 1.0)
                p_color = "red" if p_anomaly > 2.5 else "green"
                signals.add(f"Popularity: [{p_color}]{p_anomaly:.1f}x spike/drop[/{p_color}]")
                # License
                lic = report_data.get("license_spdx", "Unknown")
                has_osi = any("OSI-approved" in str(e) for e in explanations)
                lic_color = "green" if has_osi else "yellow"
                signals.add(f"License: [{lic_color}]{lic}[/{lic_color}]")

            audit_node = tree.add("[bold cyan]Agentic Journal Logs[/bold cyan]")
            for exp in explanations:
                # Parse Rich markup tags from scorer explanations for proper colored output.
                audit_node.add(Text.from_markup(exp, style="italic"))

            renderables.append(tree)
            renderables.append(Text(""))

            # 3. Alternatives Table
            if alternatives:
                table = Table(title="[bold blue]Data-Backed Recommendations[/bold blue]", show_header=True, header_style="bold blue", border_style="blue", expand=True)
                table.add_column("Alternative", style="cyan", no_wrap=True)
                table.add_column("Score Impact", justify="center")
                table.add_column("Why this is suggested")

                for alt in alternatives:
                    alt_color = "green" if alt["score"] >= 80 else "yellow" if alt["score"] >= 60 else "red"
                    impact = f"[green]{alt.get('delta', '')}[/]" if "+" in str(alt.get('delta', '')) else str(alt.get('delta', ''))
                    table.add_row(
                        f"{alt['package']} {impact}", 
                        f"[{alt_color}]{alt['score']}[/]", 
                        alt["why"]
                    )
                renderables.append(table)

            container = self.query_one("#report-container", PackageReport)
            container.update(Group(*renderables))
            
            self.add_to_history(package, ecosystem)
        except Exception as e:
            self.show_error("#report-container", f"UI Error: {e}")

    def show_reasoning_results(self, package: str, ecosystem: str, os3_data: dict, dd_data: dict, dd_score_info: tuple) -> None:
        try:
            renderables = []
            renderables.append(Panel(f"[bold blue]Deep Reasoning Audit:[/bold blue] [info]{package}[/info]", border_style="blue"))
            renderables.append(Text(""))
            
            # OS3 Signals
            os3_tree = Tree("[bold magenta]OS3 Internal Audit[/bold magenta]")
            os_score = os3_data.get('score', 0)
            os3_tree.add(f"Score: [bold green]{os_score}/100[/]")
            os3_tree.add(f"Risk Level: [bold]{os3_data.get('risk_level', 'UNKNOWN')}[/]")
            
            maint_node = os3_tree.add("Maintenance Status")
            if os3_data.get("last_release"):
                maint_node.add(f"Last Release: [cyan]{os3_data['last_release']}[/]")
            for exp in os3_data.get("explanations", []):
                if any(w in exp.lower() for w in ["maintenance", "active", "abandonment"]):
                    maint_node.add(Text.from_markup(exp))
                    
            vulns = os3_data.get("vulns", [])
            vuln_node = os3_tree.add(f"Vulnerability Signals ([red]{len(vulns)}[/])")
            for v in vulns[:5]:
                vuln_node.add(f"[dim]{v}[/]")
            renderables.append(os3_tree)
            renderables.append(Text(""))
            
            # Deps Dev Signals
            dd_tree = Tree("[bold cyan]Open Source Insights (deps.dev)[/bold cyan]")
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
                dd_tree.add("[italic white]No deep insights found in deps.dev database.[/]")
            renderables.append(dd_tree)
            
            # Final Verdict
            final_score = os_score
            if dd_score_info:
                final_score = round((os_score * 0.7) + (dd_score_info[0] * 0.3))
                
            vdct = "[red]Verdict: Recommendation is to evaluate alternatives or strictly pin versions.[/red]" if final_score < 70 else "[green]Verdict: Package appears healthy and well-maintained.[/green]"
            renderables.append(Text(""))
            renderables.append(Text(f"Weighted Intelligence Verdict: {final_score}/100", style="bold underline"))
            renderables.append(Text.from_markup(vdct))

            container = self.query_one("#report-container", PackageReport)
            container.update(Group(*renderables))
            self.add_to_history(package, ecosystem)
        except Exception as e:
            self.show_error("#report-container", f"UI Error: {e}")

    def add_to_history(self, package, ecosystem):
        if package not in self.history:
            self.history.insert(0, package)
            history_list = self.query_one("#history-list", ListView)
            list_item = ListItem(Label(f"{package} ({ecosystem})", id=f"hist-{package}"))
            list_item.pkg_name = package
            list_item.eco_name = ecosystem
            history_list.mount(list_item, before=0)

    def on_list_view_selected(self, event: ListView.Selected):
        pkg = getattr(event.item, "pkg_name", None)
        eco = getattr(event.item, "eco_name", "pypi")
        if not pkg:
            return
        self.query_one("#package-input", Input).value = pkg
        self.query_one("#ecosystem-input", Input).value = eco
        self.trigger_score(reasoning=False)

    # --- SCAN LOGIC ---
    
    def trigger_scan(self):
        file_path = self.query_one("#scan-input", Input).value.strip()
        if not file_path:
            return
            
        report = self.query_one("#scan-report-container", ScanReport)
        report.update(Panel(f"Scanning file [bold cyan]{file_path}[/bold cyan]...", border_style="cyan"))
        
        table = self.query_one("#scan-table", DataTable)
        table.clear()
        
        self.run_scan(file_path)

    @work(exclusive=True, thread=True)
    def run_scan(self, file_path: str):
        try:
            scan_data = scan_module.scan_file(file_path, force_refresh=False)
            self.call_from_thread(self.show_scan_results, scan_data)
        except Exception as e:
            self.call_from_thread(self.show_error, "#scan-report-container", f"Scan error: {e}")

    def show_scan_results(self, scan_data: dict):
        report = self.query_one("#scan-report-container", ScanReport)
        table = self.query_one("#scan-table", DataTable)
        
        summary = scan_data.get("summary", {})
        results = scan_data.get("results", [])
        
        if not results:
            report.update(Panel("No valid packages found to scan.", border_style="red"))
            return
            
        avg_score_color = "green" if summary.get("avg_score", 0) >= 80 else "yellow" if summary.get("avg_score", 0) >= 55 else "red"
        
        summary_text = (
            f"Packages Scanned: [bold white]{summary.get('total_packages', 0)}[/]\n"
            f"Average Project Score: [bold {avg_score_color}]{summary.get('avg_score', 0)}/100[/]\n"
            f"Risk Breakdown: [green]LOW: {summary.get('risk_counts', {}).get('LOW', 0)}[/] | "
            f"[yellow]MED: {summary.get('risk_counts', {}).get('MEDIUM', 0)}[/] | "
            f"[red]HIGH: {summary.get('risk_counts', {}).get('HIGH', 0)}[/]"
        )
        report.update(Panel(summary_text, title="[bold cyan]Scan Summary[/bold cyan]", border_style="cyan"))
        
        for r in results:
            if "error" in r:
                table.add_row(r["name"], r.get("version", "N/A"), "ERR", "ERROR", r["error"][:50])
                continue
                
            sd = r["score_data"]
            score = sd.get("score", 0)
            risk = sd.get("risk_level", "UNKNOWN")
            
            color = "dim cyan" if risk == "SUPPRESSED" else "green" if score >= 80 else "yellow" if score >= 55 else "red"
            
            vuln_count = len(sd.get("vulns", []))
            findings = f"[red]{vuln_count} Vulns Found[/]" if vuln_count > 0 else (sd.get("explanations", ["OK"])[0] if sd.get("explanations") else "No issues")
            
            table.add_row(
                r["name"],
                r.get("version", "latest"),
                f"[{color}]{score}[/]",
                f"[{color}]{risk}[/]",
                findings
            )

    # --- SUPPRESS LOGIC ---

    def refresh_suppress_table(self):
        table = self.query_one("#suppress-table", DataTable)
        table.clear()
        try:
            items = suppress.load_suppressions()
            for s in items:
                stype = "All versions" if s.get("suppress_all") else (f"CVEs: {', '.join(s.get('cves', []))}" if s.get("cves") else "Selected version")
                table.add_row(s.get("package", "Unknown"), s.get("ecosystem", "pypi"), s.get("reason", ""), stype)
        except Exception as e:
            pass

    def trigger_suppress_add(self):
        pkg = self.query_one("#sup-pkg", Input).value.strip()
        eco = self.query_one("#sup-eco", Input).value.strip()
        reason = self.query_one("#sup-reason", Input).value.strip()
        if not pkg: return
        
        item = {
            "package": pkg,
            "ecosystem": eco or "pypi",
            "reason": reason or "Manually verified",
            "suppress_all": True,
            "version_range": "*"
        }
        suppress.save_suppression(item, local=True)
        self.query_one("#sup-pkg", Input).value = ""
        self.refresh_suppress_table()

    def trigger_suppress_remove(self):
        pkg = self.query_one("#sup-pkg", Input).value.strip()
        if not pkg: return
        suppress.remove_suppression(pkg)
        self.query_one("#sup-pkg", Input).value = ""
        self.refresh_suppress_table()

    # --- STATUS & SYNC LOGIC ---

    def refresh_status(self):
        container = self.query_one("#status-container", StatusReport)
        try:
            stats = sync_module.get_status()
            last_sync = stats.get("last_sync", "Never")
            
            panel_content = (
                f"Total Cached Packages: [bold]{stats.get('total_packages', 0)}[/]\n"
                f"Last Cache Activity: [white]{last_sync}[/]\n\n"
                f"[bold underline]Ecosystem Coverage:[/bold underline]\n"
            )
            for eco, count in stats.get("ecosystems", {}).items():
                panel_content += f"  - {eco.upper()}: {count}\n"
                
            container.update(Panel(panel_content, title="[bold blue]Cache Status[/bold blue]", border_style="blue"))
        except Exception as e:
            container.update(Panel(f"Error fetching status: {e}", border_style="red"))

    def trigger_sync(self):
        container = self.query_one("#status-container", StatusReport)
        container.update(Panel("Forcing cache synchronization...", border_style="yellow"))
        self.run_sync()

    @work(exclusive=True, thread=True)
    def run_sync(self):
        try:
            sync_module.sync_all(full=True, quiet=True)
            self.call_from_thread(self.refresh_status)
        except Exception as e:
            self.call_from_thread(self.show_error, "#status-container", f"Sync error: {e}")

def main():
    app = OS3Tui()
    app.run()

if __name__ == "__main__":
    main()
