import json
import requests
from textual.app import App, ComposeResult
from textual.widgets import Header, Footer, Input, Button, Static, Markdown, ListItem, ListView, Label
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual import work
from rich.panel import Panel
from rich.tree import Tree
from rich.table import Table
from rich.text import Text
from rich.console import Group

from os3.scorer import ScoringEngine

class PackageReport(Static):
    """A widget to display the scoring report for a package."""
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

    #search-area {
        height: auto;
        padding: 1 2;
        background: $surface;
        border-bottom: solid $primary-lighten-2;
    }

    #search-inputs {
        height: auto;
        width: 100%;
        align: center middle;
    }

    #package-input {
        width: 50%;
        margin-right: 1;
    }
    
    #ecosystem-input {
        width: 20%;
        margin-right: 1;
    }

    #score-button {
        width: 20%;
        background: $primary;
        color: $text;
    }

    #results-scroll {
        width: 100%;
        height: 1fr;
        padding: 1 2;
    }
    
    .status-msg {
        text-align: center;
        padding: 2;
        color: $text-muted;
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
                with Vertical(id="search-area"):
                    with Horizontal(id="search-inputs"):
                        yield Input(placeholder="📦 Package name (e.g. requests, react)", id="package-input")
                        yield Input(value="pypi", placeholder="Ecosystem", id="ecosystem-input")
                        yield Button("Score", id="score-button", variant="primary")
                
                with VerticalScroll(id="results-scroll"):
                    yield Static("Welcome to OS³! Enter a package above to begin security analysis.", classes="status-msg", id="welcome-msg")
                    yield PackageReport(id="report-container")
                    
        yield Footer()

    def on_mount(self):
        self.query_one("#package-input").focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "score-button":
            self.trigger_score()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self.trigger_score()

    def trigger_score(self) -> None:
        package = self.query_one("#package-input", Input).value.strip()
        ecosystem = self.query_one("#ecosystem-input", Input).value.strip()
        
        if not package:
            return
            
        welcome_msg = self.query("#welcome-msg")
        if welcome_msg:
            welcome_msg.remove()
            
        report_container = self.query_one("#report-container", PackageReport)
        report_container.update(Panel(f"⏳ Auditing [bold cyan]{package}[/bold cyan] in {ecosystem}...", border_style="cyan", padding=(1, 2)))
        
        # Start background task
        self.run_score(package, ecosystem)

    @work(exclusive=True, thread=True)
    def run_score(self, package: str, ecosystem: str) -> None:
        try:
            engine = ScoringEngine()
            # Force refresh to get real-time info
            report_data = engine.score_package(ecosystem, package, force_refresh=True)
            if not report_data:
                self.call_from_thread(self.show_error, f"Could not find data for {package} in {ecosystem}")
                return
            self.call_from_thread(self.show_results, package, ecosystem, report_data)
        except Exception as e:
            self.call_from_thread(self.show_error, f"Error calculating score: {e}")

    def show_error(self, message: str) -> None:
        container = self.query_one("#report-container", PackageReport)
        container.update(Panel(f"❌ [bold red]Error:[/bold red] {message}", border_style="red", padding=(1, 2)))

    def show_results(self, package: str, ecosystem: str, report_data: dict) -> None:
        try:
            score = report_data.get("score", 0)
            risk_level = report_data.get("risk_level", "UNKNOWN")
            explanations = report_data.get("explanations", [])
            alternatives = report_data.get("alternatives", [])
            vulns = report_data.get("vulns", [])
            breakdown = report_data.get("signal_breakdown", {})

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
                audit_node.add(Text(exp, style="italic"))

            renderables.append(tree)
            renderables.append(Text(""))

            # 3. Alternatives Table
            if alternatives:
                table = Table(title="[bold blue]Data-Backed Recommendations[/bold blue]", show_header=True, header_style="bold blue", border_style="blue", expand=True)
                table.add_column("Alternative", style="info", no_wrap=True)
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
                renderables.append(Text(""))

            container = self.query_one("#report-container", PackageReport)
            container.update(Group(*renderables))
            
            # Add to history if not there (at top)
            if package not in self.history:
                self.history.insert(0, package)
                history_list = self.query_one("#history-list", ListView)
                # Ensure the index parameter for insert/mount is correct for Textual > 0.40
                # Actually, Textual ListView doesn't use `before=0` effectively in some versions or crashes without `await`?
                history_list.mount(ListItem(Label(f"{package} ({ecosystem})", id=f"hist-{package}")), before=0)
        except Exception as e:
            import traceback
            with open("tui_error.log", "w", encoding="utf-8") as f:
                f.write(traceback.format_exc())

    def on_list_view_selected(self, event: ListView.Selected):
        # Allow selecting history to rescore
        label = event.item.query_one(Label)
        pkg_eco = label.renderable.split(" ")
        pkg = pkg_eco[0]
        eco = pkg_eco[1].strip("()") if len(pkg_eco) > 1 else "pypi"
        
        self.query_one("#package-input", Input).value = pkg
        self.query_one("#ecosystem-input", Input).value = eco
        self.trigger_score()

def main():
    app = OS3Tui()
    app.run()

if __name__ == "__main__":
    main()
