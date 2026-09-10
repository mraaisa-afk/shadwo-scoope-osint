"""
SHADOWSCOPE TUI Application
Multi-tab terminal user interface using Textual
"""

import asyncio
from typing import Optional, List, Dict, Any
from pathlib import Path

try:
    from textual.app import App, ComposeResult
    from textual.containers import Container, Grid, ScrollableContainer
    from textual.widgets import (
        Header, Footer, Button, Label, Input, ListView, ListItem,
        DataTable, TabbedContent, TabPane, Static, RichLog
    )
    from textual.screen import Screen, ModalScreen
    from textual import work, on
    from textual.reactive import reactive
    from rich.text import Text
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    
    TEXTUAL_AVAILABLE = True
except ImportError:
    TEXTUAL_AVAILABLE = False

from shadowscope.core import targets, modules, storage, config, proxy, sandbox


# ============================================================================
# Main TUI Application
# ============================================================================

class ShadowscopeApp(App):
    """Main SHADOWSCOPE TUI Application"""
    
    CSS_PATH = [Path(__file__).parent / "styles.css"]
    TITLE = "SHADOWSCOPE"
    SUB_TITLE = "OSINT Reconnaissance Framework"
    
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("ctrl+c", "quit", "Quit"),
        ("ctrl+r", "refresh", "Refresh"),
        ("ctrl+s", "save", "Save"),
        ("ctrl+f", "search", "Search"),
        ("tab", "next_tab", "Next Tab"),
        ("shift+tab", "prev_tab", "Previous Tab"),
    ]
    
    def __init__(self, module: Optional[str] = None, target: Optional[str] = None):
        super().__init__()
        self.initial_module = module
        self.initial_target = target
        self.current_scope: List[Dict[str, Any]] = []
        self.current_results: List[Dict[str, Any]] = []
    
    def compose(self) -> ComposeResult:
        """Compose the application UI"""
        yield Header(show_clock=True)
        
        with Container(id="main-container"):
            yield self.create_main_tabs()
        
        yield Footer()
    
    def create_main_tabs(self) -> TabbedContent:
        """Create the main tabbed interface"""
        with TabbedContent(id="main-tabs"):
            # Scope Tab
            with TabPane("Scope", id="scope-tab"):
                yield ScopeScreen()
            
            # Results Tab
            with TabPane("Results", id="results-tab"):
                yield ResultsScreen()
            
            # Modules Tab
            with TabPane("Modules", id="modules-tab"):
                yield ModulesScreen()
            
            # Logs Tab
            with TabPane("Logs", id="logs-tab"):
                yield LogsScreen()
            
            # Dashboard Tab
            with TabPane("Dashboard", id="dashboard-tab"):
                yield DashboardScreen()
    
    def on_ready(self) -> None:
        """Called when the app is ready"""
        self.load_initial_data()
    
    def load_initial_data(self) -> None:
        """Load initial data from storage"""
        self.current_scope = [t.to_dict() for t in targets.get_all()]
        self.current_results = storage.get_results(limit=100)
    
    def action_quit(self) -> None:
        """Quit the application"""
        self.exit()
    
    def action_refresh(self) -> None:
        """Refresh all data"""
        self.load_initial_data()
        self.query_one(RefreshData)
    
    def action_save(self) -> None:
        """Save current state"""
        storage.export_data("shadowscope_backup.json")
        self.notify("Data saved to shadowscope_backup.json", severity="information")
    
    def action_search(self) -> None:
        """Open search dialog"""
        self.push_screen(SearchScreen())


class RefreshData:
    """Message to refresh data in screens"""
    pass


# ============================================================================
# Scope Screen
# ============================================================================

class ScopeScreen(Screen):
    """Scope management screen"""
    
    BINDINGS = [
        ("a", "add_target", "Add Target"),
        ("d", "delete_target", "Delete Target"),
        ("t", "tag_target", "Tag Target"),
        ("e", "export_scope", "Export Scope"),
        ("i", "import_scope", "Import Scope"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Label("Target Scope Management", id="scope-title")
        yield Button("Add Target", id="add-target-btn", variant="primary")
        yield Button("Delete Selected", id="delete-btn", variant="error")
        yield Button("Tag Selected", id="tag-btn", variant="success")
        yield Button("Refresh", id="refresh-btn")
        
        with ScrollableContainer(id="scope-container"):
            self.target_table = DataTable(id="target-table")
            self.target_table.add_columns("ID", "Target", "Type", "Tags", "Added", "Status")
            yield self.target_table
    
    def on_mount(self) -> None:
        self.load_targets()
    
    def load_targets(self) -> None:
        """Load targets into the table"""
        self.target_table.clear()
        self.target_table.add_columns("ID", "Target", "Type", "Tags", "Added", "Status")
        
        all_targets = targets.get_all()
        for t in all_targets:
            tags_str = ", ".join(t.tags) if t.tags else "-"
            added_str = t.added_at.strftime("%Y-%m-%d %H:%M") if t.added_at else "-"
            self.target_table.add_row(
                str(t.id),
                t.value,
                t.target_type,
                tags_str,
                added_str,
                t.status
            )
    
    def action_add_target(self) -> None:
        self.push_screen(AddTargetScreen())
    
    def action_delete_target(self) -> None:
        if self.target_table.cursor_row:
            row_idx = self.target_table.cursor_row
            if 0 <= row_idx < len(self.target_table.rows):
                target_id = self.target_table.get_cell(row_idx, 0).plain
                try:
                    targets.remove(int(target_id))
                    self.load_targets()
                    self.notify("Target deleted", severity="success")
                except Exception as e:
                    self.notify(f"Error: {e}", severity="error")
    
    def action_tag_target(self) -> None:
        if self.target_table.cursor_row:
            row_idx = self.target_table.cursor_row
            if 0 <= row_idx < len(self.target_table.rows):
                target_id = self.target_table.get_cell(row_idx, 0).plain
                self.push_screen(TagTargetScreen(target_id))
    
    def action_export_scope(self) -> None:
        storage.export_targets("scope_export.json")
        self.notify("Scope exported to scope_export.json", severity="information")
    
    def action_import_scope(self) -> None:
        self.push_screen(ImportScopeScreen())


# ============================================================================
# Results Screen
# ============================================================================

class ResultsScreen(Screen):
    """Results viewer screen"""
    
    BINDINGS = [
        ("f", "filter_results", "Filter Results"),
        ("s", "sort_results", "Sort Results"),
        ("e", "export_results", "Export Results"),
        ("c", "clear_results", "Clear Results"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Label("Investigation Results", id="results-title")
        yield Button("Filter", id="filter-btn")
        yield Button("Sort", id="sort-btn")
        yield Button("Export", id="export-btn", variant="success")
        yield Button("Clear", id="clear-btn", variant="error")
        
        with ScrollableContainer(id="results-container"):
            self.results_table = DataTable(id="results-table")
            self.results_table.add_columns("ID", "Target", "Module", "Status", "Time", "Data")
            yield self.results_table
    
    def on_mount(self) -> None:
        self.load_results()
    
    def load_results(self, limit: int = 100) -> None:
        """Load results into the table"""
        self.results_table.clear()
        self.results_table.add_columns("ID", "Target", "Module", "Status", "Time", "Data")
        
        results = storage.get_results(limit=limit)
        for r in results:
            time_str = r.get("timestamp", "-")
            if isinstance(time_str, str):
                time_str = time_str[:19]  # Truncate to YYYY-MM-DD HH:MM:SS
            
            data_str = str(r.get("data", {}))[:50] + "..." if len(str(r.get("data", {}))) > 50 else str(r.get("data", {}))
            
            self.results_table.add_row(
                str(r.get("id", "-")),
                r.get("target", "-"),
                r.get("module", "-"),
                r.get("status", "-"),
                time_str,
                data_str
            )
    
    def action_filter_results(self) -> None:
        self.push_screen(FilterResultsScreen())
    
    def action_sort_results(self) -> None:
        self.push_screen(SortResultsScreen())
    
    def action_export_results(self) -> None:
        storage.export_results("results_export.json")
        self.notify("Results exported to results_export.json", severity="information")
    
    def action_clear_results(self) -> None:
        storage.clear_results()
        self.load_results()
        self.notify("Results cleared", severity="warning")


# ============================================================================
# Modules Screen
# ============================================================================

class ModulesScreen(Screen):
    """Module management screen"""
    
    BINDINGS = [
        ("i", "install_module", "Install Module"),
        ("u", "uninstall_module", "Uninstall Module"),
        ("r", "run_module", "Run Module"),
        ("e", "enable_module", "Enable Module"),
        ("d", "disable_module", "Disable Module"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Label("Module Management", id="modules-title")
        yield Button("Install", id="install-btn", variant="primary")
        yield Button("Uninstall", id="uninstall-btn", variant="error")
        yield Button("Run", id="run-btn", variant="success")
        yield Button("Enable", id="enable-btn")
        yield Button("Disable", id="disable-btn")
        yield Button("Refresh", id="refresh-btn")
        
        with ScrollableContainer(id="modules-container"):
            self.modules_table = DataTable(id="modules-table")
            self.modules_table.add_columns("Name", "Version", "Category", "Status", "Author", "Description")
            yield self.modules_table
    
    def on_mount(self) -> None:
        self.load_modules()
    
    def load_modules(self) -> None:
        """Load modules into the table"""
        self.modules_table.clear()
        self.modules_table.add_columns("Name", "Version", "Category", "Status", "Author", "Description")
        
        all_modules = modules.list_modules()
        for m in all_modules:
            status = "[green]enabled[/green]" if m.get("enabled", True) else "[red]disabled[/red]"
            self.modules_table.add_row(
                m.get("name", "-"),
                m.get("version", "-"),
                m.get("category", "-"),
                status,
                m.get("author", "-"),
                (m.get("description", "-") or "-")[:50]
            )
    
    def action_install_module(self) -> None:
        self.push_screen(InstallModuleScreen())
    
    def action_uninstall_module(self) -> None:
        if self.modules_table.cursor_row:
            row_idx = self.modules_table.cursor_row
            if 0 <= row_idx < len(self.modules_table.rows):
                module_name = self.modules_table.get_cell(row_idx, 0).plain
                modules.uninstall(module_name)
                self.load_modules()
                self.notify(f"Module {module_name} uninstalled", severity="success")
    
    def action_run_module(self) -> None:
        if self.modules_table.cursor_row:
            row_idx = self.modules_table.cursor_row
            if 0 <= row_idx < len(self.modules_table.rows):
                module_name = self.modules_table.get_cell(row_idx, 0).plain
                self.push_screen(RunModuleScreen(module_name))
    
    def action_enable_module(self) -> None:
        if self.modules_table.cursor_row:
            row_idx = self.modules_table.cursor_row
            if 0 <= row_idx < len(self.modules_table.rows):
                module_name = self.modules_table.get_cell(row_idx, 0).plain
                modules.enable(module_name)
                self.load_modules()
                self.notify(f"Module {module_name} enabled", severity="success")
    
    def action_disable_module(self) -> None:
        if self.modules_table.cursor_row:
            row_idx = self.modules_table.cursor_row
            if 0 <= row_idx < len(self.modules_table.rows):
                module_name = self.modules_table.get_cell(row_idx, 0).plain
                modules.disable(module_name)
                self.load_modules()
                self.notify(f"Module {module_name} disabled", severity="warning")


# ============================================================================
# Logs Screen
# ============================================================================

class LogsScreen(Screen):
    """Logs viewer screen"""
    
    BINDINGS = [
        ("c", "clear_logs", "Clear Logs"),
        ("f", "filter_logs", "Filter Logs"),
    ]
    
    def compose(self) -> ComposeResult:
        yield Label("System Logs", id="logs-title")
        yield Button("Clear", id="clear-btn", variant="error")
        yield Button("Filter", id="filter-btn")
        
        with ScrollableContainer(id="logs-container"):
            self.log_view = RichLog(id="log-view", wrap=True)
            yield self.log_view
    
    def on_mount(self) -> None:
        self.load_logs()
    
    def load_logs(self) -> None:
        """Load logs into the view"""
        self.log_view.clear()
        
        # Get logs from storage
        logs = storage.get_logs(limit=100)
        for log in logs:
            level = log.get("level", "INFO")
            message = log.get("message", "")
            timestamp = log.get("timestamp", "")
            
            if level == "ERROR":
                self.log_view.write(f"[red]{timestamp} [ERROR] {message}[/red]")
            elif level == "WARNING":
                self.log_view.write(f"[yellow]{timestamp} [WARNING] {message}[/yellow]")
            elif level == "SUCCESS":
                self.log_view.write(f"[green]{timestamp} [SUCCESS] {message}[/green]")
            else:
                self.log_view.write(f"[white]{timestamp} [INFO] {message}[/white]")
    
    def action_clear_logs(self) -> None:
        storage.clear_logs()
        self.load_logs()
        self.notify("Logs cleared", severity="warning")
    
    def action_filter_logs(self) -> None:
        self.push_screen(FilterLogsScreen())


# ============================================================================
# Dashboard Screen
# ============================================================================

class DashboardScreen(Screen):
    """Dashboard overview screen"""
    
    def compose(self) -> ComposeResult:
        yield Label("SHADOWSCOPE Dashboard", id="dashboard-title")
        
        with Grid(id="dashboard-grid"):
            # Stats Cards
            with Container(id="stats-container"):
                yield Label("Targets in Scope", id="targets-count")
                yield Label("Total Results", id="results-count")
                yield Label("Active Modules", id="modules-count")
                yield Label("Proxy Status", id="proxy-status")
            
            # Quick Actions
            with Container(id="actions-container"):
                yield Button("Add Target", id="quick-add-target", variant="primary")
                yield Button("Run Module", id="quick-run-module", variant="success")
                yield Button("Export All", id="quick-export", variant="info")
            
            # Recent Activity
            with Container(id="activity-container"):
                yield Label("Recent Activity", id="activity-title")
                self.activity_log = RichLog(id="activity-log")
                yield self.activity_log
    
    def on_mount(self) -> None:
        self.update_dashboard()
    
    def update_dashboard(self) -> None:
        """Update dashboard statistics"""
        # Update counts
        target_count = len(targets.get_all())
        result_count = storage.count_results()
        module_count = len(modules.list_modules())
        proxy_status = "[green]Active[/green]" if proxy.check_health() else "[red]Inactive[/red]"
        
        self.query_one("#targets-count").update(f"[bold]Targets in Scope: {target_count}[/bold]")
        self.query_one("#results-count").update(f"[bold]Total Results: {result_count}[/bold]")
        self.query_one("#modules-count").update(f"[bold]Active Modules: {module_count}[/bold]")
        self.query_one("#proxy-status").update(f"[bold]Proxy Status: {proxy_status}[/bold]")
        
        # Update activity log
        self.activity_log.clear()
        recent_results = storage.get_results(limit=10)
        for r in recent_results:
            self.activity_log.write(f"[green]+[/green] {r.get('module', 'Unknown')} on {r.get('target', 'Unknown')}")


# ============================================================================
# Modal Screens
# ============================================================================

class AddTargetScreen(ModalScreen):
    """Screen to add a new target"""
    
    def compose(self) -> ComposeResult:
        yield Label("Add Target", id="modal-title")
        yield Input(placeholder="Enter target (domain, IP, email, etc.)", id="target-input")
        yield Input(placeholder="Tags (comma-separated, optional)", id="tags-input")
        yield Button("Add", id="add-btn", variant="primary")
        yield Button("Cancel", id="cancel-btn", variant="error")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel-btn":
            self.dismiss()
        elif event.button.id == "add-btn":
            target_input = self.query_one("#target-input", Input)
            tags_input = self.query_one("#tags-input", Input)
            
            target = target_input.value
            tags = [t.strip() for t in tags_input.value.split(",") if t.strip()]
            
            if target:
                targets.add(target, tags=tags)
                self.dismiss()
                self.notify("Target added", severity="success")
            else:
                self.notify("Please enter a target", severity="error")


class TagTargetScreen(ModalScreen):
    """Screen to tag a target"""
    
    def __init__(self, target_id: str):
        super().__init__()
        self.target_id = target_id
    
    def compose(self) -> ComposeResult:
        yield Label(f"Tag Target #{self.target_id}", id="modal-title")
        yield Input(placeholder="Tags (comma-separated)", id="tags-input")
        yield Button("Apply", id="apply-btn", variant="primary")
        yield Button("Cancel", id="cancel-btn", variant="error")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel-btn":
            self.dismiss()
        elif event.button.id == "apply-btn":
            tags_input = self.query_one("#tags-input", Input)
            tags = [t.strip() for t in tags_input.value.split(",") if t.strip()]
            
            targets.update_tags(int(self.target_id), tags)
            self.dismiss()
            self.notify("Tags updated", severity="success")


class ImportScopeScreen(ModalScreen):
    """Screen to import scope from file"""
    
    def compose(self) -> ComposeResult:
        yield Label("Import Scope", id="modal-title")
        yield Input(placeholder="File path", id="file-input")
        yield Button("Import", id="import-btn", variant="primary")
        yield Button("Cancel", id="cancel-btn", variant="error")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel-btn":
            self.dismiss()
        elif event.button.id == "import-btn":
            file_input = self.query_one("#file-input", Input)
            file_path = file_input.value
            
            if file_path:
                try:
                    targets.import_from_file(file_path)
                    self.dismiss()
                    self.notify("Scope imported", severity="success")
                except Exception as e:
                    self.notify(f"Error: {e}", severity="error")
            else:
                self.notify("Please enter a file path", severity="error")


class InstallModuleScreen(ModalScreen):
    """Screen to install a module"""
    
    def compose(self) -> ComposeResult:
        yield Label("Install Module", id="modal-title")
        yield Input(placeholder="Module name or URL", id="module-input")
        yield Button("Install", id="install-btn", variant="primary")
        yield Button("Cancel", id="cancel-btn", variant="error")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel-btn":
            self.dismiss()
        elif event.button.id == "install-btn":
            module_input = self.query_one("#module-input", Input)
            module_name = module_input.value
            
            if module_name:
                try:
                    modules.install(module_name)
                    self.dismiss()
                    self.notify(f"Module {module_name} installed", severity="success")
                except Exception as e:
                    self.notify(f"Error: {e}", severity="error")
            else:
                self.notify("Please enter a module name", severity="error")


class RunModuleScreen(ModalScreen):
    """Screen to run a module"""
    
    def __init__(self, module_name: str):
        super().__init__()
        self.module_name = module_name
    
    def compose(self) -> ComposeResult:
        yield Label(f"Run Module: {self.module_name}", id="modal-title")
        yield Input(placeholder="Target (optional, uses scope if empty)", id="target-input")
        yield Input(placeholder="Options (JSON)", id="options-input")
        yield Button("Run", id="run-btn", variant="primary")
        yield Button("Cancel", id="cancel-btn", variant="error")
    
    @work(exclusive=True)
    async def run_module_worker(self, target: str, options: dict) -> None:
        """Run module in background"""
        try:
            result = await modules.run_async(self.module_name, target, options)
            self.notify(f"Module {self.module_name} completed", severity="success")
        except Exception as e:
            self.notify(f"Error: {e}", severity="error")
        finally:
            self.dismiss()
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel-btn":
            self.dismiss()
        elif event.button.id == "run-btn":
            target_input = self.query_one("#target-input", Input)
            options_input = self.query_one("#options-input", Input)
            
            target = target_input.value
            options = {}
            if options_input.value:
                import json
                try:
                    options = json.loads(options_input.value)
                except json.JSONDecodeError:
                    self.notify("Invalid JSON for options", severity="error")
                    return
            
            self.run_module_worker(target, options)


class FilterResultsScreen(ModalScreen):
    """Screen to filter results"""
    
    def compose(self) -> ComposeResult:
        yield Label("Filter Results", id="modal-title")
        yield Input(placeholder="Module name (optional)", id="module-input")
        yield Input(placeholder="Target (optional)", id="target-input")
        yield Input(placeholder="Status (optional)", id="status-input")
        yield Button("Apply", id="apply-btn", variant="primary")
        yield Button("Cancel", id="cancel-btn", variant="error")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel-btn":
            self.dismiss()
        elif event.button.id == "apply-btn":
            # Get filter values
            module = self.query_one("#module-input", Input).value
            target = self.query_one("#target-input", Input).value
            status = self.query_one("#status-input", Input).value
            
            # Apply filters and update results
            # This would need to communicate back to the ResultsScreen
            self.dismiss()
            self.notify("Filters applied", severity="information")


class SortResultsScreen(ModalScreen):
    """Screen to sort results"""
    
    def compose(self) -> ComposeResult:
        yield Label("Sort Results", id="modal-title")
        yield Label("Sort by:", id="sort-label")
        yield Button("Timestamp", id="timestamp-btn")
        yield Button("Target", id="target-btn")
        yield Button("Module", id="module-btn")
        yield Button("Status", id="status-btn")
        yield Button("Cancel", id="cancel-btn", variant="error")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel-btn":
            self.dismiss()
        else:
            sort_by = event.button.id.replace("-btn", "")
            self.dismiss()
            self.notify(f"Sorted by {sort_by}", severity="information")


class FilterLogsScreen(ModalScreen):
    """Screen to filter logs"""
    
    def compose(self) -> ComposeResult:
        yield Label("Filter Logs", id="modal-title")
        yield Input(placeholder="Level (ERROR, WARNING, INFO)", id="level-input")
        yield Input(placeholder="Message contains", id="message-input")
        yield Button("Apply", id="apply-btn", variant="primary")
        yield Button("Cancel", id="cancel-btn", variant="error")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel-btn":
            self.dismiss()
        elif event.button.id == "apply-btn":
            level = self.query_one("#level-input", Input).value
            message = self.query_one("#message-input", Input).value
            self.dismiss()
            self.notify("Log filters applied", severity="information")


class SearchScreen(ModalScreen):
    """Global search screen"""
    
    def compose(self) -> ComposeResult:
        yield Label("Search", id="modal-title")
        yield Input(placeholder="Search query", id="search-input")
        yield Button("Search", id="search-btn", variant="primary")
        yield Button("Cancel", id="cancel-btn", variant="error")
    
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel-btn":
            self.dismiss()
        elif event.button.id == "search-btn":
            query = self.query_one("#search-input", Input).value
            if query:
                # Perform search across all data
                self.dismiss()
                self.notify(f"Searching for: {query}", severity="information")
            else:
                self.notify("Please enter a search query", severity="error")


# ============================================================================
# Entry Points
# ============================================================================

def run_tui(module: Optional[str] = None, target: Optional[str] = None) -> None:
    """Run the main TUI application"""
    if not TEXTUAL_AVAILABLE:
        print("Textual is not installed. Install with: pip install textual")
        return
    
    app = ShadowscopeApp(module=module, target=target)
    app.run()


def run_scope_tui() -> None:
    """Run scope management TUI"""
    run_tui()


def run_results_tui() -> None:
    """Run results viewer TUI"""
    run_tui()


def run_modules_tui() -> None:
    """Run module management TUI"""
    run_tui()


def run_logs_tui() -> None:
    """Run logs viewer TUI"""
    run_tui()
