# python-tools/utils/logger.py
from rich.console import Console
from rich.panel import Panel

console = Console()

def print_banner(text):
    """Hàm in banner tiêu đề (Thứ mà script audit đang thiếu)"""
    console.print(Panel(f"[bold cyan]{text}[/bold cyan]", expand=False))

def log_info(message):
    console.print(f"[blue][INFO][/blue] {message}")

def log_success(message):
    console.print(f"[green][SUCCESS][/green] {message}")

def log_warning(message):
    console.print(f"[yellow][WARNING][/yellow] {message}")

def log_danger(message):
    console.print(f"[red][DANGER][/red] {message}")