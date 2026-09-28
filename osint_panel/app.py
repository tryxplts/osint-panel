from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path

from rich import box
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from .core import Finding, Inspection, OsintError, history_entry, inspect_target, load_history, run_maigret, save_history, smart_insights
from .intel import full_name_search, result_category, summarize_web_results


console = Console()


def print_banner() -> None:
    console.print("[bold cyan]OSINT PANEL[/bold cyan] [dim]1.0[/dim]")
    console.print("[dim]Maigret username search + target inspection[/dim]\n")


def print_menu() -> None:
    table = Table(box=box.SQUARE, show_header=False, expand=False)
    table.add_column(style="bold cyan", no_wrap=True)
    table.add_column(style="white")
    table.add_row("[1]", "Username search with Maigret")
    table.add_row("[2]", "Full-name web search")
    table.add_row("[3]", "Domain / IP inspection")
    table.add_row("[4]", "View history")
    table.add_row("[5]", "Exit")
    console.print(table)


def pause() -> None:
    console.input("\n[dim]Press Enter to return...[/dim]")


def safe_name(value: str) -> str:
    return "".join(character if character.isalnum() else "_" for character in value)[:80] or "target"


def export_findings(findings: list[Finding], username: str) -> Path:
    path = Path("data") / f"maigret_{safe_name(username)}_{datetime.now():%Y%m%d_%H%M%S}.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(("site", "url", "status"))
        writer.writerows((finding.site, finding.url, finding.status) for finding in findings)
    return path


def export_inspection(inspection: Inspection) -> Path:
    path = Path("data") / f"target_{safe_name(inspection.target)}_{datetime.now():%Y%m%d_%H%M%S}.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(("property", "value"))
        writer.writerows((
            ("Addresses", ", ".join(inspection.addresses)),
            ("Reverse names", ", ".join(inspection.reverse_names)),
            ("HTTP status", inspection.http_status),
            ("Server", inspection.server),
            ("Content type", inspection.content_type),
            ("TLS subject", inspection.tls_subject),
        ))
        writer.writerows((f"IP {label}", value) for label, value in inspection.ip_details)
        writer.writerows((f"Domain {label}", value) for label, value in inspection.domain_details)
    return path


def username_search() -> None:
    console.print("\n[bold]USERNAME SEARCH[/bold]")
    username = console.input("Username: ").strip()
    if not username:
        console.print("[red]Username cannot be empty.[/red]")
        return
    scope_choice = console.input("Scope [1] top 500 sites / [2] all sites: ").strip() or "1"
    scope = "all" if scope_choice == "2" else "top"
    use_tor = console.input("Use Tor if available? [y/N]: ").strip().lower() in {"y", "yes"}
    default_timeout = 600 if scope == "all" else 180
    timeout_value = console.input(f"Timeout seconds [{default_timeout}]: ").strip() or str(default_timeout)
    try:
        timeout = int(timeout_value)
    except ValueError:
        console.print("[red]Timeout must be a number.[/red]")
        return
    if not 30 <= timeout <= 3600:
        console.print("[red]Timeout must be between 30 and 3600 seconds.[/red]")
        return
    console.print(f"\n[yellow]Scanning {username} for up to {timeout} seconds...[/yellow]")
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Starting Maigret...", total=None)

            def report_line(line: str) -> None:
                progress.update(task, description=line[:100] or "Scanning...")

            findings = run_maigret(username, scope=scope, timeout=timeout, use_tor=use_tor, on_line=report_line)
            progress.update(task, description="Maigret finished", total=1, completed=1)
    except OsintError as error:
        console.print(f"[red]{error}[/red]")
        return
    if not findings:
        console.print("[yellow]No public profile findings returned.[/yellow]")
    else:
        table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
        table.add_column("#", justify="right")
        table.add_column("Site")
        table.add_column("Profile URL")
        table.add_column("Status")
        for index, finding in enumerate(findings, 1):
            table.add_row(str(index), finding.site, finding.url, finding.status)
        console.print(table)
        console.print("\n[bold cyan]SMART SUMMARY[/bold cyan]")
        for insight in smart_insights(findings):
            console.print(f"- {insight}")
        console.print("\n[bold cyan]PROFILE DETAILS[/bold cyan]")
        for index, finding in enumerate(findings, 1):
            console.print(f"\n[bold]{index}. {finding.site}[/bold] [green]{finding.status}[/green]")
            console.print(f"   URL: {finding.url}")
            if finding.tags:
                console.print(f"   Tags: {', '.join(finding.tags)}")
            for detail in finding.details[:8]:
                console.print(f"   - {detail}", markup=False)
    save_history(history_entry("username", username, f"{len(findings)} finding(s)"))
    if console.input("\nSave results as CSV? [y/N]: ").strip().lower() in {"y", "yes"}:
        console.print(f"[green]Saved:[/green] {export_findings(findings, username)}")


def export_web_results(results: list, name: str) -> Path:
    path = Path("data") / f"name_{safe_name(name)}_{datetime.now():%Y%m%d_%H%M%S}.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(("title", "url", "category", "query"))
        writer.writerows((result.title, result.url, result_category(result.url), result.query) for result in results)
    return path


def name_search() -> None:
    console.print("\n[bold]FULL-NAME SEARCH[/bold]")
    name = console.input("Full name: ").strip()
    if not name:
        console.print("[red]Name cannot be empty.[/red]")
        return
    mode = console.input("Mode [1] fast / [2] deep multi-query: ").strip() or "1"
    limit_value = console.input("Maximum results [20]: ").strip() or "20"
    try:
        limit = max(1, min(100, int(limit_value)))
    except ValueError:
        console.print("[red]Maximum results must be a number.[/red]")
        return
    console.print(f"\n[yellow]Searching public web results for {name}...[/yellow]")
    results = full_name_search(name, deep=mode == "2", limit=limit)
    if not results:
        console.print("[yellow]No indexed results returned. Try deep mode or a different spelling.[/yellow]")
        return
    table = Table(box=box.SIMPLE, header_style="bold cyan")
    table.add_column("#", justify="right")
    table.add_column("Type")
    table.add_column("Title")
    table.add_column("URL")
    for index, result in enumerate(results, 1):
        table.add_row(str(index), result_category(result.url), result.title, result.url)
    console.print(table)
    console.print("\n[bold cyan]SMART SUMMARY[/bold cyan]")
    for summary in summarize_web_results(results):
        console.print(f"- {summary}")
    save_history(history_entry("name", name, f"{len(results)} web result(s)"))
    if console.input("\nSave results as CSV? [y/N]: ").strip().lower() in {"y", "yes"}:
        console.print(f"[green]Saved:[/green] {export_web_results(results, name)}")


def target_inspection() -> None:
    console.print("\n[bold]DOMAIN / IP INSPECTION[/bold]")
    target = console.input("Domain, hostname, or IP: ").strip()
    if not target:
        console.print("[red]Target cannot be empty.[/red]")
        return
    console.print(f"\n[yellow]Inspecting {target}...[/yellow]")
    try:
        inspection = inspect_target(target)
    except OsintError as error:
        console.print(f"[red]{error}[/red]")
        return
    table = Table(box=box.SIMPLE, show_header=False)
    table.add_column("Property", style="bold cyan")
    table.add_column("Value")
    table.add_row("Addresses", ", ".join(inspection.addresses))
    table.add_row("Reverse names", ", ".join(inspection.reverse_names) or "none")
    table.add_row("HTTP status", inspection.http_status)
    table.add_row("Server", inspection.server)
    table.add_row("Content type", inspection.content_type)
    table.add_row("TLS subject", inspection.tls_subject)
    for label, value in inspection.ip_details:
        table.add_row(label, value)
    for label, value in inspection.domain_details:
        table.add_row(label, value)
    console.print(table)
    if inspection.http_status == "no HTTP(S) response":
        console.print("[dim]No web service answered on 80/443; use the network and owner fields above for attribution context.[/dim]")
    save_history(history_entry("target", target, f"{inspection.http_status} · {len(inspection.addresses)} address(es)"))
    if console.input("\nSave inspection as CSV? [y/N]: ").strip().lower() in {"y", "yes"}:
        console.print(f"[green]Saved:[/green] {export_inspection(inspection)}")


def show_history() -> None:
    entries = load_history()
    if not entries:
        console.print("[yellow]No history yet.[/yellow]")
        return
    table = Table(box=box.SIMPLE, header_style="bold cyan")
    table.add_column("Time")
    table.add_column("Type")
    table.add_column("Target")
    table.add_column("Result")
    for entry in entries:
        table.add_row(entry.timestamp, entry.kind, entry.target, entry.result)
    console.print(table)


def main() -> None:
    while True:
        console.clear()
        print_banner()
        print_menu()
        choice = console.input("\nSelect [1-5]: ").strip()
        if choice == "1":
            username_search()
            pause()
        elif choice == "2":
            name_search()
            pause()
        elif choice == "3":
            target_inspection()
            pause()
        elif choice == "4":
            show_history()
            pause()
        elif choice == "5":
            console.print("[dim]Exit.[/dim]")
            return
        else:
            console.print("[red]Invalid selection.[/red]")
            pause()


if __name__ == "__main__":
    main()
