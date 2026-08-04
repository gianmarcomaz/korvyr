"""``korvyr`` command-line client for the scanner API."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
import httpx
from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeRemainingColumn,
)

from korvyr import __version__, config

console = Console()

CONNECT_HINT = "Start it with: [bold]uvicorn korvyr.api.server:app[/bold]"


def print_evidence(pkg: dict) -> None:
    # Keep CLI evidence compact; the API returns the structured payload for automation.
    if pkg.get("evidence"):
        console.print("    [dim]Evidence:[/dim]")
        for item in pkg["evidence"]:
            console.print(f"    [dim]-> {item}[/dim]")
    if pkg.get("decision_path"):
        console.print(f"    [dim]Decision: {pkg['decision_path']}[/dim]")


def print_scan_mode(res: dict) -> None:
    """Warn when a verdict came from static analysis alone."""
    if res.get("scan_mode") == "static-only" or res.get("fallback") == "rules_only":
        console.print(
            "  [yellow]note:[/yellow] [dim]static-only verdict "
            "(no GNN score for this package)[/dim]"
        )


def _fail_to_connect(api_url: str, error: Exception, json_output: bool) -> None:
    if json_output:
        print(json.dumps({"error": str(error)}))
    else:
        console.print(f"[red]Error:[/red] Could not reach the Korvyr API at {api_url}.")
        console.print(CONNECT_HINT)
    sys.exit(1)


@click.group()
@click.version_option(__version__, prog_name="korvyr")
def cli() -> None:
    """Korvyr - screen npm packages before installing them."""


@cli.command()
@click.option("--api-url", default=config.api_url, help="URL of the scanning server")
def status(api_url: str) -> None:
    """Show whether the API is up and which scan mode it is in."""
    try:
        with httpx.Client(timeout=10) as client:
            resp = client.get(f"{api_url}/health")
            resp.raise_for_status()
            res = resp.json()
    except httpx.HTTPError as exc:
        _fail_to_connect(api_url, exc, json_output=False)
        return

    mode = res.get("scan_mode", "unknown")
    colour = "green" if mode == "hybrid" else "yellow"
    console.print(f"  API:        [green]{api_url}[/green]")
    console.print(f"  Scan mode:  [{colour}]{mode}[/{colour}]")
    console.print(f"  Device:     {res.get('device', 'unknown')}")
    console.print(f"  Checkpoint: {res.get('model_checkpoint', 'unknown')}")
    if mode != "hybrid":
        console.print("  [dim]No GNN checkpoint loaded - verdicts use static analysis only.[/dim]")


@cli.command()
@click.argument("package_spec")
@click.option("--api-url", default=config.api_url, help="URL of the scanning server")
@click.option("--json", "json_output", is_flag=True, help="Output results as JSON")
@click.option("--timeout", default=120, type=int, help="Request timeout in seconds")
def scan(package_spec: str, api_url: str, json_output: bool, timeout: int) -> None:
    """Scan a single package, e.g. ``korvyr scan is-number@7.0.0``."""
    # Scoped npm names look like @scope/name@version, so split after the leading @.
    if "@" not in package_spec[1:]:
        console.print("[red]Error:[/red] Package must be in the format name@version")
        sys.exit(1)

    if package_spec.startswith("@"):
        scope_name, version = package_spec[1:].split("@", 1)
        name = f"@{scope_name}"
    else:
        name, version = package_spec.split("@", 1)

    if not json_output:
        console.print(f"\n  [bold cyan]Korvyr[/bold cyan] - scanning {package_spec}...\n")

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(f"{api_url}/scan/package", json={"name": name, "version": version})
            resp.raise_for_status()
            res = resp.json()
    except httpx.HTTPError as exc:
        _fail_to_connect(api_url, exc, json_output)
        return

    if json_output:
        print(json.dumps(res, indent=2))
        sys.exit(0)

    verdict = res.get("verdict")
    conf = res.get("confidence", 0.0)

    if verdict == "clean":
        console.print(
            f"  [green]OK[/green] {package_spec} is [green]clean[/green] "
            f"[dim][confidence: {conf:.2f}][/dim]"
        )
    elif verdict == "suspicious":
        console.print(
            f"  [yellow]![/yellow] {package_spec} is "
            f"[bold yellow]SUSPICIOUS[/bold yellow] [dim][confidence: {conf:.2f}][/dim]"
        )
        print_evidence(res)
    elif verdict == "malicious":
        console.print(
            f"  [red]X[/red] {package_spec} is [bold red]MALICIOUS[/bold red] "
            f"[dim][confidence: {conf:.2f}][/dim]"
        )
        print_evidence(res)
    else:
        console.print(
            f"  [red]![/red] {package_spec} scan failed: {res.get('error_msg', 'Unknown error')}"
        )

    print_scan_mode(res)
    console.print(f"\n  [dim]Scan complete in {res.get('scan_time_ms', 0) / 1000:.1f}s[/dim]")


@cli.command()
@click.option("--api-url", default=config.api_url, help="URL of the scanning server")
@click.option("--json", "json_output", is_flag=True, help="Output results as JSON")
@click.option(
    "--fail-on",
    type=click.Choice(["high", "medium", "any"]),
    default="high",
    help="Exit 1 when packages at or above this severity are found",
)
@click.option("--lockfile", default="package-lock.json", help="Path to package-lock.json")
@click.option("--timeout", default=120, type=int, help="Request timeout in seconds")
def audit(api_url: str, json_output: bool, fail_on: str, lockfile: str, timeout: int) -> None:
    """Scan every pinned dependency in a lockfile."""
    lock_path = Path(lockfile)
    if not lock_path.exists():
        if json_output:
            print(json.dumps({"error": f"Could not find {lockfile}"}))
        else:
            console.print(f"[red]Error:[/red] Could not find {lockfile} here.")
        sys.exit(1)

    if not json_output:
        console.print("\n  [bold cyan]Korvyr[/bold cyan] - scanning dependencies...\n")

    def post_lockfile(handle) -> httpx.Response:
        with httpx.Client(timeout=timeout) as client:
            return client.post(
                f"{api_url}/scan/lockfile",
                files={"lockfile": (lock_path.name, handle, "application/json")},
            )

    try:
        with open(lock_path, "rb") as handle:
            if json_output:
                resp = post_lockfile(handle)
            else:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TimeRemainingColumn(),
                    console=console,
                ) as progress:
                    task = progress.add_task("Uploading and scanning...", total=None)
                    resp = post_lockfile(handle)
                    progress.update(task, completed=100)
            resp.raise_for_status()
            res = resp.json()
    except httpx.HTTPError as exc:
        _fail_to_connect(api_url, exc, json_output)
        return

    if json_output:
        print(json.dumps(res, indent=2))
        sys.exit(0)

    results = res.get("results", {})
    clean = results.get("clean", 0)
    suspicious = results.get("suspicious", 0)
    malicious = results.get("malicious", 0)

    console.print("\n  [bold]Results:[/bold]")
    if clean:
        console.print(f"  [green]OK[/green] {clean} packages clean")
    if suspicious:
        console.print(f"  [yellow]![/yellow] {suspicious} packages suspicious")
    if malicious:
        console.print(f"  [red]X[/red] {malicious} packages malicious")
    console.print()

    flagged = res.get("flagged_packages", [])
    for pkg in flagged:
        name = pkg.get("package_name")
        version = pkg.get("version")
        conf = pkg.get("confidence", 0.0)
        if pkg.get("verdict") == "malicious":
            console.print(
                f"  [red]X {name}@{version}[/red]  "
                f"[bold red][MALICIOUS - confidence: {conf:.2f}][/bold red]"
            )
        else:
            console.print(
                f"  [yellow]! {name}@{version}[/yellow]  "
                f"[bold yellow][SUSPICIOUS - confidence: {conf:.2f}][/bold yellow]"
            )
        print_evidence(pkg)
        console.print()

    print_scan_mode(res)
    console.print(f"  [dim]Scan complete in {res.get('scan_time_seconds', 0)}s[/dim]\n")

    if fail_on == "high" and malicious > 0:
        sys.exit(1)
    if fail_on == "medium" and (malicious > 0 or suspicious > 0):
        sys.exit(1)
    if fail_on == "any" and flagged:
        sys.exit(1)


if __name__ == "__main__":
    cli()
