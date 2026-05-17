import json
import os
import sys
from pathlib import Path

import click
import httpx
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn

console = Console()

def print_evidence(pkg: dict):
    # Keep CLI evidence compact; the API returns the structured payload for automation.
    if "evidence" in pkg and pkg["evidence"]:
        console.print("    [dim]Evidence:[/dim]")
        for e in pkg["evidence"]:
            console.print(f"    [dim]→ {e}[/dim]")
    if "decision_path" in pkg and pkg["decision_path"]:
        console.print(f"    [dim]Decision: {pkg['decision_path']}[/dim]")

@click.group()
def cli():
    """SupplyGuard CLI — Scan npm packages for malicious behavior."""
    pass

@cli.command()
def version():
    """Print the version number."""
    click.echo("SupplyGuard v0.1.0")

@cli.command()
@click.argument("package_spec")
@click.option("--api-url", default="http://localhost:8000", help="URL of the scanning server")
@click.option("--json", "json_output", is_flag=True, help="Output results as JSON")
@click.option("--timeout", default=120, type=int, help="Request timeout in seconds")
def scan(package_spec: str, api_url: str, json_output: bool, timeout: int):
    """Scan a single package (e.g., axios@1.14.1)"""
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
        console.print(f"\n  [bold cyan]SupplyGuard[/bold cyan] — Scanning {package_spec}...\n")

    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(f"{api_url}/scan/package", json={"name": name, "version": version})
            resp.raise_for_status()
            res = resp.json()
    except httpx.HTTPError as e:
        if not json_output:
            console.print(f"[red]Error:[/red] Could not connect to SupplyGuard server at {api_url}.")
            console.print("Is the server running? Start it with: [bold]uvicorn supplyguard.api.server:app[/bold]")
        else:
            print(json.dumps({"error": str(e)}))
        sys.exit(1)

    if json_output:
        print(json.dumps(res, indent=2))
        sys.exit(0)

    verdict = res.get("verdict")
    conf = res.get("confidence", 0.0)
    
    if verdict == "clean":
        console.print(f"  [green]✓[/green] {package_spec} is [green]clean[/green] [dim][confidence: {conf:.2f}][/dim]")
    elif verdict == "suspicious":
        console.print(f"  [yellow]⚠[/yellow] {package_spec} is [bold yellow]SUSPICIOUS[/bold yellow] [dim][confidence: {conf:.2f}][/dim]")
        print_evidence(res)
    elif verdict == "malicious":
        console.print(f"  [red]✗[/red] {package_spec} is [bold red]MALICIOUS[/bold red] [dim][confidence: {conf:.2f}][/dim]")
        print_evidence(res)
    else:
        console.print(f"  [red]![/red] {package_spec} scan failed: {res.get('error_msg', 'Unknown error')}")

    ms = res.get("scan_time_ms", 0)
    console.print(f"\n  [dim]Scan complete in {ms/1000:.1f}s[/dim]")

@cli.command()
@click.option("--api-url", default="http://localhost:8000", help="URL of the scanning server")
@click.option("--json", "json_output", is_flag=True, help="Output results as JSON")
@click.option("--fail-on", type=click.Choice(["high", "medium", "any"]), default="high", help="Exit code 1 if packages above this severity are found")
@click.option("--lockfile", default="package-lock.json", help="Path to package-lock.json")
@click.option("--timeout", default=120, type=int, help="Request timeout in seconds")
def audit(api_url: str, json_output: bool, fail_on: str, lockfile: str, timeout: int):
    """Scan all dependencies in the current project."""
    lock_path = Path(lockfile)
    if not lock_path.exists():
        if not json_output:
            console.print(f"[red]Error:[/red] Could not find {lockfile} in the current directory.")
        else:
            print(json.dumps({"error": f"Could not find {lockfile}"}))
        sys.exit(1)

    if not json_output:
        console.print("\n  [bold cyan]SupplyGuard[/bold cyan] — Scanning dependencies...\n")

    try:
        with open(lock_path, "rb") as f:
            if not json_output:
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TimeRemainingColumn(),
                    console=console
                ) as progress:
                    task = progress.add_task("Uploading and scanning...", total=None)
                    
                    with httpx.Client(timeout=timeout) as client:
                        resp = client.post(
                            f"{api_url}/scan/lockfile", 
                            files={"lockfile": (lock_path.name, f, "application/json")}
                        )
                        progress.update(task, completed=100)
            else:
                with httpx.Client(timeout=timeout) as client:
                    resp = client.post(
                        f"{api_url}/scan/lockfile", 
                        files={"lockfile": (lock_path.name, f, "application/json")}
                    )
            resp.raise_for_status()
            res = resp.json()
    except httpx.HTTPError as e:
        if not json_output:
            console.print(f"[red]Error:[/red] Could not connect to SupplyGuard server at {api_url}.")
            console.print("Is the server running? Start it with: [bold]uvicorn supplyguard.api.server:app[/bold]")
        else:
            print(json.dumps({"error": str(e)}))
        sys.exit(1)

    if json_output:
        print(json.dumps(res, indent=2))
        sys.exit(0)

    total = res.get("total_packages", 0)
    results = res.get("results", {})
    clean = results.get("clean", 0)
    suspicious = results.get("suspicious", 0)
    malicious = results.get("malicious", 0)

    console.print(f"\n  [bold]Results:[/bold]")
    if clean > 0:
        console.print(f"  [green]✓[/green] {clean} packages clean")
    if suspicious > 0:
        console.print(f"  [yellow]⚠[/yellow] {suspicious} packages suspicious")
    if malicious > 0:
        console.print(f"  [red]✗[/red] {malicious} packages malicious")
        
    console.print()

    flagged = res.get("flagged_packages", [])
    for pkg in flagged:
        name = pkg.get("package_name")
        version = pkg.get("version")
        verdict = pkg.get("verdict")
        conf = pkg.get("confidence", 0.0)
        
        if verdict == "malicious":
            console.print(f"  [red]✗ {name}@{version}[/red]  [bold red][MALICIOUS — confidence: {conf:.2f}][/bold red]")
            print_evidence(pkg)
            console.print()
        elif verdict == "suspicious":
            console.print(f"  [yellow]⚠ {name}@{version}[/yellow]  [bold yellow][SUSPICIOUS — confidence: {conf:.2f}][/bold yellow]")
            print_evidence(pkg)
            console.print()

    console.print(f"  [dim]Scan complete in {res.get('scan_time_seconds', 0)}s[/dim]\n")

    # Exit codes
    if fail_on == "high" and malicious > 0:
        sys.exit(1)
    elif fail_on == "medium" and (malicious > 0 or suspicious > 0):
        sys.exit(1)
    elif fail_on == "any" and len(flagged) > 0:
        sys.exit(1)

if __name__ == "__main__":
    cli()
