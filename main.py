#!/usr/bin/env python3
"""
shadowmap: Passive attack surface mapper.
Maps the external attack surface of a domain using only passive,
non-intrusive techniques — certificate transparency, DNS records,
and public HTTP probing.

Usage:
    python main.py map example.com
    python main.py map example.com --output json > surface.json
    python main.py map example.com --ai-analysis --report report.md
"""

import json
import click
from openai import OpenAI
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.recon import map_attack_surface

console = Console()
ai_client = OpenAI()


@click.group()
@click.version_option("1.0.0", prog_name="shadowmap")
def cli():
    """shadowmap — Passive attack surface mapper for security teams."""
    pass


@cli.command()
@click.argument("domain")
@click.option("--output", default="table",
              type=click.Choice(["table", "json", "markdown"], case_sensitive=False),
              help="Output format.")
@click.option("--ai-analysis", is_flag=True, default=False,
              help="Generate AI-powered risk analysis and recommendations.")
@click.option("--report", default=None, help="Save full report to a Markdown file.")
@click.option("--no-http", is_flag=True, default=False,
              help="Skip HTTP probing (faster, less intrusive).")
@click.option("--workers", default=20, show_default=True,
              help="Number of parallel workers for subdomain enrichment.")
def map(domain, output, ai_analysis, report, no_http, workers):
    """Map the passive attack surface of a domain.

    \b
    Examples:
        python main.py map example.com
        python main.py map example.com --ai-analysis --report surface_report.md
        python main.py map example.com --output json | jq '.subdomains[] | select(.risk_flags | length > 0)'
    """
    console.print(Panel(
        f"[bold cyan]shadowmap[/bold cyan] — passive recon for [bold]{domain}[/bold]\n"
        f"HTTP probing: {'disabled' if no_http else 'enabled'} | Workers: {workers}",
        expand=False
    ))

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console, transient=True) as progress:
        task = progress.add_task(f"Mapping attack surface for {domain}...", total=None)
        surface = map_attack_surface(
            domain,
            resolve_ips=True,
            fetch_http=not no_http,
            max_workers=workers,
        )
        progress.update(task, description=f"Found {len(surface.subdomains)} subdomains.")

    if output == "json":
        print(json.dumps(surface.to_dict(), indent=2))
        return

    # Display DNS records
    if surface.dns_records:
        dns_table = Table(title="DNS Records", show_header=True, header_style="bold blue")
        dns_table.add_column("Type", style="cyan", width=8)
        dns_table.add_column("Records")
        for rtype, values in surface.dns_records.items():
            if values:
                dns_table.add_row(rtype, "\n".join(values[:5]))
        console.print(dns_table)

    # Display subdomains
    sub_table = Table(
        title=f"Subdomains ({len(surface.subdomains)} found)",
        show_header=True, header_style="bold magenta"
    )
    sub_table.add_column("Subdomain", style="cyan")
    sub_table.add_column("IP", width=16)
    sub_table.add_column("HTTP", width=6)
    sub_table.add_column("Title", max_width=40)
    sub_table.add_column("Risk Flags", style="red")

    flagged = sorted(surface.subdomains, key=lambda s: len(s.risk_flags), reverse=True)
    for s in flagged[:50]:
        flags = "; ".join(s.risk_flags) if s.risk_flags else "[green]—[/green]"
        sub_table.add_row(
            s.subdomain,
            s.ip or "—",
            str(s.http_status) if s.http_status else "—",
            s.title or "—",
            flags,
        )
    console.print(sub_table)

    if len(surface.subdomains) > 50:
        console.print(f"[dim]... and {len(surface.subdomains) - 50} more. Use --output json for full results.[/dim]")

    # Risk summary
    if surface.risk_summary:
        console.print(Panel("\n".join(surface.risk_summary), title="Risk Summary", border_style="yellow"))

    if ai_analysis:
        with Progress(SpinnerColumn(), TextColumn("Generating AI risk analysis..."),
                      console=console, transient=True) as progress:
            progress.add_task("", total=None)
            ai_report = _generate_ai_analysis(surface)
        console.print(Markdown(ai_report))

        if report:
            with open(report, "w") as f:
                f.write(f"# shadowmap Report: {domain}\n\n")
                f.write(f"**Subdomains found:** {len(surface.subdomains)}\n\n---\n\n")
                f.write(ai_report)
            console.print(f"[bold green]✓ Report saved to {report}[/bold green]")


def _generate_ai_analysis(surface) -> str:
    """Generate AI-powered attack surface risk analysis."""
    flagged = [s for s in surface.subdomains if s.risk_flags]
    live = [s for s in surface.subdomains if s.http_status and s.http_status < 400]

    summary = {
        "domain": surface.domain,
        "total_subdomains": len(surface.subdomains),
        "live_subdomains": len(live),
        "flagged_subdomains": len(flagged),
        "dns_records": surface.dns_records,
        "risk_flags_sample": [
            {"subdomain": s.subdomain, "ip": s.ip, "status": s.http_status,
             "flags": s.risk_flags, "title": s.title}
            for s in flagged[:15]
        ],
    }

    prompt = f"""You are a senior penetration tester performing an attack surface assessment.
Analyze the following passive reconnaissance data for {surface.domain} and provide:

1. **Executive Summary** — Overall attack surface risk level and key findings.
2. **High-Risk Assets** — Which subdomains pose the greatest risk and why?
3. **Exposed Services** — Any admin panels, dev environments, or sensitive services?
4. **Recommended Investigation** — What should a pentester investigate further?
5. **Defensive Recommendations** — How should the organization reduce their attack surface?

Recon Data:
{json.dumps(summary, indent=2)}

Format in Markdown."""

    try:
        response = ai_client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": "You are an expert penetration tester and attack surface analyst."},
                {"role": "user", "content": prompt},
            ]
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"AI analysis unavailable: {e}"


if __name__ == "__main__":
    cli()
