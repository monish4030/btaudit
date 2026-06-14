"""
BTAudit CLI
============
Modern command-line interface for the Bluetooth Security Auditing Tool.

Usage:
  btaudit scan [OPTIONS]
  btaudit dashboard [OPTIONS]
  btaudit report [OPTIONS]
  btaudit consent-log

Made by Monish Paramasivam
"""

from __future__ import annotations
import asyncio
import json
import logging
import sys
import uuid
from datetime import datetime
from pathlib import Path

import click

from . import __version__
from .consent import ConsentManager, AuthorizationError
from .models import ScanSession, BluetoothProtocol
from .analyzers import SecurityAnalyzer, DeviceCategorizer
from .reporters import JSONReporter, CSVReporter, HTMLReporter

# ── Logging setup ────────────────────────────────────────────────────────

def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
        datefmt="%H:%M:%S",
    )


# ── Rich-style terminal output (no rich dependency required) ─────────────

def _header() -> None:
    click.echo(
        click.style(
            "\n  ██████╗ ████████╗ █████╗ ██╗   ██╗██████╗ ██╗████████╗\n"
            "  ██╔══██╗╚══██╔══╝██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝\n"
            "  ██████╔╝   ██║   ███████║██║   ██║██║  ██║██║   ██║   \n"
            "  ██╔══██╗   ██║   ██╔══██║██║   ██║██║  ██║██║   ██║   \n"
            "  ██████╔╝   ██║   ██║  ██║╚██████╔╝██████╔╝██║   ██║   \n"
            "  ╚═════╝    ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝  \n",
            fg="blue", bold=True,
        )
    )
    click.echo(
        click.style(f"  Bluetooth Security Auditing Tool  v{__version__}", fg="cyan")
        + click.style("  |  Made by Monish Paramasivam\n", fg="bright_black")
    )


def _risk_color(level: str) -> str:
    return {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "yellow",
            "LOW": "blue", "INFO": "bright_black"}.get(level, "white")


def _print_device_summary(device: object) -> None:
    risk = device.highest_risk.value
    color = _risk_color(risk)
    click.echo(
        f"  {click.style('●', fg=color)} "
        f"{click.style(device.name, bold=True)} "
        f"{click.style(f'[{device.address}]', fg='bright_black')}"
    )
    click.echo(
        f"    Protocol: {click.style(device.protocol.value, fg='cyan')}  "
        f"Manufacturer: {device.manufacturer}  "
        f"RSSI: {device.rssi} dBm ({device.signal_strength_label})"
    )
    click.echo(
        f"    Risk: {click.style(risk, fg=color, bold=True)}  "
        f"Score: {device.risk_score}/100  "
        f"Findings: {len(device.findings)}"
    )
    if device.services:
        svc_names = ", ".join(s.name for s in device.services[:4])
        extra = f" +{len(device.services)-4} more" if len(device.services) > 4 else ""
        click.echo(f"    Services: {click.style(svc_names + extra, fg='bright_black')}")
    for finding in device.findings:
        fc = _risk_color(finding.risk_level.value)
        click.echo(
            f"    {click.style(f'[{finding.finding_id}]', fg=fc)} "
            f"{click.style(finding.title, fg=fc)}"
        )
    click.echo()


# ── CLI group ────────────────────────────────────────────────────────────

@click.group()
@click.version_option(__version__, prog_name="btaudit")
def cli() -> None:
    """
    BTAudit — Bluetooth Security Auditing & Inventory Tool.

    \b
    LEGAL NOTICE: For authorized environments only.
    Made by Monish Paramasivam.
    """
    pass


# ── Scan command ──────────────────────────────────────────────────────────

@cli.command()
@click.option("--duration", "-d", default=15, show_default=True,
              help="Scan duration in seconds.")
@click.option("--ble/--no-ble", default=True, show_default=True,
              help="Scan Bluetooth Low Energy devices.")
@click.option("--classic/--no-classic", default=True, show_default=True,
              help="Scan Bluetooth Classic devices.")
@click.option("--active-scan", is_flag=True, default=False,
              help="Enable BLE active scanning (sends scan request packets).")
@click.option("--output", "-o", default="./reports", show_default=True,
              type=click.Path(), help="Output directory for reports.")
@click.option("--format", "-f", "fmt",
              type=click.Choice(["json", "csv", "html", "all"], case_sensitive=False),
              default="all", show_default=True, help="Report format(s) to generate.")
@click.option("--authorized-by", "-a", default="",
              help="Authorization reference or name (skips interactive prompt).")
@click.option("--environment", "-e", default="",
              help="Description of the authorized environment.")
@click.option("--non-interactive", is_flag=True, default=False,
              help="Non-interactive mode (requires BTAUDIT_AUTHORIZED=1 env var).")
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Enable verbose debug logging.")
@click.option("--json-output", is_flag=True, default=False,
              help="Print JSON results to stdout (for scripting).")
def scan(
    duration: int,
    ble: bool,
    classic: bool,
    active_scan: bool,
    output: str,
    fmt: str,
    authorized_by: str,
    environment: str,
    non_interactive: bool,
    verbose: bool,
    json_output: bool,
) -> None:
    """Discover and audit nearby Bluetooth devices."""
    setup_logging(verbose)
    if not json_output:
        _header()

    # ── Consent gate ─────────────────────────────────────────────────────
    consent_mgr = ConsentManager()
    try:
        consent = consent_mgr.prompt_for_consent(
            authorized_by=authorized_by,
            environment=environment,
            non_interactive=non_interactive,
        )
        if not json_output:
            click.echo(
                click.style("  ✓ Authorization recorded. ", fg="green")
                + click.style(f"Hash: {consent.consent_hash[:16]}…\n", fg="bright_black")
            )
    except AuthorizationError as exc:
        click.echo(click.style(f"\n  ✗ Authorization failed: {exc}\n", fg="red"), err=True)
        sys.exit(1)

    # ── Run scanners ──────────────────────────────────────────────────────
    session_id = str(uuid.uuid4())[:8]
    started_at = datetime.utcnow()
    all_devices: dict[str, object] = {}

    analyzer = SecurityAnalyzer()
    categorizer = DeviceCategorizer()

    def on_device(device: object) -> None:
        categorizer.categorize(device)
        analyzer.analyze(device)
        all_devices[device.address] = device
        if not json_output:
            _print_device_summary(device)

    if not json_output:
        click.echo(
            click.style(f"  Scanning for {duration}s", fg="cyan")
            + (" [BLE]" if ble else "")
            + (" [Classic]" if classic else "")
            + (" [Active]" if active_scan else " [Passive]")
            + "\n"
        )

    if ble:
        from .scanners import BLEScanner
        scanner = BLEScanner(
            scan_duration=float(duration),
            active_scan=active_scan,
            callback=on_device,
        )
        try:
            asyncio.run(scanner.scan())
        except KeyboardInterrupt:
            click.echo(click.style("\n  Scan interrupted by user.\n", fg="yellow"))

    if classic:
        from .scanners import ClassicScanner
        cscan = ClassicScanner(
            scan_duration=duration,
            callback=on_device,
        )
        try:
            cscan.scan()
        except KeyboardInterrupt:
            pass

    ended_at = datetime.utcnow()
    duration_actual = (ended_at - started_at).total_seconds()

    # ── Build session ──────────────────────────────────────────────────────
    session = ScanSession(
        session_id=session_id,
        started_at=started_at,
        ended_at=ended_at,
        duration_seconds=duration_actual,
        scan_type="active" if active_scan else "passive",
        devices=list(all_devices.values()),
        authorized_by=consent.authorized_by,
        scan_environment=consent.environment_description,
        tool_version=__version__,
    )

    # ── Output ────────────────────────────────────────────────────────────
    if json_output:
        click.echo(json.dumps(session.to_dict(), indent=2, default=str))
        return

    output_dir = Path(output)
    generated: list[Path] = []

    if fmt in ("json", "all"):
        generated.append(JSONReporter(output_dir).generate(session))
    if fmt in ("csv", "all"):
        generated.append(CSVReporter(output_dir).generate(session))
    if fmt in ("html", "all"):
        generated.append(HTMLReporter(output_dir).generate(session))

    # ── Summary ───────────────────────────────────────────────────────────
    summary = session.to_dict()["summary"]
    click.echo(click.style("  ─" * 30, fg="bright_black"))
    click.echo(click.style("  Scan Complete\n", bold=True))
    click.echo(f"  Devices found : {click.style(str(summary['total_devices']), bold=True)}")
    click.echo(f"  BLE           : {summary['ble_devices']}")
    click.echo(f"  Classic       : {summary['classic_devices']}")
    click.echo(f"  Critical      : {click.style(str(summary['critical_findings']), fg='red', bold=True)}")
    click.echo(f"  High          : {click.style(str(summary['high_findings']), fg='yellow', bold=True)}")
    click.echo(f"  Avg Risk Score: {summary['average_risk_score']:.0f}/100")
    click.echo(f"  Duration      : {duration_actual:.1f}s\n")

    if generated:
        click.echo("  Reports written:")
        for p in generated:
            click.echo(f"  {click.style('→', fg='green')} {p}")
    click.echo()


# ── Dashboard command ─────────────────────────────────────────────────────

@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Dashboard bind host.")
@click.option("--port", "-p", default=8080, show_default=True,
              help="Dashboard port.")
@click.option("--verbose", "-v", is_flag=True, default=False)
def dashboard(host: str, port: int, verbose: bool) -> None:
    """Launch the real-time web dashboard."""
    setup_logging(verbose)
    _header()

    try:
        import uvicorn
        from .dashboard import create_app
    except ImportError:
        click.echo(
            click.style(
                "  Dashboard requires additional dependencies.\n"
                "  Install with: pip install btaudit[dashboard]\n",
                fg="red",
            )
        )
        sys.exit(1)

    app = create_app()
    if app is None:
        click.echo(click.style("  Failed to create dashboard app.", fg="red"))
        sys.exit(1)

    click.echo(
        click.style(f"  Dashboard running at ", fg="cyan")
        + click.style(f"http://{host}:{port}", fg="green", bold=True)
        + click.style("\n  Press Ctrl+C to stop.\n", fg="bright_black")
    )
    uvicorn.run(app, host=host, port=port, log_level="warning")


# ── Consent-log command ───────────────────────────────────────────────────

@cli.command("consent-log")
def consent_log() -> None:
    """Display the authorization consent audit log."""
    _header()
    mgr = ConsentManager()
    records = mgr.get_consent_history()
    if not records:
        click.echo("  No consent records found.\n")
        return
    click.echo(click.style(f"  {len(records)} consent record(s) on file:\n", bold=True))
    for rec in records:
        click.echo(
            f"  {click.style(rec['timestamp'], fg='bright_black')}  "
            f"{click.style(rec['user'], fg='cyan')}@{rec['hostname']}  "
            f"auth_by={rec['authorized_by']}  "
            f"hash={rec['consent_hash'][:16]}…"
        )
    click.echo()


# ── Report command ────────────────────────────────────────────────────────

@cli.command()
@click.argument("input_json", type=click.Path(exists=True))
@click.option("--format", "-f", "fmt",
              type=click.Choice(["csv", "html", "all"], case_sensitive=False),
              default="all")
@click.option("--output", "-o", default="./reports", type=click.Path())
def report(input_json: str, fmt: str, output: str) -> None:
    """Re-generate reports from an existing JSON scan file."""
    _header()
    data = json.loads(Path(input_json).read_text())

    from .models import BluetoothDevice, ScanSession, BluetoothProtocol, DeviceCategory
    from .models import SecurityFinding, ServiceRecord, RiskLevel

    # Reconstruct session from JSON (simplified)
    session = ScanSession(
        session_id=data.get("session_id", "imported"),
        started_at=datetime.fromisoformat(data["started_at"]),
        ended_at=datetime.fromisoformat(data["ended_at"]) if data.get("ended_at") else None,
        duration_seconds=data.get("duration_seconds", 0),
        authorized_by=data.get("authorized_by", ""),
        scan_environment=data.get("scan_environment", ""),
        tool_version=data.get("tool_version", __version__),
    )

    output_dir = Path(output)
    if fmt in ("csv", "all"):
        p = CSVReporter(output_dir).generate(session)
        click.echo(f"  → {p}")
    if fmt in ("html", "all"):
        p = HTMLReporter(output_dir).generate(session)
        click.echo(f"  → {p}")
    click.echo()


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
