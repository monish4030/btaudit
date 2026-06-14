"""
HTML Report Generator
======================
Generates a self-contained, professional HTML security report
with risk summaries, device tables, and finding details.

Made by Monish Paramasivam
"""

from __future__ import annotations
import logging
from datetime import datetime
from pathlib import Path

from ..models import ScanSession, BluetoothDevice, RiskLevel

logger = logging.getLogger(__name__)

RISK_COLORS = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ea580c",
    "MEDIUM":   "#d97706",
    "LOW":      "#2563eb",
    "INFO":     "#6b7280",
}

RISK_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fffbeb",
    "LOW":      "#eff6ff",
    "INFO":     "#f9fafb",
}


def _risk_badge(level: str) -> str:
    color = RISK_COLORS.get(level, "#6b7280")
    bg = RISK_BG.get(level, "#f9fafb")
    return (
        f'<span style="background:{bg};color:{color};border:1px solid {color};'
        f'padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;'
        f'letter-spacing:.5px;">{level}</span>'
    )


def _score_bar(score: int) -> str:
    color = "#22c55e"
    if score >= 70:
        color = RISK_COLORS["CRITICAL"]
    elif score >= 50:
        color = RISK_COLORS["HIGH"]
    elif score >= 30:
        color = RISK_COLORS["MEDIUM"]
    elif score >= 10:
        color = RISK_COLORS["LOW"]
    return (
        f'<div style="display:flex;align-items:center;gap:8px;">'
        f'<div style="flex:1;height:8px;background:#e5e7eb;border-radius:4px;">'
        f'<div style="width:{score}%;height:100%;background:{color};border-radius:4px;"></div>'
        f'</div><span style="font-weight:700;color:{color};min-width:28px;">{score}</span></div>'
    )


def _device_card(device: BluetoothDevice) -> str:
    risk_color = RISK_COLORS.get(device.highest_risk.value, "#6b7280")
    services_html = ""
    if device.services:
        items = "".join(
            f'<li style="padding:3px 0;border-bottom:1px solid #f3f4f6;font-size:13px;">'
            f'<code style="color:#6366f1;font-size:12px;">{s.uuid[:8]}…</code> '
            f'<strong>{s.name}</strong> <span style="color:#9ca3af;">({s.protocol})</span></li>'
            for s in device.services
        )
        services_html = f'<ul style="margin:8px 0 0;padding-left:0;list-style:none;">{items}</ul>'

    findings_html = ""
    if device.findings:
        finding_parts: list[str] = []
        for f in device.findings:
            bc = RISK_COLORS.get(f.risk_level.value, "#6b7280")
            bg = RISK_BG.get(f.risk_level.value, "#f9fafb")
            ref_html = (
                f'<p style="margin:4px 0;font-size:12px;color:#9ca3af;">'
                f'<strong>Reference:</strong> {f.reference}</p>'
                if f.reference else ""
            )
            part = (
                f'<div style="border-left:3px solid {bc};padding:8px 12px;margin:8px 0;'
                f'background:{bg};border-radius:0 6px 6px 0;">'
                f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">'
                f'{_risk_badge(f.risk_level.value)}'
                f'<strong style="font-size:13px;">[{f.finding_id}] {f.title}</strong></div>'
                f'<p style="margin:4px 0;font-size:13px;color:#374151;">{f.description}</p>'
                f'<p style="margin:4px 0;font-size:12px;color:#6b7280;">'
                f'<strong>Recommendation:</strong> {f.recommendation}</p>'
                + ref_html
                + '</div>'
            )
            finding_parts.append(part)
        findings_html = '<div style="margin-top:12px;">' + "".join(finding_parts) + "</div>"

    mfr_data_html = ""
    if device.manufacturer_data:
        entries = "; ".join(
            f"0x{cid:04X}: {data.hex()}"
            for cid, data in device.manufacturer_data.items()
        )
        mfr_data_html = f'<div style="font-size:12px;color:#6b7280;margin-top:4px;font-family:monospace;">{entries}</div>'

    return f"""
<div style="background:#fff;border:1px solid #e5e7eb;border-radius:10px;
     margin-bottom:20px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.06);">
  <div style="padding:14px 18px;background:#f8fafc;border-bottom:1px solid #e5e7eb;
       display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
    <div>
      <span style="font-size:16px;font-weight:700;color:#111;">{device.name}</span>
      <code style="margin-left:8px;font-size:12px;color:#6b7280;background:#f1f5f9;
           padding:2px 6px;border-radius:4px;">{device.address}</code>
    </div>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
      {_risk_badge(device.highest_risk.value)}
      <span style="font-size:12px;color:#6b7280;background:#f1f5f9;padding:2px 8px;
           border-radius:4px;">{device.protocol.value}</span>
      <span style="font-size:12px;color:#6b7280;background:#f1f5f9;padding:2px 8px;
           border-radius:4px;">{device.category.value}</span>
    </div>
  </div>
  <div style="padding:16px 18px;">
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:14px;">
      <div><span style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#9ca3af;">Manufacturer</span>
           <div style="font-weight:600;color:#374151;">{device.manufacturer}</div></div>
      <div><span style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#9ca3af;">RSSI</span>
           <div style="font-weight:600;color:#374151;">{device.rssi} dBm — {device.signal_strength_label} ({device.distance_estimate})</div></div>
      <div><span style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#9ca3af;">TX Power</span>
           <div style="font-weight:600;color:#374151;">{str(device.tx_power) + " dBm" if device.tx_power is not None else "—"}</div></div>
      <div><span style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#9ca3af;">Connectable</span>
           <div style="font-weight:600;color:#374151;">{"Yes" if device.is_connectable else "No"}</div></div>
      <div><span style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#9ca3af;">First Seen</span>
           <div style="font-weight:600;color:#374151;">{device.first_seen.strftime("%H:%M:%S UTC")}</div></div>
      <div><span style="font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:#9ca3af;">Risk Score</span>
           <div style="margin-top:4px;">{_score_bar(device.risk_score)}</div></div>
    </div>
    {mfr_data_html}
    {"<h4 style='margin:14px 0 6px;font-size:13px;color:#374151;'>Advertised Services</h4>" + services_html if device.services else ""}
    {"<h4 style='margin:14px 0 6px;font-size:13px;color:#374151;'>Security Findings</h4>" + findings_html if device.findings else ""}
  </div>
</div>"""


class HTMLReporter:
    """Generates a self-contained HTML security report."""

    def __init__(self, output_dir: Path | str = Path(".")) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        session: ScanSession,
        filename: str | None = None,
    ) -> Path:
        if not filename:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"btaudit_report_{ts}.html"

        output_path = self.output_dir / filename
        output_path.write_text(self._render(session), encoding="utf-8")
        logger.info("HTML report written to %s", output_path)
        return output_path

    def to_string(self, session: ScanSession) -> str:
        return self._render(session)

    def _render(self, session: ScanSession) -> str:
        summary = session.to_dict()["summary"]
        devices_html = "".join(_device_card(d) for d in session.devices)
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        # Stat cards
        def stat_card(label: str, value: str, color: str = "#374151") -> str:
            return (
                f'<div style="background:#fff;border:1px solid #e5e7eb;border-radius:10px;'
                f'padding:20px;text-align:center;">'
                f'<div style="font-size:32px;font-weight:800;color:{color};">{value}</div>'
                f'<div style="font-size:12px;text-transform:uppercase;letter-spacing:.5px;'
                f'color:#9ca3af;margin-top:4px;">{label}</div></div>'
            )

        stats_html = (
            stat_card("Total Devices", str(summary["total_devices"]))
            + stat_card("BLE", str(summary["ble_devices"]), "#6366f1")
            + stat_card("Classic", str(summary["classic_devices"]), "#0891b2")
            + stat_card("Critical", str(summary["critical_findings"]), RISK_COLORS["CRITICAL"])
            + stat_card("High", str(summary["high_findings"]), RISK_COLORS["HIGH"])
            + stat_card("Avg Risk Score", f'{summary["average_risk_score"]:.0f}', "#d97706")
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>BTAudit Security Report — {session.session_id}</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
         background:#f1f5f9;color:#111;min-height:100vh;}}
    .container{{max-width:1100px;margin:0 auto;padding:32px 20px;}}
    @media(max-width:640px){{.container{{padding:16px 12px;}}}}
    @media print{{body{{background:#fff;}}.no-print{{display:none;}}}}
  </style>
</head>
<body>
<div class="container">

  <!-- Header -->
  <div style="background:linear-gradient(135deg,#0f172a 0%,#1e3a5f 100%);
       border-radius:14px;padding:32px;margin-bottom:28px;color:#fff;">
    <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px;">
      <div>
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:2px;
             color:#94a3b8;margin-bottom:8px;">Security Assessment Report</div>
        <h1 style="font-size:28px;font-weight:800;letter-spacing:-.5px;">
          🔵 BTAudit
        </h1>
        <div style="font-size:13px;color:#94a3b8;margin-top:6px;">
          Bluetooth Security Auditing &amp; Inventory Tool
        </div>
        <div style="font-size:12px;color:#64748b;margin-top:4px;">
          Made by <strong style="color:#93c5fd;">Monish Paramasivam</strong>
        </div>
      </div>
      <div style="text-align:right;">
        <div style="font-size:12px;color:#94a3b8;">Session ID</div>
        <code style="font-size:13px;color:#e2e8f0;">{session.session_id}</code>
        <div style="font-size:12px;color:#94a3b8;margin-top:8px;">Generated</div>
        <div style="font-size:13px;color:#e2e8f0;">{ts}</div>
        <div style="font-size:12px;color:#94a3b8;margin-top:8px;">Duration</div>
        <div style="font-size:13px;color:#e2e8f0;">{session.duration_seconds:.1f}s</div>
      </div>
    </div>
    {"<div style='margin-top:16px;padding:12px;background:rgba(255,255,255,.07);border-radius:8px;font-size:13px;color:#94a3b8;'><strong style='color:#cbd5e1;'>Authorized by:</strong> " + session.authorized_by + " &nbsp;|&nbsp; <strong style='color:#cbd5e1;'>Environment:</strong> " + session.scan_environment + "</div>" if session.authorized_by else ""}
  </div>

  <!-- Legal notice -->
  <div style="background:#fefce8;border:1px solid #fde047;border-radius:10px;
       padding:14px 18px;margin-bottom:28px;font-size:13px;color:#854d0e;">
    ⚠️ <strong>Authorized Use Only.</strong> This report was generated by BTAudit for
    defensive security assessment in an authorized environment. Unauthorized scanning of
    Bluetooth devices may violate the CFAA, Computer Misuse Act, and equivalent legislation.
    All findings are observational — no exploitation was attempted.
  </div>

  <!-- Stats -->
  <h2 style="font-size:16px;font-weight:700;color:#374151;margin-bottom:14px;">Scan Summary</h2>
  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
       gap:14px;margin-bottom:32px;">
    {stats_html}
  </div>

  <!-- Devices -->
  <h2 style="font-size:16px;font-weight:700;color:#374151;margin-bottom:14px;">
    Discovered Devices ({len(session.devices)})
  </h2>
  {devices_html if devices_html else '<div style="text-align:center;padding:48px;color:#9ca3af;">No devices discovered in this scan session.</div>'}

  <!-- Footer -->
  <div style="border-top:1px solid #e5e7eb;margin-top:32px;padding-top:20px;
       display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;
       font-size:12px;color:#9ca3af;">
    <div>BTAudit v{session.tool_version} — Made by <strong>Monish Paramasivam</strong></div>
    <div>NIST SP 800-121 Rev 2 · Bluetooth SIG Security · OWASP IoT</div>
  </div>

</div>
</body>
</html>"""
