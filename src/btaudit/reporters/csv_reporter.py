"""
CSV Report Generator
======================
Exports scan session data to a flat CSV file suitable for spreadsheet analysis.

Made by Monish Paramasivam
"""

from __future__ import annotations
import csv
import io
import logging
from datetime import datetime
from pathlib import Path

from ..models import ScanSession, BluetoothDevice, RiskLevel

logger = logging.getLogger(__name__)

CSV_HEADERS = [
    "address",
    "name",
    "manufacturer",
    "protocol",
    "category",
    "rssi",
    "signal_strength",
    "distance_estimate",
    "tx_power",
    "is_connectable",
    "is_discoverable",
    "service_count",
    "service_names",
    "risk_score",
    "highest_risk",
    "finding_count",
    "finding_titles",
    "first_seen",
    "last_seen",
]


def _device_to_row(device: BluetoothDevice) -> dict[str, str]:
    return {
        "address": device.address,
        "name": device.name,
        "manufacturer": device.manufacturer,
        "protocol": device.protocol.value,
        "category": device.category.value,
        "rssi": str(device.rssi),
        "signal_strength": device.signal_strength_label,
        "distance_estimate": device.distance_estimate,
        "tx_power": str(device.tx_power) if device.tx_power is not None else "",
        "is_connectable": str(device.is_connectable),
        "is_discoverable": str(device.is_discoverable),
        "service_count": str(len(device.services)),
        "service_names": "; ".join(s.name for s in device.services),
        "risk_score": str(device.risk_score),
        "highest_risk": device.highest_risk.value,
        "finding_count": str(len(device.findings)),
        "finding_titles": "; ".join(f.title for f in device.findings),
        "first_seen": device.first_seen.isoformat(),
        "last_seen": device.last_seen.isoformat(),
    }


class CSVReporter:
    """Generates flat CSV reports from a ScanSession."""

    def __init__(self, output_dir: Path | str = Path(".")) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        session: ScanSession,
        filename: str | None = None,
    ) -> Path:
        """Write session data to a CSV file and return the output path."""
        if not filename:
            ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            filename = f"btaudit_report_{ts}.csv"

        output_path = self.output_dir / filename
        with output_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=CSV_HEADERS)
            writer.writeheader()
            for device in session.devices:
                writer.writerow(_device_to_row(device))

        logger.info("CSV report written to %s", output_path)
        return output_path

    def to_string(self, session: ScanSession) -> str:
        """Return the CSV as a string."""
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=CSV_HEADERS)
        writer.writeheader()
        for device in session.devices:
            writer.writerow(_device_to_row(device))
        return buf.getvalue()
