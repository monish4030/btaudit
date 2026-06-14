"""
Core data models for BTAudit.

Made by Monish Paramasivam
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class BluetoothProtocol(str, Enum):
    CLASSIC = "Bluetooth Classic"
    BLE = "Bluetooth Low Energy"
    DUAL = "Dual Mode (Classic + BLE)"
    UNKNOWN = "Unknown"


class RiskLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class DeviceCategory(str, Enum):
    PHONE = "Mobile Phone"
    LAPTOP = "Laptop/Computer"
    HEADSET = "Audio/Headset"
    KEYBOARD = "Keyboard/Input"
    MEDICAL = "Medical Device"
    IOT = "IoT/Smart Device"
    VEHICLE = "Automotive"
    WEARABLE = "Wearable"
    PERIPHERAL = "Peripheral"
    UNKNOWN = "Unknown"


@dataclass
class ServiceRecord:
    """Represents a Bluetooth service advertised by a device."""
    uuid: str
    name: str
    protocol: str = "Unknown"
    description: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "uuid": self.uuid,
            "name": self.name,
            "protocol": self.protocol,
            "description": self.description,
        }


@dataclass
class SecurityFinding:
    """Represents a detected security misconfiguration or concern."""
    finding_id: str
    title: str
    description: str
    risk_level: RiskLevel
    recommendation: str
    reference: str = ""
    cve: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "risk_level": self.risk_level.value,
            "recommendation": self.recommendation,
            "reference": self.reference,
            "cve": self.cve,
        }


@dataclass
class BluetoothDevice:
    """
    Represents a discovered Bluetooth device with all collected metadata.
    No exploitation is performed — data is passive/observed only.
    """
    address: str
    name: str = "Unknown"
    rssi: int = -100
    protocol: BluetoothProtocol = BluetoothProtocol.UNKNOWN
    category: DeviceCategory = DeviceCategory.UNKNOWN
    manufacturer: str = "Unknown"
    manufacturer_data: dict[int, bytes] = field(default_factory=dict)
    services: list[ServiceRecord] = field(default_factory=list)
    service_uuids: list[str] = field(default_factory=list)
    tx_power: int | None = None
    is_connectable: bool = False
    is_discoverable: bool = True
    raw_advertisement: bytes | None = None
    first_seen: datetime = field(default_factory=datetime.utcnow)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    findings: list[SecurityFinding] = field(default_factory=list)
    risk_score: int = 0
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def signal_strength_label(self) -> str:
        if self.rssi >= -50:
            return "Excellent"
        elif self.rssi >= -70:
            return "Good"
        elif self.rssi >= -85:
            return "Fair"
        else:
            return "Poor"

    @property
    def distance_estimate(self) -> str:
        """Rough distance estimate based on RSSI (not precise)."""
        if self.rssi >= -50:
            return "< 1m"
        elif self.rssi >= -60:
            return "1–3m"
        elif self.rssi >= -70:
            return "3–10m"
        elif self.rssi >= -80:
            return "10–30m"
        else:
            return "> 30m"

    @property
    def highest_risk(self) -> RiskLevel:
        if not self.findings:
            return RiskLevel.INFO
        order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]
        for level in order:
            if any(f.risk_level == level for f in self.findings):
                return level
        return RiskLevel.INFO

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "name": self.name,
            "rssi": self.rssi,
            "signal_strength": self.signal_strength_label,
            "distance_estimate": self.distance_estimate,
            "protocol": self.protocol.value,
            "category": self.category.value,
            "manufacturer": self.manufacturer,
            "manufacturer_data": {
                str(k): v.hex() for k, v in self.manufacturer_data.items()
            },
            "services": [s.to_dict() for s in self.services],
            "service_uuids": self.service_uuids,
            "tx_power": self.tx_power,
            "is_connectable": self.is_connectable,
            "is_discoverable": self.is_discoverable,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "findings": [f.to_dict() for f in self.findings],
            "risk_score": self.risk_score,
            "highest_risk": self.highest_risk.value,
        }


@dataclass
class ScanSession:
    """Represents a complete scan session with metadata."""
    session_id: str
    started_at: datetime
    ended_at: datetime | None = None
    duration_seconds: float = 0.0
    scan_type: str = "passive"
    devices: list[BluetoothDevice] = field(default_factory=list)
    authorized_by: str = ""
    scan_environment: str = ""
    operator_notes: str = ""
    tool_version: str = "1.0.0"
    author: str = "Monish Paramasivam"

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_seconds": self.duration_seconds,
            "scan_type": self.scan_type,
            "device_count": len(self.devices),
            "devices": [d.to_dict() for d in self.devices],
            "authorized_by": self.authorized_by,
            "scan_environment": self.scan_environment,
            "operator_notes": self.operator_notes,
            "tool_version": self.tool_version,
            "author": self.author,
            "summary": {
                "total_devices": len(self.devices),
                "classic_devices": sum(1 for d in self.devices if d.protocol == BluetoothProtocol.CLASSIC),
                "ble_devices": sum(1 for d in self.devices if d.protocol == BluetoothProtocol.BLE),
                "critical_findings": sum(1 for d in self.devices if d.highest_risk == RiskLevel.CRITICAL),
                "high_findings": sum(1 for d in self.devices if d.highest_risk == RiskLevel.HIGH),
                "average_risk_score": (
                    sum(d.risk_score for d in self.devices) / len(self.devices)
                    if self.devices else 0
                ),
            },
        }
