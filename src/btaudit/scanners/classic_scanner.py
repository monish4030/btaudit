"""
Bluetooth Classic Scanner
==========================
Passive discovery of Bluetooth Classic (BR/EDR) devices using PyBluez.
Performs inquiry scan and SDP service record lookup only.
No connection or pairing is attempted.

Made by Monish Paramasivam
"""

from __future__ import annotations
import logging
import platform
import subprocess
from datetime import datetime
from typing import Callable

from ..models import BluetoothDevice, BluetoothProtocol, ServiceRecord
from ..oui_db import lookup_manufacturer_by_mac, lookup_service_name, is_sensitive_service
from ..consent import TransmissionGuard

logger = logging.getLogger(__name__)


class ClassicScanner:
    """
    Bluetooth Classic device discoverer.

    Uses OS-level inquiry mechanisms:
    - Linux: PyBluez or hcitool (subprocess, read-only)
    - macOS: system_profiler (read-only)
    - Windows: PyBluez or WMI (read-only)

    SDP (Service Discovery Protocol) browsing is performed
    without initiating a data-plane connection.
    """

    def __init__(
        self,
        scan_duration: int = 10,
        lookup_services: bool = True,
        callback: Callable[[BluetoothDevice], None] | None = None,
    ) -> None:
        TransmissionGuard.validate_scan_parameters(connect=False, pair=False)
        self.scan_duration = scan_duration
        self.lookup_services = lookup_services
        self.callback = callback
        self._platform = platform.system().lower()

    def scan(self) -> list[BluetoothDevice]:
        """Run Bluetooth Classic inquiry. Returns list of BluetoothDevice."""
        logger.info(
            "Starting Bluetooth Classic scan (duration=%ds)", self.scan_duration
        )

        try:
            return self._scan_with_pybluez()
        except ImportError:
            logger.warning("PyBluez not available; trying system fallback.")
        except Exception as exc:
            logger.warning("PyBluez scan failed: %s; trying system fallback.", exc)

        if self._platform == "linux":
            return self._scan_linux_hcitool()
        elif self._platform == "darwin":
            return self._scan_macos()
        else:
            logger.error(
                "No Bluetooth Classic scanner available on this platform. "
                "Install PyBluez: pip install pybluez2"
            )
            return []

    def _scan_with_pybluez(self) -> list[BluetoothDevice]:
        """Primary scanner using PyBluez."""
        import bluetooth  # type: ignore

        nearby = bluetooth.discover_devices(
            duration=self.scan_duration,
            lookup_names=True,
            flush_cache=True,
            lookup_class=True,
        )

        devices: list[BluetoothDevice] = []
        for address, name, device_class in nearby:
            services = self._get_sdp_services_pybluez(address, bluetooth)
            mfr = lookup_manufacturer_by_mac(address)
            now = datetime.utcnow()
            dev = BluetoothDevice(
                address=address,
                name=name or "Unknown",
                rssi=-70,  # Classic inquiry doesn't return RSSI by default
                protocol=BluetoothProtocol.CLASSIC,
                manufacturer=mfr,
                services=services,
                service_uuids=[s.uuid for s in services],
                is_connectable=True,
                is_discoverable=True,
                first_seen=now,
                last_seen=now,
                extra={"device_class": device_class},
            )
            devices.append(dev)
            logger.debug("Classic device: %s [%s]", name, address)
            if self.callback:
                self.callback(dev)

        return devices

    def _get_sdp_services_pybluez(
        self, address: str, bluetooth_module: object
    ) -> list[ServiceRecord]:
        """Browse SDP service records for a device."""
        if not self.lookup_services:
            return []
        try:
            records = bluetooth_module.find_service(address=address)
            services: list[ServiceRecord] = []
            for rec in records:
                uuid = str(rec.get("service-id") or rec.get("profiles", [{}])[0].get("id", "unknown"))
                name = rec.get("name", lookup_service_name(uuid))
                proto = rec.get("protocol", "Unknown")
                services.append(
                    ServiceRecord(
                        uuid=uuid,
                        name=name,
                        protocol=proto,
                        description=rec.get("description", ""),
                    )
                )
            return services
        except Exception as exc:
            logger.debug("SDP browse failed for %s: %s", address, exc)
            return []

    def _scan_linux_hcitool(self) -> list[BluetoothDevice]:
        """Fallback: use hcitool inq (Linux only, read-only inquiry)."""
        logger.info("Using hcitool fallback (Linux)")
        devices: list[BluetoothDevice] = []
        try:
            result = subprocess.run(
                ["hcitool", "scan", "--flush"],
                capture_output=True,
                text=True,
                timeout=self.scan_duration + 5,
            )
            lines = result.stdout.strip().splitlines()
            for line in lines[1:]:  # skip header
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    addr, name = parts[0].strip(), parts[1].strip()
                    mfr = lookup_manufacturer_by_mac(addr)
                    now = datetime.utcnow()
                    dev = BluetoothDevice(
                        address=addr,
                        name=name,
                        rssi=-70,
                        protocol=BluetoothProtocol.CLASSIC,
                        manufacturer=mfr,
                        first_seen=now,
                        last_seen=now,
                    )
                    devices.append(dev)
                    if self.callback:
                        self.callback(dev)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.error("hcitool scan failed: %s", exc)
        return devices

    def _scan_macos(self) -> list[BluetoothDevice]:
        """Fallback: parse macOS system_profiler Bluetooth output."""
        logger.info("Using system_profiler fallback (macOS)")
        devices: list[BluetoothDevice] = []
        try:
            result = subprocess.run(
                ["system_profiler", "SPBluetoothDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            import json
            data = json.loads(result.stdout)
            bt_items = data.get("SPBluetoothDataType", [{}])
            for item in bt_items:
                for section_key in ("device_connected", "device_not_connected"):
                    for name, attrs in item.get(section_key, {}).items():
                        addr = attrs.get("device_address", "00:00:00:00:00:00")
                        addr_clean = addr.replace("-", ":")
                        mfr = lookup_manufacturer_by_mac(addr_clean)
                        now = datetime.utcnow()
                        dev = BluetoothDevice(
                            address=addr_clean,
                            name=name,
                            rssi=int(attrs.get("device_rssi", -70)),
                            protocol=BluetoothProtocol.CLASSIC,
                            manufacturer=mfr,
                            first_seen=now,
                            last_seen=now,
                            extra=dict(attrs),
                        )
                        devices.append(dev)
                        if self.callback:
                            self.callback(dev)
        except Exception as exc:
            logger.error("macOS system_profiler parse failed: %s", exc)
        return devices
