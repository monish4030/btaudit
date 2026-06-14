"""
BLE (Bluetooth Low Energy) Scanner
====================================
Passive BLE advertisement scanner using bleak.
Performs NO connection, pairing, or packet injection.

Made by Monish Paramasivam
"""

from __future__ import annotations
import asyncio
import logging
from datetime import datetime
from typing import Callable

from ..models import BluetoothDevice, BluetoothProtocol, ServiceRecord
from ..oui_db import (
    lookup_manufacturer_by_company_id,
    lookup_manufacturer_by_mac,
    lookup_service_name,
)
from ..consent import TransmissionGuard

logger = logging.getLogger(__name__)


class BLEScanner:
    """
    Passive BLE advertisement scanner.
    Discovers and records BLE devices from broadcast advertisements only.
    Does NOT attempt to connect to any device.
    """

    def __init__(
        self,
        scan_duration: float = 10.0,
        active_scan: bool = False,
        callback: Callable[[BluetoothDevice], None] | None = None,
    ) -> None:
        TransmissionGuard.validate_scan_parameters(
            active_scan=active_scan,
            connect=False,
            pair=False,
        )
        self.scan_duration = scan_duration
        self.active_scan = active_scan
        self.callback = callback
        self._devices: dict[str, BluetoothDevice] = {}

    async def scan(self) -> list[BluetoothDevice]:
        """
        Run a BLE passive scan for `scan_duration` seconds.
        Returns list of discovered BluetoothDevice objects.
        """
        try:
            from bleak import BleakScanner
            from bleak.backends.device import BLEDevice
            from bleak.backends.scanner import AdvertisementData
        except ImportError:
            logger.error(
                "bleak is not installed. Install with: pip install bleak"
            )
            return []

        logger.info(
            "Starting BLE %s scan for %.1fs",
            "active" if self.active_scan else "passive",
            self.scan_duration,
        )

        def detection_callback(
            ble_device: "BLEDevice", advertisement_data: "AdvertisementData"
        ) -> None:
            self._process_advertisement(ble_device, advertisement_data)

        try:
            async with BleakScanner(
                detection_callback=detection_callback,
                scanning_mode="active" if self.active_scan else "passive",
            ) as scanner:
                await asyncio.sleep(self.scan_duration)
        except Exception as exc:
            logger.error("BLE scan error: %s", exc)

        return list(self._devices.values())

    def _process_advertisement(
        self, ble_device: object, adv: object
    ) -> None:
        """Parse a BLE advertisement into a BluetoothDevice record."""
        mac: str = getattr(ble_device, "address", "00:00:00:00:00:00")
        name: str = (
            getattr(adv, "local_name", None)
            or getattr(ble_device, "name", None)
            or "Unknown"
        )
        rssi: int = getattr(adv, "rssi", -100)
        tx_power: int | None = getattr(adv, "tx_power", None)
        mfr_data: dict = getattr(adv, "manufacturer_data", {}) or {}
        service_uuids: list[str] = list(getattr(adv, "service_uuids", []) or [])
        service_data: dict = getattr(adv, "service_data", {}) or {}

        # Resolve manufacturer
        manufacturer = lookup_manufacturer_by_mac(mac)
        if mfr_data:
            company_id = next(iter(mfr_data))
            from_id = lookup_manufacturer_by_company_id(company_id)
            if from_id != f"Unknown (0x{company_id:04X})":
                manufacturer = from_id

        # Build service records
        services: list[ServiceRecord] = []
        for uuid in service_uuids:
            services.append(
                ServiceRecord(
                    uuid=uuid,
                    name=lookup_service_name(uuid),
                    protocol="GATT/BLE",
                )
            )
        for uuid in service_data:
            if uuid not in service_uuids:
                services.append(
                    ServiceRecord(
                        uuid=uuid,
                        name=lookup_service_name(uuid),
                        protocol="GATT/BLE",
                        description="Service data present",
                    )
                )

        now = datetime.utcnow()
        if mac in self._devices:
            existing = self._devices[mac]
            existing.last_seen = now
            existing.rssi = rssi
            if name != "Unknown":
                existing.name = name
        else:
            device = BluetoothDevice(
                address=mac,
                name=name,
                rssi=rssi,
                protocol=BluetoothProtocol.BLE,
                manufacturer=manufacturer,
                manufacturer_data={k: bytes(v) for k, v in mfr_data.items()},
                services=services,
                service_uuids=service_uuids,
                tx_power=tx_power,
                is_connectable=getattr(adv, "connectable", False),
                first_seen=now,
                last_seen=now,
            )
            self._devices[mac] = device
            logger.debug("Discovered BLE device: %s [%s] RSSI=%d", name, mac, rssi)
            if self.callback:
                self.callback(device)
