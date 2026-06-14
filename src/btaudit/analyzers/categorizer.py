"""
Device Categorizer
==================
Classifies Bluetooth devices into functional categories using
heuristics from device name, manufacturer, services, and class-of-device.

Made by Monish Paramasivam
"""

from __future__ import annotations
import re

from ..models import BluetoothDevice, DeviceCategory

# Keyword → category mapping (case-insensitive, ordered by priority)
NAME_PATTERNS: list[tuple[re.Pattern, DeviceCategory]] = [
    (re.compile(r"iphone|android|pixel|galaxy|oneplus|xiaomi|huawei|nokia|moto", re.I), DeviceCategory.PHONE),
    (re.compile(r"macbook|thinkpad|laptop|surface|dell|hp\s|lenovo|asus\s", re.I), DeviceCategory.LAPTOP),
    (re.compile(r"airpod|headset|earbuds?|headphone|jabra|bose|sony wh|plantronics|beats|jbl", re.I), DeviceCategory.HEADSET),
    (re.compile(r"keyboard|mouse\b|trackpad|magic keyboard", re.I), DeviceCategory.KEYBOARD),
    (re.compile(r"pacemaker|glucometer|glucose|pulse ox|blood pressure|hearing aid", re.I), DeviceCategory.MEDICAL),
    (re.compile(r"watch|band|fitbit|garmin|polar|amazfit|mi band|wearable", re.I), DeviceCategory.WEARABLE),
    (re.compile(r"car|vehicle|obd|tesla|bmw|toyota bt|ford bt|auto", re.I), DeviceCategory.VEHICLE),
    (re.compile(r"tv\b|speaker|echo|home|hub|sensor|lock|bulb|thermostat|nest|hue|ring\b", re.I), DeviceCategory.IOT),
    (re.compile(r"printer|scanner|camera|peripheral", re.I), DeviceCategory.PERIPHERAL),
]

MANUFACTURER_CATEGORY: dict[str, DeviceCategory] = {
    "Apple": DeviceCategory.PHONE,
    "Samsung Electronics": DeviceCategory.PHONE,
    "Fitbit": DeviceCategory.WEARABLE,
    "Garmin": DeviceCategory.WEARABLE,
    "Polar Electro": DeviceCategory.WEARABLE,
    "Bose": DeviceCategory.HEADSET,
    "Jabra": DeviceCategory.HEADSET,
    "Plantronics": DeviceCategory.HEADSET,
    "Logitech": DeviceCategory.KEYBOARD,
}

# Bluetooth Classic device class bits → category
DEVICE_CLASS_MAP: dict[int, DeviceCategory] = {
    0x200: DeviceCategory.PHONE,       # Phone
    0x100: DeviceCategory.LAPTOP,      # Computer
    0x400: DeviceCategory.HEADSET,     # Audio/Video
    0x500: DeviceCategory.PERIPHERAL,  # Peripheral
    0x900: DeviceCategory.MEDICAL,     # Health
}


class DeviceCategorizer:
    """Classifies a BluetoothDevice into a DeviceCategory."""

    def categorize(self, device: BluetoothDevice) -> BluetoothDevice:
        device.category = self._classify(device)
        return device

    def categorize_all(self, devices: list[BluetoothDevice]) -> list[BluetoothDevice]:
        return [self.categorize(d) for d in devices]

    def _classify(self, device: BluetoothDevice) -> DeviceCategory:
        # 1. Name-based heuristics
        for pattern, category in NAME_PATTERNS:
            if pattern.search(device.name):
                return category

        # 2. Manufacturer-based
        for mfr_key, category in MANUFACTURER_CATEGORY.items():
            if mfr_key.lower() in device.manufacturer.lower():
                return category

        # 3. Class-of-device (Classic BT)
        device_class = device.extra.get("device_class", 0)
        if device_class:
            major_class = device_class & 0x1F00
            if major_class in DEVICE_CLASS_MAP:
                return DEVICE_CLASS_MAP[major_class]

        return DeviceCategory.UNKNOWN
