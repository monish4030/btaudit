"""
Bluetooth OUI (Organizationally Unique Identifier) database and utilities.
Provides manufacturer lookup from MAC address prefixes.

Made by Monish Paramasivam
"""

from __future__ import annotations

# Curated subset of common Bluetooth OUI prefixes → manufacturer names.
# Full OUI databases can be obtained from IEEE: https://regauth.standards.ieee.org/
OUI_DATABASE: dict[str, str] = {
    # Apple
    "00:1B:63": "Apple",
    "28:CF:E9": "Apple",
    "8C:85:90": "Apple",
    "AC:BC:32": "Apple",
    "F0:CB:A1": "Apple",
    "F4:F1:5A": "Apple",
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0A:27": "Apple",
    "00:0A:95": "Apple",
    "00:11:24": "Apple",
    "00:14:51": "Apple",
    "00:16:CB": "Apple",
    "00:17:F2": "Apple",
    "00:19:E3": "Apple",
    "00:1C:B3": "Apple",
    "00:1D:4F": "Apple",
    "00:1E:52": "Apple",
    "00:1E:C2": "Apple",
    "00:1F:5B": "Apple",
    "00:1F:F3": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:23:DF": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4B": "Apple",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "00:26:B0": "Apple",
    "00:26:BB": "Apple",
    # Samsung
    "00:07:AB": "Samsung",
    "00:12:47": "Samsung",
    "00:15:99": "Samsung",
    "00:16:32": "Samsung",
    "00:17:C9": "Samsung",
    "00:17:D5": "Samsung",
    "00:18:AF": "Samsung",
    "00:1A:8A": "Samsung",
    "00:1C:43": "Samsung",
    "00:1D:25": "Samsung",
    "00:1E:7D": "Samsung",
    "00:1F:CC": "Samsung",
    "00:21:19": "Samsung",
    "00:23:39": "Samsung",
    "00:23:99": "Samsung",
    "00:24:54": "Samsung",
    "00:24:90": "Samsung",
    "00:24:E9": "Samsung",
    "00:25:38": "Samsung",
    "00:25:66": "Samsung",
    # Google
    "00:1A:11": "Google",
    "94:EB:2C": "Google",
    "F4:F5:E8": "Google",
    "F4:8B:32": "Google",
    "3C:28:6D": "Google",
    # Microsoft
    "00:50:F2": "Microsoft",
    "28:18:78": "Microsoft",
    "60:45:BD": "Microsoft",
    "7C:1E:52": "Microsoft",
    "98:5F:D3": "Microsoft",
    "C4:9A:02": "Microsoft",
    # Sony
    "00:01:4A": "Sony",
    "00:13:A9": "Sony",
    "00:18:3A": "Sony",
    "00:1D:BA": "Sony",
    "00:24:BE": "Sony",
    "04:EF:7A": "Sony",
    # Broadcom (chipset)
    "00:10:18": "Broadcom",
    "00:90:4C": "Broadcom",
    "DC:EF:09": "Broadcom",
    # Intel
    "00:02:B3": "Intel",
    "34:13:E8": "Intel",
    "8C:8D:28": "Intel",
    "D0:37:45": "Intel",
    # Texas Instruments
    "00:12:4B": "Texas Instruments",
    "10:12:B4": "Texas Instruments",
    "E4:C5:D2": "Texas Instruments",
    # Nordic Semiconductor
    "D4:F5:13": "Nordic Semiconductor",
    "E3:4D:FD": "Nordic Semiconductor",  # random private
    # Qualcomm
    "00:02:6F": "Qualcomm",
    "20:02:AF": "Qualcomm",
    # Fitbit
    "C4:4B:D1": "Fitbit",
    "F4:31:C3": "Fitbit",
    # Garmin
    "00:08:20": "Garmin",
    "09:18:41": "Garmin",
    # Polar
    "00:22:D0": "Polar Electro",
    # Bose
    "00:09:A7": "Bose",
    "04:52:C7": "Bose",
    "44:10:D8": "Bose",
    # Jabra
    "50:C2:ED": "Jabra",
    "70:BF:92": "Jabra",
    # Plantronics/Poly
    "64:D4:DA": "Plantronics",
    "00:15:83": "Plantronics",
    # Logitech
    "00:1F:20": "Logitech",
    "34:88:5D": "Logitech",
    # Raspberry Pi Foundation
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    # Arduino
    "A4:CF:12": "Espressif (Arduino-compatible)",
    "24:6F:28": "Espressif",
    # Generic / Unknown
    "00:00:00": "Unknown/Reserved",
}

# Manufacturer data company IDs (from Bluetooth SIG Assigned Numbers)
COMPANY_IDS: dict[int, str] = {
    0x004C: "Apple",
    0x0006: "Microsoft",
    0x0075: "Samsung Electronics",
    0x000F: "Broadcom",
    0x0002: "Intel",
    0x0025: "Nokia",
    0x00E0: "Google",
    0x0059: "Nordic Semiconductor",
    0x000D: "Texas Instruments",
    0x000A: "Qualcomm",
    0x0A8C: "OPPO",
    0x038F: "Huawei",
    0x0499: "Ruuvi Innovations",
    0x02E5: "Anhui Huami",
    0x0157: "Garmin",
}

# Bluetooth SIG standard service UUIDs
SERVICE_NAMES: dict[str, str] = {
    # GATT Services
    "00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
    "00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
    "0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
    "0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
    "00001810-0000-1000-8000-00805f9b34fb": "Blood Pressure",
    "00001816-0000-1000-8000-00805f9b34fb": "Cycling Speed and Cadence",
    "00001818-0000-1000-8000-00805f9b34fb": "Cycling Power",
    "00001819-0000-1000-8000-00805f9b34fb": "Location and Navigation",
    "0000181a-0000-1000-8000-00805f9b34fb": "Environmental Sensing",
    "0000181c-0000-1000-8000-00805f9b34fb": "User Data",
    "0000181e-0000-1000-8000-00805f9b34fb": "Bond Management",
    "0000181f-0000-1000-8000-00805f9b34fb": "Continuous Glucose Monitoring",
    "00001820-0000-1000-8000-00805f9b34fb": "Internet Protocol Support",
    "00001821-0000-1000-8000-00805f9b34fb": "Indoor Positioning",
    "00001822-0000-1000-8000-00805f9b34fb": "Pulse Oximeter",
    "00001823-0000-1000-8000-00805f9b34fb": "HTTP Proxy",
    "00001824-0000-1000-8000-00805f9b34fb": "Transport Discovery",
    # Classic BT Profiles (short-form UUID)
    "0x1101": "SPP – Serial Port Profile",
    "0x1103": "DUN – Dial-up Networking",
    "0x1104": "IrMC Sync",
    "0x1105": "OBEX Object Push",
    "0x1106": "OBEX File Transfer",
    "0x1108": "Headset",
    "0x110a": "A2DP Source",
    "0x110b": "A2DP Sink",
    "0x110c": "AVRCP Target",
    "0x110e": "AVRCP Controller",
    "0x1112": "Headset – Audio Gateway",
    "0x1115": "BNEP – PAN",
    "0x1116": "NAP – Network Access Point",
    "0x1117": "GN – Group Network",
    "0x111e": "HFP – Hands-Free",
    "0x111f": "HFP – Audio Gateway",
    "0x1124": "HID – Human Interface Device",
    "0x1200": "PnP Information",
    "0x1203": "Generic Audio",
    "0x1204": "Generic Telephony",
}

# Security-relevant service UUIDs
SENSITIVE_SERVICES: frozenset[str] = frozenset({
    "0x1101",  # SPP — raw serial, often unauthenticated
    "0x1103",  # DUN — modem/internet access
    "0x1105",  # OBEX Object Push — file transfer without PIN
    "0x1106",  # OBEX File Transfer
    "0x1115",  # PAN — network bridging
    "0x1116",  # NAP — network access point
    "0x1117",  # GN — group network
    "0x1200",  # PnP Info — device enumeration aid
})


def lookup_manufacturer_by_mac(mac: str) -> str:
    """Look up manufacturer name from MAC address OUI prefix."""
    normalized = mac.upper().replace("-", ":")
    prefix = normalized[:8]
    return OUI_DATABASE.get(prefix, "Unknown")


def lookup_manufacturer_by_company_id(company_id: int) -> str:
    """Look up manufacturer name from BLE manufacturer data company ID."""
    return COMPANY_IDS.get(company_id, f"Unknown (0x{company_id:04X})")


def lookup_service_name(uuid: str) -> str:
    """Resolve a service UUID to a human-readable name."""
    uuid_lower = uuid.lower()
    if uuid_lower in SERVICE_NAMES:
        return SERVICE_NAMES[uuid_lower]
    # Try short form match
    short = f"0x{uuid_lower[:4]}" if len(uuid_lower) >= 4 else uuid_lower
    return SERVICE_NAMES.get(short, f"Unknown Service ({uuid})")


def is_sensitive_service(uuid: str) -> bool:
    """Return True if the service UUID is known to be security-sensitive."""
    uuid_lower = uuid.lower()
    short = f"0x{uuid_lower[:4]}" if len(uuid_lower) >= 4 else uuid_lower
    return short in SENSITIVE_SERVICES or uuid_lower in SENSITIVE_SERVICES


def is_random_address(mac: str) -> bool:
    """
    Heuristic check for BLE random/private addresses.
    Random addresses have the two MSBs of the first byte set:
    11xxxxxx (static random) or 01xxxxxx/10xxxxxx (private resolvable/non-resolvable)
    """
    try:
        first_byte = int(mac.split(":")[0].replace("-", ""), 16)
        return bool(first_byte & 0xC0)
    except (ValueError, IndexError):
        return False
