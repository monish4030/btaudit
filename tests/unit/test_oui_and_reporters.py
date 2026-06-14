"""
Unit tests for OUI lookup, categorizer, and reporters.
Made by Monish Paramasivam
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from src.btaudit.oui_db import (
    lookup_manufacturer_by_mac,
    lookup_manufacturer_by_company_id,
    lookup_service_name,
    is_sensitive_service,
    is_random_address,
)
from src.btaudit.analyzers.categorizer import DeviceCategorizer
from src.btaudit.models import (
    BluetoothDevice,
    BluetoothProtocol,
    DeviceCategory,
    ScanSession,
    ServiceRecord,
)
from src.btaudit.reporters import JSONReporter, CSVReporter, HTMLReporter


# ── OUI Tests ─────────────────────────────────────────────────────────────

class TestOUILookup:
    def test_known_apple_mac(self):
        assert lookup_manufacturer_by_mac("AC:BC:32:00:00:01") == "Apple"

    def test_known_samsung_mac(self):
        assert lookup_manufacturer_by_mac("00:12:47:00:00:01") == "Samsung"

    def test_unknown_mac_returns_unknown(self):
        result = lookup_manufacturer_by_mac("FF:FF:FF:00:00:01")
        assert result == "Unknown"

    def test_case_insensitive(self):
        assert lookup_manufacturer_by_mac("ac:bc:32:00:00:01") == "Apple"

    def test_company_id_apple(self):
        assert lookup_manufacturer_by_company_id(0x004C) == "Apple"

    def test_company_id_microsoft(self):
        assert lookup_manufacturer_by_company_id(0x0006) == "Microsoft"

    def test_unknown_company_id(self):
        result = lookup_manufacturer_by_company_id(0xFFFF)
        assert "Unknown" in result

    def test_service_name_spp(self):
        assert "SPP" in lookup_service_name("0x1101") or "Serial" in lookup_service_name("0x1101")

    def test_service_name_unknown(self):
        result = lookup_service_name("0xDEAD")
        assert "Unknown" in result or "0xDEAD" in result

    def test_is_sensitive_spp(self):
        assert is_sensitive_service("0x1101")

    def test_is_sensitive_obex(self):
        assert is_sensitive_service("0x1105")

    def test_is_not_sensitive_battery(self):
        assert not is_sensitive_service("0000180f-0000-1000-8000-00805f9b34fb")

    def test_random_address_detection(self):
        # High bits set → random
        assert is_random_address("C0:00:00:00:00:01")
        assert is_random_address("F0:00:00:00:00:01")

    def test_public_address_detection(self):
        # Low bits → public
        assert not is_random_address("00:11:22:33:44:55")
        assert not is_random_address("04:00:00:00:00:01")


# ── Categorizer Tests ─────────────────────────────────────────────────────

class TestDeviceCategorizer:
    def setup_method(self):
        self.cat = DeviceCategorizer()

    def _dev(self, name="", manufacturer="") -> BluetoothDevice:
        return BluetoothDevice(address="AA:BB:CC:DD:EE:FF", name=name, manufacturer=manufacturer)

    def test_iphone_categorized(self):
        d = self.cat.categorize(self._dev(name="iPhone 14"))
        assert d.category == DeviceCategory.PHONE

    def test_airpods_categorized(self):
        d = self.cat.categorize(self._dev(name="AirPods Pro"))
        assert d.category == DeviceCategory.HEADSET

    def test_fitbit_manufacturer(self):
        d = self.cat.categorize(self._dev(name="Charge 5", manufacturer="Fitbit"))
        assert d.category == DeviceCategory.WEARABLE

    def test_unknown_device(self):
        d = self.cat.categorize(self._dev(name="XYZ-9999", manufacturer="Unknown"))
        assert d.category == DeviceCategory.UNKNOWN

    def test_keyboard_name(self):
        d = self.cat.categorize(self._dev(name="Magic Keyboard"))
        assert d.category == DeviceCategory.KEYBOARD


# ── Reporter Tests ────────────────────────────────────────────────────────

def _make_session() -> ScanSession:
    dev = BluetoothDevice(
        address="AA:BB:CC:DD:EE:FF",
        name="Test Device",
        rssi=-70,
        protocol=BluetoothProtocol.BLE,
        manufacturer="Test Corp",
        services=[ServiceRecord(uuid="0x1101", name="SPP", protocol="RFCOMM")],
    )
    from src.btaudit.models import SecurityFinding, RiskLevel
    dev.findings = [SecurityFinding("BT-004", "SPP", "Desc", RiskLevel.HIGH, "Fix")]
    dev.risk_score = 25
    return ScanSession(
        session_id="test-001",
        started_at=datetime.utcnow(),
        ended_at=datetime.utcnow(),
        duration_seconds=15.0,
        devices=[dev],
        authorized_by="Test User",
        scan_environment="Test Lab",
    )


class TestJSONReporter:
    def test_generates_valid_json(self):
        session = _make_session()
        with tempfile.TemporaryDirectory() as tmp:
            path = JSONReporter(tmp).generate(session)
            data = json.loads(path.read_text())
        assert "session_id" in data
        assert data["session_id"] == "test-001"

    def test_contains_devices(self):
        session = _make_session()
        with tempfile.TemporaryDirectory() as tmp:
            path = JSONReporter(tmp).generate(session)
            data = json.loads(path.read_text())
        assert len(data["devices"]) == 1

    def test_to_string_is_json(self):
        session = _make_session()
        result = JSONReporter().to_string(session)
        parsed = json.loads(result)
        assert "devices" in parsed

    def test_author_attribution(self):
        session = _make_session()
        result = JSONReporter().to_string(session)
        assert "Monish Paramasivam" in result


class TestCSVReporter:
    def test_generates_csv_with_header(self):
        session = _make_session()
        with tempfile.TemporaryDirectory() as tmp:
            path = CSVReporter(tmp).generate(session)
            content = path.read_text()
        assert "address" in content
        assert "risk_score" in content
        assert "AA:BB:CC:DD:EE:FF" in content

    def test_to_string_contains_device(self):
        session = _make_session()
        result = CSVReporter().to_string(session)
        assert "Test Device" in result
        assert "Test Corp" in result


class TestHTMLReporter:
    def test_generates_valid_html(self):
        session = _make_session()
        with tempfile.TemporaryDirectory() as tmp:
            path = HTMLReporter(tmp).generate(session)
            content = path.read_text()
        assert "<!DOCTYPE html>" in content
        assert "BTAudit" in content

    def test_html_contains_device(self):
        session = _make_session()
        result = HTMLReporter().to_string(session)
        assert "Test Device" in result
        assert "AA:BB:CC:DD:EE:FF" in result

    def test_html_contains_author(self):
        session = _make_session()
        result = HTMLReporter().to_string(session)
        assert "Monish Paramasivam" in result

    def test_html_contains_legal_notice(self):
        session = _make_session()
        result = HTMLReporter().to_string(session)
        assert "Authorized Use Only" in result or "authorized" in result.lower()
