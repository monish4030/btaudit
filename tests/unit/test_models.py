"""
Unit tests for BTAudit data models.
Made by Monish Paramasivam
"""

import pytest
from datetime import datetime
from src.btaudit.models import (
    BluetoothDevice,
    BluetoothProtocol,
    DeviceCategory,
    RiskLevel,
    SecurityFinding,
    ServiceRecord,
    ScanSession,
)


class TestBluetoothDevice:
    def _make_device(self, **kwargs) -> BluetoothDevice:
        defaults = dict(
            address="AA:BB:CC:DD:EE:FF",
            name="Test Device",
            rssi=-65,
            protocol=BluetoothProtocol.BLE,
        )
        defaults.update(kwargs)
        return BluetoothDevice(**defaults)

    def test_signal_strength_excellent(self):
        d = self._make_device(rssi=-45)
        assert d.signal_strength_label == "Excellent"

    def test_signal_strength_good(self):
        d = self._make_device(rssi=-65)
        assert d.signal_strength_label == "Good"

    def test_signal_strength_fair(self):
        d = self._make_device(rssi=-80)
        assert d.signal_strength_label == "Fair"

    def test_signal_strength_poor(self):
        d = self._make_device(rssi=-95)
        assert d.signal_strength_label == "Poor"

    def test_distance_close(self):
        d = self._make_device(rssi=-45)
        assert "1m" in d.distance_estimate

    def test_highest_risk_no_findings(self):
        d = self._make_device()
        assert d.highest_risk == RiskLevel.INFO

    def test_highest_risk_with_critical(self):
        d = self._make_device()
        d.findings = [
            SecurityFinding("BT-001", "Low", "", RiskLevel.LOW, ""),
            SecurityFinding("BT-002", "Critical", "", RiskLevel.CRITICAL, ""),
        ]
        assert d.highest_risk == RiskLevel.CRITICAL

    def test_highest_risk_with_high(self):
        d = self._make_device()
        d.findings = [
            SecurityFinding("BT-001", "Medium", "", RiskLevel.MEDIUM, ""),
            SecurityFinding("BT-002", "High", "", RiskLevel.HIGH, ""),
        ]
        assert d.highest_risk == RiskLevel.HIGH

    def test_to_dict_contains_required_fields(self):
        d = self._make_device()
        result = d.to_dict()
        for field in ("address", "name", "rssi", "protocol", "manufacturer",
                      "services", "risk_score", "highest_risk", "findings"):
            assert field in result, f"Missing field: {field}"

    def test_to_dict_manufacturer_data_hex(self):
        d = self._make_device(manufacturer_data={0x004C: b"\x00\x01\x02"})
        result = d.to_dict()
        assert result["manufacturer_data"]["76"] == "000102"

    def test_to_dict_protocol_is_string(self):
        d = self._make_device(protocol=BluetoothProtocol.BLE)
        assert isinstance(d.to_dict()["protocol"], str)


class TestScanSession:
    def _make_session(self, devices=None) -> ScanSession:
        return ScanSession(
            session_id="test-abc",
            started_at=datetime.utcnow(),
            devices=devices or [],
        )

    def test_summary_zero_devices(self):
        session = self._make_session()
        summary = session.to_dict()["summary"]
        assert summary["total_devices"] == 0
        assert summary["average_risk_score"] == 0

    def test_summary_device_counts(self):
        ble = BluetoothDevice(
            address="AA:BB:CC:DD:EE:01",
            protocol=BluetoothProtocol.BLE,
        )
        classic = BluetoothDevice(
            address="AA:BB:CC:DD:EE:02",
            protocol=BluetoothProtocol.CLASSIC,
        )
        session = self._make_session(devices=[ble, classic])
        summary = session.to_dict()["summary"]
        assert summary["ble_devices"] == 1
        assert summary["classic_devices"] == 1
        assert summary["total_devices"] == 2

    def test_summary_critical_count(self):
        d = BluetoothDevice(address="AA:BB:CC:DD:EE:01")
        d.findings = [SecurityFinding("BT-001", "T", "", RiskLevel.CRITICAL, "")]
        session = self._make_session(devices=[d])
        summary = session.to_dict()["summary"]
        assert summary["critical_findings"] == 1

    def test_to_dict_has_author(self):
        session = self._make_session()
        assert "Monish Paramasivam" in session.to_dict()["author"]


class TestServiceRecord:
    def test_to_dict(self):
        svc = ServiceRecord(uuid="0x1101", name="SPP", protocol="RFCOMM")
        d = svc.to_dict()
        assert d["uuid"] == "0x1101"
        assert d["name"] == "SPP"
        assert d["protocol"] == "RFCOMM"


class TestSecurityFinding:
    def test_to_dict_risk_level_is_string(self):
        f = SecurityFinding(
            finding_id="BT-001",
            title="Test",
            description="Desc",
            risk_level=RiskLevel.HIGH,
            recommendation="Fix it",
            reference="NIST",
            cve="CVE-2023-0001",
        )
        d = f.to_dict()
        assert d["risk_level"] == "HIGH"
        assert d["cve"] == "CVE-2023-0001"
