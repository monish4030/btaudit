"""
Unit tests for the SecurityAnalyzer and risk scoring engine.
Made by Monish Paramasivam
"""

import pytest
from src.btaudit.models import (
    BluetoothDevice,
    BluetoothProtocol,
    RiskLevel,
    ServiceRecord,
)
from src.btaudit.analyzers.security_analyzer import SecurityAnalyzer


def _make_device(**kwargs) -> BluetoothDevice:
    defaults = dict(address="AA:BB:CC:DD:EE:FF", name="Test Device")
    defaults.update(kwargs)
    return BluetoothDevice(**defaults)


class TestSecurityAnalyzer:
    def setup_method(self):
        self.analyzer = SecurityAnalyzer()

    def test_analyze_returns_device(self):
        d = _make_device()
        result = self.analyzer.analyze(d)
        assert result is d

    def test_no_findings_for_clean_ble_device(self):
        d = _make_device(
            protocol=BluetoothProtocol.BLE,
            address="D4:F5:13:00:00:01",  # random-looking
            is_connectable=False,
            is_discoverable=False,
        )
        result = self.analyzer.analyze(d)
        # May have some findings but should not have CRITICAL/HIGH for clean device
        critical_high = [f for f in result.findings if f.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)]
        assert len(critical_high) == 0

    def test_discoverable_classic_flagged(self):
        d = _make_device(
            protocol=BluetoothProtocol.CLASSIC,
            is_discoverable=True,
        )
        result = self.analyzer.analyze(d)
        ids = [f.finding_id for f in result.findings]
        assert "BT-001" in ids

    def test_obex_service_flagged(self):
        d = _make_device()
        d.services = [ServiceRecord(uuid="0x1105", name="OBEX Object Push", protocol="RFCOMM")]
        result = self.analyzer.analyze(d)
        ids = [f.finding_id for f in result.findings]
        assert "BT-003" in ids

    def test_spp_service_flagged(self):
        d = _make_device()
        d.services = [ServiceRecord(uuid="0x1101", name="SPP", protocol="RFCOMM")]
        result = self.analyzer.analyze(d)
        ids = [f.finding_id for f in result.findings]
        assert "BT-004" in ids

    def test_pan_service_flagged_as_critical(self):
        d = _make_device()
        d.services = [ServiceRecord(uuid="0x1116", name="NAP", protocol="BNEP")]
        result = self.analyzer.analyze(d)
        pan_findings = [f for f in result.findings if f.finding_id == "BT-005"]
        assert len(pan_findings) == 1
        assert pan_findings[0].risk_level == RiskLevel.CRITICAL

    def test_ble_public_address_flagged(self):
        # Non-random address (low bit pattern)
        d = _make_device(
            protocol=BluetoothProtocol.BLE,
            address="00:11:22:33:44:55",  # public address
        )
        result = self.analyzer.analyze(d)
        ids = [f.finding_id for f in result.findings]
        assert "BT-007" in ids

    def test_high_tx_power_flagged(self):
        d = _make_device(tx_power=20)
        result = self.analyzer.analyze(d)
        ids = [f.finding_id for f in result.findings]
        assert "BT-009" in ids

    def test_normal_tx_power_not_flagged(self):
        d = _make_device(tx_power=0)
        result = self.analyzer.analyze(d)
        ids = [f.finding_id for f in result.findings]
        assert "BT-009" not in ids

    def test_medical_device_flagged(self):
        d = _make_device()
        d.services = [
            ServiceRecord(
                uuid="00001810-0000-1000-8000-00805f9b34fb",
                name="Blood Pressure",
                protocol="GATT",
            )
        ]
        result = self.analyzer.analyze(d)
        ids = [f.finding_id for f in result.findings]
        assert "BT-011" in ids

    def test_risk_score_zero_for_no_findings(self):
        d = _make_device(protocol=BluetoothProtocol.BLE, is_connectable=False)
        d.findings = []
        d.risk_score = self.analyzer._compute_risk_score([])
        assert d.risk_score == 0

    def test_risk_score_capped_at_100(self):
        from src.btaudit.models import SecurityFinding
        # Many critical findings
        findings = [
            SecurityFinding(f"BT-{i:03d}", "T", "", RiskLevel.CRITICAL, "")
            for i in range(20)
        ]
        score = self.analyzer._compute_risk_score(findings)
        assert score <= 100

    def test_risk_score_critical_higher_than_low(self):
        from src.btaudit.models import SecurityFinding
        critical_score = self.analyzer._compute_risk_score([
            SecurityFinding("BT-001", "T", "", RiskLevel.CRITICAL, "")
        ])
        low_score = self.analyzer._compute_risk_score([
            SecurityFinding("BT-002", "T", "", RiskLevel.LOW, "")
        ])
        assert critical_score > low_score

    def test_analyze_all(self):
        devices = [_make_device(address=f"AA:BB:CC:DD:EE:{i:02X}") for i in range(5)]
        results = self.analyzer.analyze_all(devices)
        assert len(results) == 5
        for d in results:
            assert d.risk_score >= 0
