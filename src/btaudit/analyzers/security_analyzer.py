"""
Security Analyzer and Risk Scoring Engine
==========================================
Detects common Bluetooth security misconfigurations based on
publicly documented best practices. No exploitation is performed.

References:
  - NIST SP 800-121 Rev 2: Guide to Bluetooth Security
  - Bluetooth SIG Security Requirements
  - OWASP IoT Attack Surface Areas
  - CVE database (for known-vulnerable service patterns)

Made by Monish Paramasivam
"""

from __future__ import annotations
import logging
from typing import Sequence

from ..models import (
    BluetoothDevice,
    BluetoothProtocol,
    DeviceCategory,
    RiskLevel,
    SecurityFinding,
)
from ..oui_db import is_sensitive_service, is_random_address, SENSITIVE_SERVICES

logger = logging.getLogger(__name__)

# Risk score weights per severity level
RISK_WEIGHTS: dict[RiskLevel, int] = {
    RiskLevel.CRITICAL: 40,
    RiskLevel.HIGH: 25,
    RiskLevel.MEDIUM: 15,
    RiskLevel.LOW: 5,
    RiskLevel.INFO: 1,
}

# Maximum possible score (capped at 100)
MAX_SCORE = 100


class SecurityAnalyzer:
    """
    Passive security misconfiguration detector.

    Evaluates each device against a rule set derived from public
    security documentation. All checks are read-only — no packets
    are transmitted and no connections are made.
    """

    def analyze(self, device: BluetoothDevice) -> BluetoothDevice:
        """Run all checks against a device; attach findings and risk score."""
        findings: list[SecurityFinding] = []

        findings += self._check_discoverability(device)
        findings += self._check_sensitive_services(device)
        findings += self._check_obex_without_auth(device)
        findings += self._check_serial_port_profile(device)
        findings += self._check_pan_services(device)
        findings += self._check_legacy_profiles(device)
        findings += self._check_ble_address_privacy(device)
        findings += self._check_ble_unprotected_connectable(device)
        findings += self._check_tx_power_anomaly(device)
        findings += self._check_weak_rssi_exposure(device)
        findings += self._check_medical_device(device)
        findings += self._check_no_services_advertised(device)

        device.findings = findings
        device.risk_score = self._compute_risk_score(findings)
        return device

    def analyze_all(
        self, devices: Sequence[BluetoothDevice]
    ) -> list[BluetoothDevice]:
        """Analyze a list of devices in place."""
        return [self.analyze(dev) for dev in devices]

    # ── Individual check methods ──────────────────────────────────────────

    def _check_discoverability(
        self, device: BluetoothDevice
    ) -> list[SecurityFinding]:
        """
        Devices in permanent discoverable mode violate Bluetooth SIG
        best practices (NIST SP 800-121 §5.1).
        """
        if device.protocol != BluetoothProtocol.CLASSIC:
            return []
        if not device.is_discoverable:
            return []
        return [
            SecurityFinding(
                finding_id="BT-001",
                title="Device Permanently Discoverable",
                description=(
                    f"Device '{device.name}' ({device.address}) is broadcasting "
                    "in discoverable mode. Bluetooth Classic devices should only "
                    "be discoverable during intentional pairing sessions."
                ),
                risk_level=RiskLevel.MEDIUM,
                recommendation=(
                    "Configure the device to use 'non-discoverable' or "
                    "'limited discoverable' mode. Enable discoverability only "
                    "when actively pairing."
                ),
                reference="NIST SP 800-121 Rev 2 §5.1.1",
            )
        ]

    def _check_sensitive_services(
        self, device: BluetoothDevice
    ) -> list[SecurityFinding]:
        """Flag any services known to carry security risk."""
        findings: list[SecurityFinding] = []
        for service in device.services:
            if is_sensitive_service(service.uuid):
                findings.append(
                    SecurityFinding(
                        finding_id="BT-002",
                        title=f"Security-Sensitive Service Advertised: {service.name}",
                        description=(
                            f"Device '{device.name}' advertises '{service.name}' "
                            f"(UUID: {service.uuid}), which is associated with "
                            "elevated security risk if unauthenticated."
                        ),
                        risk_level=RiskLevel.HIGH,
                        recommendation=(
                            f"Verify that '{service.name}' requires authentication "
                            "and authorization before data transfer. Disable the "
                            "service if not operationally required."
                        ),
                        reference="NIST SP 800-121 Rev 2 §5.3",
                    )
                )
        return findings

    def _check_obex_without_auth(
        self, device: BluetoothDevice
    ) -> list[SecurityFinding]:
        """OBEX Object Push without authentication is a known data-leakage vector."""
        has_obex = any(
            "0x1105" in s.uuid.lower() or "obex" in s.name.lower()
            for s in device.services
        )
        if not has_obex:
            return []
        return [
            SecurityFinding(
                finding_id="BT-003",
                title="OBEX Object Push Detected (Potential Unauthenticated File Transfer)",
                description=(
                    f"Device '{device.name}' advertises OBEX Object Push. "
                    "Older implementations accept files without PIN authentication, "
                    "enabling BlueBugging-class attacks or data exfiltration."
                ),
                risk_level=RiskLevel.HIGH,
                recommendation=(
                    "Ensure OBEX Push requires authentication. Disable OBEX "
                    "Object Push if the device does not require file transfer "
                    "functionality."
                ),
                reference="CVE-2006-6076 / NIST SP 800-121 §5.3.2",
                cve="CVE-2006-6076",
            )
        ]

    def _check_serial_port_profile(
        self, device: BluetoothDevice
    ) -> list[SecurityFinding]:
        """SPP (Serial Port Profile) exposes a raw bidirectional serial channel."""
        has_spp = any(
            "0x1101" in s.uuid.lower() or "serial" in s.name.lower()
            for s in device.services
        )
        if not has_spp:
            return []
        return [
            SecurityFinding(
                finding_id="BT-004",
                title="Serial Port Profile (SPP) Detected",
                description=(
                    f"Device '{device.name}' advertises the Serial Port Profile. "
                    "SPP provides a raw serial data channel with minimal security "
                    "controls and is frequently unauthenticated in legacy firmware."
                ),
                risk_level=RiskLevel.HIGH,
                recommendation=(
                    "Require Secure Simple Pairing (SSP) with authentication "
                    "for SPP connections. Evaluate whether SPP can be replaced "
                    "with a more secure transport."
                ),
                reference="NIST SP 800-121 Rev 2 §5.3.4",
            )
        ]

    def _check_pan_services(
        self, device: BluetoothDevice
    ) -> list[SecurityFinding]:
        """PAN/NAP/GN services expose network bridging capabilities."""
        pan_services = [
            s for s in device.services
            if any(k in s.uuid.lower() for k in ("0x1115", "0x1116", "0x1117"))
            or any(k in s.name.lower() for k in ("pan", "nap", "network access", "group network"))
        ]
        if not pan_services:
            return []
        return [
            SecurityFinding(
                finding_id="BT-005",
                title="Network Access / PAN Service Detected",
                description=(
                    f"Device '{device.name}' advertises Bluetooth PAN/NAP services, "
                    "which can bridge Bluetooth to an Ethernet/IP network. "
                    "This can expose internal network segments to Bluetooth-range attackers."
                ),
                risk_level=RiskLevel.CRITICAL,
                recommendation=(
                    "Disable PAN/NAP/GN services unless strictly required. "
                    "If required, enforce strong authentication and firewall "
                    "the bridged network segment."
                ),
                reference="NIST SP 800-121 Rev 2 §5.3.5",
            )
        ]

    def _check_legacy_profiles(
        self, device: BluetoothDevice
    ) -> list[SecurityFinding]:
        """Headset and DUN profiles use legacy PIN-based authentication."""
        legacy = [
            s for s in device.services
            if any(
                k in s.uuid.lower() for k in ("0x1108", "0x1112", "0x1103")
            )
            or any(k in s.name.lower() for k in ("headset", "dial-up", "dun"))
        ]
        if not legacy:
            return []
        return [
            SecurityFinding(
                finding_id="BT-006",
                title="Legacy Headset/DUN Profile Detected",
                description=(
                    f"Device '{device.name}' advertises legacy Bluetooth profiles "
                    "(Headset or Dial-Up Networking) that rely on PIN-based pairing "
                    "rather than Secure Simple Pairing (SSP)."
                ),
                risk_level=RiskLevel.MEDIUM,
                recommendation=(
                    "Upgrade device firmware to support SSP. Require a "
                    "minimum PIN length of 8+ digits if legacy PIN pairing "
                    "cannot be avoided."
                ),
                reference="NIST SP 800-121 Rev 2 §4.3",
            )
        ]

    def _check_ble_address_privacy(
        self, device: BluetoothDevice
    ) -> list[SecurityFinding]:
        """
        BLE devices using static public addresses are trackable.
        Resolvable private addresses (RPA) are the best practice.
        """
        if device.protocol not in (BluetoothProtocol.BLE, BluetoothProtocol.DUAL):
            return []
        if is_random_address(device.address):
            return []  # Using random/private address — good practice
        return [
            SecurityFinding(
                finding_id="BT-007",
                title="BLE Device Using Static Public MAC Address",
                description=(
                    f"BLE device '{device.name}' ({device.address}) broadcasts a "
                    "static public address. Static addresses allow passive tracking "
                    "of device location and owner activity over time."
                ),
                risk_level=RiskLevel.MEDIUM,
                recommendation=(
                    "Configure the device to use Resolvable Private Addresses (RPA) "
                    "with address rotation. This is supported in Bluetooth 4.2+ and "
                    "required for privacy compliance in many jurisdictions."
                ),
                reference="Bluetooth Core Spec 5.4 §Vol 3, Part C §10.7 / GDPR",
            )
        ]

    def _check_ble_unprotected_connectable(
        self, device: BluetoothDevice
    ) -> list[SecurityFinding]:
        """Connectable BLE peripherals with no discernible encryption indicators."""
        if device.protocol not in (BluetoothProtocol.BLE, BluetoothProtocol.DUAL):
            return []
        if not device.is_connectable:
            return []
        if not device.services:
            return [
                SecurityFinding(
                    finding_id="BT-008",
                    title="Connectable BLE Device with No Advertised Services",
                    description=(
                        f"BLE device '{device.name}' is connectable but advertises "
                        "no GATT services. Without service metadata, it is impossible "
                        "to assess whether GATT operations are authenticated."
                    ),
                    risk_level=RiskLevel.LOW,
                    recommendation=(
                        "Ensure GATT characteristics that expose sensitive data "
                        "require authenticated and encrypted connections. "
                        "Audit GATT server configuration."
                    ),
                    reference="Bluetooth Core Spec 5.4 §Vol 3, Part F §3.2",
                )
            ]
        return []

    def _check_tx_power_anomaly(
        self, device: BluetoothDevice
    ) -> list[SecurityFinding]:
        """
        Very high TX power may indicate an intentionally long-range device
        or firmware misconfiguration.
        """
        if device.tx_power is None:
            return []
        if device.tx_power > 10:  # dBm; regulatory max is typically 10–20 dBm
            return [
                SecurityFinding(
                    finding_id="BT-009",
                    title=f"Elevated TX Power Detected ({device.tx_power} dBm)",
                    description=(
                        f"Device '{device.name}' advertises TX power of "
                        f"{device.tx_power} dBm, which exceeds typical device "
                        "ranges. This may indicate a modified or misconfigured device "
                        "with extended physical range."
                    ),
                    risk_level=RiskLevel.LOW,
                    recommendation=(
                        "Verify device firmware configuration. High TX power extends "
                        "the physical attack surface and may violate local RF regulations."
                    ),
                    reference="FCC Part 15 / CE RED Directive 2014/53/EU",
                )
            ]
        return []

    def _check_weak_rssi_exposure(
        self, device: BluetoothDevice
    ) -> list[SecurityFinding]:
        """
        Very strong RSSI with a sensitive service is an informational note
        that the device is physically close and easily reachable.
        """
        has_sensitive = any(is_sensitive_service(s.uuid) for s in device.services)
        if device.rssi >= -40 and has_sensitive:
            return [
                SecurityFinding(
                    finding_id="BT-010",
                    title="High-Risk Service on Nearby Device (Strong Signal)",
                    description=(
                        f"Device '{device.name}' is within ~1m (RSSI={device.rssi} dBm) "
                        "and advertises security-sensitive services. Physical proximity "
                        "reduces Bluetooth attack difficulty."
                    ),
                    risk_level=RiskLevel.LOW,
                    recommendation=(
                        "Review physical access controls. Ensure sensitive Bluetooth "
                        "services require authentication before establishing data channels."
                    ),
                    reference="NIST SP 800-121 Rev 2 §3.2",
                )
            ]
        return []

    def _check_medical_device(
        self, device: BluetoothDevice
    ) -> list[SecurityFinding]:
        """Medical device services (BLE Health profiles) carry extra scrutiny."""
        medical_uuids = {
            "00001810-0000-1000-8000-00805f9b34fb",  # Blood Pressure
            "00001822-0000-1000-8000-00805f9b34fb",  # Pulse Oximeter
            "0000181f-0000-1000-8000-00805f9b34fb",  # Continuous Glucose
        }
        medical_services = [
            s for s in device.services if s.uuid.lower() in medical_uuids
        ]
        if not medical_services:
            return []
        return [
            SecurityFinding(
                finding_id="BT-011",
                title="Medical Device Profile Detected",
                description=(
                    f"Device '{device.name}' advertises medical-grade Bluetooth "
                    "health profiles. Medical devices are subject to strict regulatory "
                    "requirements (FDA, MDR) and must enforce authenticated, encrypted "
                    "connections."
                ),
                risk_level=RiskLevel.HIGH,
                recommendation=(
                    "Verify device complies with FDA cybersecurity guidance for "
                    "medical devices (2023) and implements encrypted, authenticated "
                    "Bluetooth LE connections."
                ),
                reference="FDA Cybersecurity in Medical Devices (2023) / EU MDR 2017/745",
            )
        ]

    def _check_no_services_advertised(
        self, device: BluetoothDevice
    ) -> list[SecurityFinding]:
        """Informational: classic devices with zero SDP records may be stealthy."""
        if device.protocol != BluetoothProtocol.CLASSIC:
            return []
        if device.services:
            return []
        return [
            SecurityFinding(
                finding_id="BT-012",
                title="No SDP Service Records Found",
                description=(
                    f"Classic device '{device.name}' returned no SDP service records. "
                    "This may indicate a restricted device, a scan limitation, "
                    "or intentional service hiding."
                ),
                risk_level=RiskLevel.INFO,
                recommendation=(
                    "Manually verify SDP records with authorized tools (e.g., sdptool). "
                    "Some devices restrict SDP browsing from unpaired hosts."
                ),
                reference="NIST SP 800-121 Rev 2 §5.2",
            )
        ]

    # ── Risk scoring ─────────────────────────────────────────────────────

    def _compute_risk_score(self, findings: list[SecurityFinding]) -> int:
        """
        Compute a 0–100 risk score from findings.
        Multiple findings of the same level accumulate with diminishing returns.
        """
        score = 0
        level_counts: dict[RiskLevel, int] = {}
        for finding in findings:
            level_counts[finding.risk_level] = level_counts.get(finding.risk_level, 0) + 1

        for level, count in level_counts.items():
            base = RISK_WEIGHTS[level]
            # Diminishing returns: each additional finding contributes 50% of the last
            for i in range(count):
                score += int(base * (0.5 ** i))

        return min(score, MAX_SCORE)
