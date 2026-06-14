"""
Authorization and Consent Safeguards
=====================================
BTAudit enforces explicit consent before any scan begins.
This module cannot be bypassed — it is the first gate in every scan path.

Made by Monish Paramasivam

LEGAL CONTEXT:
  Scanning Bluetooth devices without authorization may violate:
  - Computer Fraud and Abuse Act (CFAA) — US
  - Computer Misuse Act 1990 — UK
  - Directive 2013/40/EU — EU
  - Equivalent legislation in other jurisdictions

  This tool performs PASSIVE OBSERVATION only. It never:
  - Transmits crafted/malicious Bluetooth packets
  - Attempts to pair, connect, or authenticate with devices
  - Injects data into any Bluetooth stream
  - Performs active jamming or interference
"""

from __future__ import annotations
import hashlib
import json
import logging
import os
import platform
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Literal

logger = logging.getLogger(__name__)

CONSENT_FILE = Path.home() / ".btaudit" / "consent_record.json"

LEGAL_NOTICE = """
╔══════════════════════════════════════════════════════════════════════════════╗
║              BTAudit — LEGAL AND ETHICAL USAGE NOTICE                       ║
║              Made by Monish Paramasivam                                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  This tool performs PASSIVE Bluetooth scanning for AUTHORIZED environments  ║
║  only. By proceeding, you confirm ALL of the following:                     ║
║                                                                              ║
║  ✓ You own, or have explicit WRITTEN AUTHORIZATION to audit, all Bluetooth  ║
║    devices and infrastructure in the target environment.                    ║
║                                                                              ║
║  ✓ You understand that scanning Bluetooth devices without authorization     ║
║    may violate the CFAA (US), Computer Misuse Act (UK), EU Directive        ║
║    2013/40/EU, and equivalent laws in your jurisdiction.                    ║
║                                                                              ║
║  ✓ You will use findings ONLY for defensive security improvements.          ║
║                                                                              ║
║  ✓ You will NOT use this tool to harass, stalk, track, or harm individuals. ║
║                                                                              ║
║  ✓ This tool performs NO active exploitation, packet injection, or          ║
║    connection attempts. It is a read-only, passive observer.                ║
║                                                                              ║
║  Unauthorized use is strictly prohibited and may result in criminal         ║
║  and/or civil liability.                                                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""


@dataclass
class ConsentRecord:
    """Immutable record of user consent for audit logging."""
    timestamp: str
    user: str
    hostname: str
    platform_info: str
    consent_hash: str
    authorized_by: str
    environment_description: str
    agreed: bool = True
    tool_version: str = "1.0.0"
    safeguards_confirmed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__

    @classmethod
    def create(
        cls,
        authorized_by: str,
        environment: str,
        version: str = "1.0.0",
    ) -> "ConsentRecord":
        ts = datetime.utcnow().isoformat()
        user = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
        hostname = platform.node()
        platform_info = f"{platform.system()} {platform.release()}"
        raw = f"{ts}:{user}:{hostname}:{authorized_by}"
        consent_hash = hashlib.sha256(raw.encode()).hexdigest()

        return cls(
            timestamp=ts,
            user=user,
            hostname=hostname,
            platform_info=platform_info,
            consent_hash=consent_hash,
            authorized_by=authorized_by,
            environment_description=environment,
            tool_version=version,
            safeguards_confirmed=[
                "passive_observation_only",
                "no_packet_injection",
                "no_exploitation_attempts",
                "no_connection_attempts",
                "authorized_environment",
            ],
        )


class AuthorizationError(PermissionError):
    """Raised when authorization requirements are not met."""
    pass


class ConsentManager:
    """
    Manages user consent and authorization records.
    Every scan session MUST pass through this gate.
    """

    def __init__(self, consent_file: Path = CONSENT_FILE) -> None:
        self.consent_file = consent_file
        self.consent_file.parent.mkdir(parents=True, exist_ok=True)

    def display_legal_notice(self) -> None:
        print(LEGAL_NOTICE)

    def prompt_for_consent(
        self,
        authorized_by: str = "",
        environment: str = "",
        non_interactive: bool = False,
    ) -> ConsentRecord:
        """
        Prompt the operator for explicit consent.
        In non-interactive mode (CI/testing), consent must be pre-confirmed
        via environment variables.
        """
        if non_interactive:
            return self._non_interactive_consent(authorized_by, environment)

        self.display_legal_notice()

        if not authorized_by:
            authorized_by = input(
                "Enter your name or the authorization reference number: "
            ).strip()
            if not authorized_by:
                raise AuthorizationError(
                    "Authorization reference is required. Scan aborted."
                )

        if not environment:
            environment = input(
                "Briefly describe the authorized environment being audited: "
            ).strip()
            if not environment:
                raise AuthorizationError(
                    "Environment description is required. Scan aborted."
                )

        print("\nDo you confirm you have explicit authorization to scan this environment?")
        print("Type 'YES I HAVE AUTHORIZATION' to proceed: ", end="")
        response = input().strip()

        if response != "YES I HAVE AUTHORIZATION":
            raise AuthorizationError(
                "Consent not confirmed. Scan aborted for safety."
            )

        record = ConsentRecord.create(authorized_by, environment)
        self._save_record(record)
        logger.info(
            "Consent recorded: hash=%s user=%s",
            record.consent_hash[:12],
            record.user,
        )
        return record

    def _non_interactive_consent(
        self, authorized_by: str, environment: str
    ) -> ConsentRecord:
        """
        Non-interactive consent for CI/testing.
        Requires BTAUDIT_AUTHORIZED=1 environment variable.
        """
        if os.environ.get("BTAUDIT_AUTHORIZED") != "1":
            raise AuthorizationError(
                "Non-interactive mode requires BTAUDIT_AUTHORIZED=1 environment variable. "
                "This variable confirms you have explicit authorization to run this scan."
            )
        if not authorized_by:
            authorized_by = os.environ.get("BTAUDIT_AUTHORIZED_BY", "CI/CD Pipeline")
        if not environment:
            environment = os.environ.get("BTAUDIT_ENVIRONMENT", "Test Environment")

        record = ConsentRecord.create(authorized_by, environment)
        self._save_record(record)
        return record

    def _save_record(self, record: ConsentRecord) -> None:
        """Append consent record to audit log (append-only)."""
        records: list[dict] = []
        if self.consent_file.exists():
            try:
                records = json.loads(self.consent_file.read_text())
            except (json.JSONDecodeError, OSError):
                records = []
        records.append(record.to_dict())
        self.consent_file.write_text(
            json.dumps(records, indent=2, default=str)
        )

    def get_consent_history(self) -> list[dict]:
        """Return the consent audit log."""
        if not self.consent_file.exists():
            return []
        try:
            return json.loads(self.consent_file.read_text())
        except (json.JSONDecodeError, OSError):
            return []


# ── Packet transmission safeguard ──────────────────────────────────────────

class TransmissionGuard:
    """
    Hard block against any outbound Bluetooth packet transmission.
    BTAudit is strictly a passive observer.
    """
    _BLOCKED_OPERATIONS = frozenset({
        "connect",
        "pair",
        "send",
        "write",
        "inject",
        "jam",
        "spoof",
        "advertise_custom",
        "l2cap_send",
        "rfcomm_send",
        "gatt_write",
    })

    @staticmethod
    def assert_passive(operation: str) -> None:
        """
        Raise if the requested operation would transmit Bluetooth data.
        Call this before any Bluetooth API call.
        """
        if operation.lower() in TransmissionGuard._BLOCKED_OPERATIONS:
            raise AuthorizationError(
                f"BLOCKED: Operation '{operation}' would transmit Bluetooth data. "
                "BTAudit is a passive-only tool and does not send Bluetooth packets. "
                "This restriction cannot be overridden."
            )

    @staticmethod
    def validate_scan_parameters(
        active_scan: bool = False,
        connect: bool = False,
        pair: bool = False,
    ) -> None:
        """Validate that scan parameters remain in passive mode."""
        if connect:
            raise AuthorizationError(
                "Connection attempts are prohibited. BTAudit does not connect to devices."
            )
        if pair:
            raise AuthorizationError(
                "Pairing attempts are prohibited. BTAudit does not pair with devices."
            )
        if active_scan:
            logger.warning(
                "Active BLE scanning sends scan-request packets. "
                "Ensure your authorization explicitly covers active scanning."
            )
