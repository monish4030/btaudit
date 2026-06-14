"""
Unit tests for consent and transmission safeguard modules.
Made by Monish Paramasivam
"""

import os
import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch

from src.btaudit.consent import (
    ConsentManager,
    ConsentRecord,
    AuthorizationError,
    TransmissionGuard,
)


class TestConsentRecord:
    def test_create_generates_hash(self):
        rec = ConsentRecord.create("Alice", "Lab Network")
        assert len(rec.consent_hash) == 64  # SHA-256 hex digest

    def test_create_sets_agreed(self):
        rec = ConsentRecord.create("Alice", "Lab")
        assert rec.agreed is True

    def test_create_includes_safeguards(self):
        rec = ConsentRecord.create("Alice", "Lab")
        assert "passive_observation_only" in rec.safeguards_confirmed
        assert "no_packet_injection" in rec.safeguards_confirmed
        assert "no_exploitation_attempts" in rec.safeguards_confirmed

    def test_to_dict_serializable(self):
        rec = ConsentRecord.create("Bob", "Office")
        d = rec.to_dict()
        assert isinstance(d, dict)
        assert d["authorized_by"] == "Bob"
        assert d["environment_description"] == "Office"


class TestConsentManager:
    def _temp_manager(self) -> ConsentManager:
        tmp = tempfile.mkdtemp()
        return ConsentManager(consent_file=Path(tmp) / "consent.json")

    def test_non_interactive_requires_env_var(self, monkeypatch):
        monkeypatch.delenv("BTAUDIT_AUTHORIZED", raising=False)
        mgr = self._temp_manager()
        with pytest.raises(AuthorizationError, match="BTAUDIT_AUTHORIZED=1"):
            mgr._non_interactive_consent("Alice", "Lab")

    def test_non_interactive_with_env_var(self, monkeypatch):
        monkeypatch.setenv("BTAUDIT_AUTHORIZED", "1")
        mgr = self._temp_manager()
        rec = mgr._non_interactive_consent("Alice", "Lab")
        assert rec.authorized_by == "Alice"

    def test_save_record_creates_file(self, monkeypatch):
        monkeypatch.setenv("BTAUDIT_AUTHORIZED", "1")
        mgr = self._temp_manager()
        rec = ConsentRecord.create("Carol", "Test Lab")
        mgr._save_record(rec)
        assert mgr.consent_file.exists()

    def test_save_and_retrieve_record(self, monkeypatch):
        monkeypatch.setenv("BTAUDIT_AUTHORIZED", "1")
        mgr = self._temp_manager()
        rec = ConsentRecord.create("Dave", "Pentest Lab")
        mgr._save_record(rec)
        history = mgr.get_consent_history()
        assert len(history) == 1
        assert history[0]["authorized_by"] == "Dave"

    def test_multiple_saves_append(self, monkeypatch):
        monkeypatch.setenv("BTAUDIT_AUTHORIZED", "1")
        mgr = self._temp_manager()
        mgr._save_record(ConsentRecord.create("Eve", "Lab A"))
        mgr._save_record(ConsentRecord.create("Frank", "Lab B"))
        history = mgr.get_consent_history()
        assert len(history) == 2

    def test_get_consent_history_empty(self):
        mgr = self._temp_manager()
        assert mgr.get_consent_history() == []

    def test_prompt_non_interactive_uses_env_defaults(self, monkeypatch):
        monkeypatch.setenv("BTAUDIT_AUTHORIZED", "1")
        monkeypatch.setenv("BTAUDIT_AUTHORIZED_BY", "CI Bot")
        monkeypatch.setenv("BTAUDIT_ENVIRONMENT", "Test Env")
        mgr = self._temp_manager()
        rec = mgr.prompt_for_consent(non_interactive=True)
        assert rec.authorized_by == "CI Bot"
        assert rec.environment_description == "Test Env"


class TestTransmissionGuard:
    def test_blocks_connect(self):
        with pytest.raises(AuthorizationError, match="BLOCKED"):
            TransmissionGuard.assert_passive("connect")

    def test_blocks_pair(self):
        with pytest.raises(AuthorizationError, match="BLOCKED"):
            TransmissionGuard.assert_passive("pair")

    def test_blocks_inject(self):
        with pytest.raises(AuthorizationError, match="BLOCKED"):
            TransmissionGuard.assert_passive("inject")

    def test_blocks_send(self):
        with pytest.raises(AuthorizationError, match="BLOCKED"):
            TransmissionGuard.assert_passive("send")

    def test_allows_scan(self):
        # Should not raise
        TransmissionGuard.assert_passive("scan")

    def test_allows_discover(self):
        TransmissionGuard.assert_passive("discover")

    def test_validate_scan_blocks_connect(self):
        with pytest.raises(AuthorizationError):
            TransmissionGuard.validate_scan_parameters(connect=True)

    def test_validate_scan_blocks_pair(self):
        with pytest.raises(AuthorizationError):
            TransmissionGuard.validate_scan_parameters(pair=True)

    def test_validate_scan_passive_ok(self):
        # Should not raise
        TransmissionGuard.validate_scan_parameters(
            active_scan=False, connect=False, pair=False
        )

    def test_case_insensitive_block(self):
        with pytest.raises(AuthorizationError):
            TransmissionGuard.assert_passive("CONNECT")
