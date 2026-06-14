"""
Pytest configuration and shared fixtures.
Made by Monish Paramasivam
"""

import os
import pytest


@pytest.fixture(autouse=True)
def set_ci_auth_env(monkeypatch):
    """
    Auto-set BTAUDIT_AUTHORIZED=1 for all tests so consent checks pass
    without requiring interactive terminal input.
    """
    monkeypatch.setenv("BTAUDIT_AUTHORIZED", "1")
    monkeypatch.setenv("BTAUDIT_AUTHORIZED_BY", "Pytest CI Runner")
    monkeypatch.setenv("BTAUDIT_ENVIRONMENT", "Automated Test Suite")
