#!/usr/bin/env python3
"""
BTAudit — Quick launcher (no install needed)
Made by Monish Paramasivam

Usage:
    sudo python3 run.py scan --duration 15
    sudo python3 run.py dashboard
    python3 run.py --help
"""
import sys
import subprocess

# Auto-install dependencies if missing
def ensure_deps():
    try:
        import click
        import bleak
    except ImportError:
        print("[*] Installing dependencies...")
        subprocess.check_call([
            sys.executable, "-m", "pip", "install",
            "bleak>=0.21.1", "click>=8.1.7",
            "fastapi>=0.110.0", "uvicorn[standard]>=0.29.0",
            "--break-system-packages", "-q"
        ])
        print("[✓] Dependencies installed\n")

ensure_deps()

# Add src to path so btaudit package is importable without pip install
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from btaudit.cli import main
main()
