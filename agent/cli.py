#!/usr/bin/env python3
"""CLI entry: python -m agent.cli …"""
from .orchestrator import main

if __name__ == "__main__":
    raise SystemExit(main())
