#!/usr/bin/env python3
"""
PacketFuzz - Main Entry Point

This module provides the main entry point for running PacketFuzz via 'python -m packetfuzz'.
Following the pattern used by pytest, scapy, pip, and other major Python CLI tools.
"""

from packetfuzz.cli import main

if __name__ == "__main__":
    exit(main())
