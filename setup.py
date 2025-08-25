#!/usr/bin/env python3
"""
Setup script for PacketFuzz

Provides automated dependency installation and framework setup.
"""

from setuptools import setup, find_packages

setup(
    name="PacketFuzz",
    version="2.0.0",
    description="Modern class-based network protocol fuzzing framework built on Scapy",
    python_requires=">=3.10",
    install_requires=["scapy"],
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "packetfuzz=packetfuzz.cli:main",
        ],
    },
)
