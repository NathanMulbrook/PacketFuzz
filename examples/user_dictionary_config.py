#!/usr/bin/env python3
"""
User Dictionary Configuration

This file provides user-specific dictionary configurations that override
the default mappings for specific fields and protocols.
"""

# Example user dictionary configuration
USER_FIELD_DICTIONARIES = {
    "TCP.dport": ["custom_ports.txt", "common_ports.txt"],
    "UDP.dport": ["udp_ports.txt"],
    "Raw.load": ["payloads.txt"]
}

USER_FIELD_VALUES = {
    "TCP.dport": [8080, 8443, 9000, 3000],
    "UDP.dport": [53, 67, 68, 123]
}

USER_FIELD_WEIGHTS = {
    "TCP.dport": 0.8,
    "UDP.dport": 0.6,
    "Raw.load": 0.9
}
