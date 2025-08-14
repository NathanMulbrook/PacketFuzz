# Minimal dictionary config for CLI tests
FIELD_ADVANCED_WEIGHTS = [
    {"layer": "IP", "field": "dst", "fuzz_weight": 1.0},
    {"layer": "TCP", "field": "dport", "fuzz_weight": 1.0}
]
