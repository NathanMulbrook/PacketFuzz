# Debug Tools

This directory contains debugging and investigation scripts used during development to analyze and troubleshoot specific behavior in the fuzzing framework.

## Scripts

- `debug_actual_weights.py` - Debug specific field weights and mutation behavior
- `debug_depth_calculation.py` - Debug layer depth calculation logic
- `debug_depth_with_raw.py` - Investigate Raw layer depth effects
- `debug_direct_scaling.py` - Debug direct scaling behavior
- `debug_field_fuzzing_path.py` - Debug field fuzzing path resolution
- `debug_force_fuzz_behavior.py` - Debug forced fuzzing behavior
- `debug_ip_dst_*.py` - Various IP destination field debugging scripts
- `debug_key_construction.py` - Debug dictionary key construction
- `debug_resolution_path.py` - Debug resolution path logic
- `debug_retry_behavior.py` - Debug retry behavior
- `debug_scaling_logic.py` - Debug scaling logic implementation
- `debug_skip_logic.py` - Debug field skipping logic
- `debug_weight_calculations.py` - Debug weight calculation logic
- `debug_weight_resolution.py` - Debug weight resolution process
- `inspect_field_weights.py` - Inspect actual field weights during fuzzing
- `investigate_raw_layer_effect.py` - Investigate Raw layer effects on scaling

## Usage

These scripts are development tools and can be run directly:

```bash
cd /path/to/PacketFuzz
python utils/debug/debug_actual_weights.py
```

Note: These tools import from the main framework and are intended for debugging and analysis during development.
