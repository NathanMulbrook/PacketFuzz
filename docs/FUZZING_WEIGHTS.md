# Fuzzing Weights & Layer Scaling

## Fuzzing Weights Overview

**Fuzzing weights** control mutation probability and intensity for packet fields, enabling targeted fuzzing over random mutations.

### Weight System
- **Higher weights (0.7-1.0)**: More mutations, aggressive changes
- **Lower weights (0.1-0.4)**: Fewer mutations, gentle changes  
- **Zero weight**: Skip field entirely

### Weight Resolution Priority
| Priority | Source | Range | Description |
|----------|--------|-------|-------------|
| **1** | User config | 0.0-1.0 | Explicit field weights |
| **2** | Field mappings | 0.7-0.9 | Property-based rules |
| **3** | Name patterns | 0.6-0.8 | Field name matching |
| **4** | Type defaults | 0.5-0.7 | Scapy field type |
| **5** | Framework default | 0.5 | Unmatched fields |

**See**: `examples/config/user_dictionary_config.py` for configuration examples.
---

# Layer Weight Scaling

## Overview
Layer weight scaling controls mutation distribution across protocol layers. Outer layers (IP, TCP headers) can be scaled independently from inner layers (payload).

### Core Concept
```
effective_weight = base_weight × (scaling_factor ^ depth_below_surface)
```

- **Lower scaling (0.1)**: Less fuzzing of outer layers
- **Higher scaling (0.9)**: More fuzzing of outer layers  
- **Default**: 0.5 (balanced)

### Layer Depth Example
```
IP Layer    (depth=2) → weight = base × scaling²
TCP Layer   (depth=1) → weight = base × scaling¹  
Raw Payload (depth=0) → weight = base × scaling⁰ (unchanged)
```

**With scaling=0.1**: IP gets 1% weight, TCP gets 10% weight, payload gets 100%
**With scaling=0.9**: IP gets 81% weight, TCP gets 90% weight, payload gets 100%

## Configuration

```python
class MyFuzzingCampaign(FuzzingCampaign):
    def __init__(self):
        super().__init__()
        self.layer_weight_scaling = 0.1  # Focus on inner layers
        self.enable_layer_weight_scaling = True
```

## Use Cases

### Web Application Testing (Focus on Payload)
```python
class WebAppFuzzCampaign(FuzzingCampaign):
    def __init__(self):
        super().__init__()
        self.layer_weight_scaling = 0.1  # Minimize header mutations
        
    def get_packet(self):
        return IP(dst="192.168.1.100") / TCP(dport=80) / Raw("HTTP data")
```

### Network Infrastructure Testing (Focus on Headers)
```python
class NetworkInfraCampaign(FuzzingCampaign):
    def __init__(self):
        super().__init__()
        self.layer_weight_scaling = 0.8  # More header mutations
```

## Best Practices & Validation

### Reliable Fields for Testing
- **IP.ttl**: Strong scaling behavior (8.5% → 0.0% with 0.9 → 0.1)
- **TCP.sport/dport/seq**: Excellent scaling with Raw layer (30% → 3.5%)
- **UDP.sport**: Strong scaling in basic scenarios (32% → 4%)

### Known Edge Cases
- **IP.src**: Often 0% mutations (dictionary config dependent)
- **IP.dst**: May show 100% mutations (campaign target override)
- **No Raw layer**: May cause inconsistent scaling
- **Random seed effects**: ±2-3% variation between runs

### Recommendations
1. **Include Raw layer** for most reliable scaling
2. **Test with extreme values** (0.01 vs 0.99) to validate
3. **Focus on TCP/UDP fields** for validation rather than IP.src/dst
4. **Average multiple runs** for consistent measurements

## Troubleshooting

### Scaling Not Working
1. Verify `enable_layer_weight_scaling = True`
2. Ensure packet has multiple layers
3. Add Raw layer for reliable behavior
4. Use extreme values (0.01 vs 0.99) for visibility

### Inconsistent Results  
1. Run multiple iterations and average
2. Use packets with Raw layer
3. Focus on TCP/UDP fields for validation

### Expected Behavior
- **IP.src**: 0% mutations (dictionary config)
- **IP.dst**: May be overridden by campaign
- **Fields without dictionaries**: Scaling applies to logic, may appear unchanged

---

**Tests**: `tests/test_layer_weight_scaling.py` - PASSING  
**Performance**: Minimal impact (~0.001ms per field)  
**Last Updated**: August 25, 2025
