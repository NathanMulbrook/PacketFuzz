# Scapy DNS Resolution Behavior in PacketFuzz

## Problem Overview

During PacketFuzz fuzzing operations, significant performance delays (4-12+ seconds) can occur when mutating IP address fields (`src` and `dst`). These delays are caused by DNS resolution timeouts when Scapy attempts to resolve invalid string values as hostnames.

## Root Cause Analysis

When a string value is assigned to a Scapy IP field (`IP().src` or `IP().dst`), Scapy attempts to interpret the value as either:
1. A valid IP address (e.g., "192.168.1.1")  
2. A hostname to be resolved via DNS (e.g., "google.com")

If the string is neither a valid IP address nor a resolvable hostname, Scapy performs a DNS lookup that times out after ~4 seconds.

### Examples of Problematic Values

The following string values cause 4+ second DNS resolution timeouts:
- `"randomstring123456"` → 3893ms timeout
- `"àüéíöú"` → 3999ms timeout  
- `"invalidhost"` → 3795ms timeout
- `"256.256.256.256"` → Fast failure (invalid IP format)

### Performance Impact

In multilayer fuzzing scenarios:
- Each IP field (src, dst) can trigger multiple mutation attempts
- Each failed mutation attempt includes a 4-second DNS timeout
- Multiple IP fields × multiple attempts = 8-12+ second delays per iteration

## DNS Resolution Controls in Scapy

### Configuration Options Tested

| Option | Effect | Performance Impact |
|--------|--------|-------------------|
| `scapy.conf.checkIPaddr = False` | No effect on DNS lookups | Still triggers DNS resolution |
| `scapy.conf.nameservers = []` | No effect on DNS lookups | Still triggers DNS resolution |
| `scapy.conf.resolve = None` | No effect on DNS lookups | Still triggers DNS resolution |

**None of the Scapy configuration options prevent DNS resolution for IP field assignments.**

## Solutions and Workarounds

### 1. Integer Assignment (Recommended)
Convert string values to integers to bypass DNS resolution entirely:

```python
from scapy.layers.inet import IP

ip = IP()
ip.src = 12345  # Fast: 0.01ms, no DNS lookup
```

### 2. IP Validation with socket.inet_aton()
Validate IP addresses before assignment to avoid invalid formats:

```python
import socket
from scapy.layers.inet import IP

def is_valid_ip(value):
    try:
        socket.inet_aton(str(value))
        return True
    except socket.error:
        return False

ip = IP()
if is_valid_ip("192.168.1.1"):
    ip.src = "192.168.1.1"  # Fast: 0.01ms
else:
    ip.src = 12345  # Fallback to integer
```

### 3. Direct Attribute Assignment (Bypass DNS)
Use `object.__setattr__()` to bypass Scapy's field validation entirely:

```python
from scapy.layers.inet import IP

ip = IP()
# Bypass DNS resolution completely
object.__setattr__(ip, 'src', 'invalidhost')  # Fast: 0.01ms
```

### 4. Comprehensive Safe Assignment Function

```python
import socket
from scapy.layers.inet import IP

def safe_ip_assign(ip_obj, field_name, value):
    """Safely assign a value to IP field without DNS lookup"""
    try:
        # Method 1: Integer values (fastest)
        if isinstance(value, int):
            setattr(ip_obj, field_name, value)
            return True, f'integer: {value}'
            
        # Method 2: Valid IP string 
        if isinstance(value, str):
            try:
                socket.inet_aton(value)  # Validate IP format
                setattr(ip_obj, field_name, value)
                return True, f'valid IP: {value}'
            except socket.error:
                pass
        
        # Method 3: String to integer conversion
        if isinstance(value, str):
            try:
                int_val = int(value)
                setattr(ip_obj, field_name, int_val)
                return True, f'string->int: {value} -> {int_val}'
            except ValueError:
                pass
                
        # Method 4: Direct assignment (bypass DNS)
        object.__setattr__(ip_obj, field_name, value)
        return True, f'direct bypass: {value}'
        
    except Exception as e:
        return False, str(e)
```

## Performance Comparison

| Method | Time | DNS Lookup | Serializes |
|--------|------|------------|------------|
| Standard string assignment (valid IP) | 0.01ms | No | ✅ |
| Standard string assignment (invalid) | 3800-4000ms | Yes | ❌ |
| Integer assignment | 0.01ms | No | ✅ |
| socket.inet_aton() validation | 0.02ms | No | ✅ |
| Direct `object.__setattr__()` | 0.01ms | No | ✅ |

## Implementation in PacketFuzz

**✅ IMPLEMENTED**: The safe assignment function has been integrated into PacketFuzz's validation layer (`mutator_manager_data.py`) to eliminate DNS resolution delays:

### Changes Made

1. **Added `_safe_ip_assign()` method** to `MutatorManagerData` class
2. **Modified `validate_and_assign()`** to use safe IP assignment for IP src/dst fields
3. **Performance improvement**: Reduced multilayer fuzzing time from 8-12+ seconds per iteration to sub-second performance

### Code Integration

```python
def _safe_ip_assign(self, layer_obj, field_name: str, value: Any) -> Tuple[bool, str]:
    """Safely assign IP field values without DNS lookup delays"""
    # 1. Try integer assignment (fastest)
    # 2. Validate IP strings with socket.inet_aton()
    # 3. Convert string integers to integers
    # 4. Use direct assignment to bypass DNS for invalid strings
```

The implementation automatically detects IP layer fields (`layer_name == 'IP'` and `field_name in ['src', 'dst']`) and applies safe assignment, while using standard assignment for all other fields.

### Performance Results

- **Before**: 8-12+ seconds per iteration in multilayer fuzzing
- **After**: 3.7 seconds total for 5 iterations across 2 campaigns  
- **Improvement**: ~95% reduction in execution time

This approach eliminates the 4+ second DNS resolution delays while preserving the ability to fuzz IP fields with a wide range of values, maintaining compatibility with existing fuzzing logic.

## Environment Information

- **Scapy Version**: Tested with Scapy 2.x
- **DNS Resolution**: System-level DNS resolution via glibc
- **Timeout Behavior**: ~4 second timeout for DNS failures
- **OS**: Linux (systemd-resolved)

## Related Issues

- IP field mutations taking 8-12 seconds in multilayer fuzzing
- DNS resolution errors in PacketFuzz logs: `[Errno -3] Temporary failure in name resolution`
- Performance degradation in campaigns with many IP field mutations

## References

- Scapy Documentation: https://scapy.readthedocs.io/
- Python socket.inet_aton(): https://docs.python.org/3/library/socket.html#socket.inet_aton
- DNS Resolution Behavior: https://man7.org/linux/man-pages/man3/gethostbyname.3.html
