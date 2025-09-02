"""
Pattern matching utilities for PacketFuzz wildcard support.

This module provides shared functionality for matching field patterns across
the fuzzing framework and mutator manager systems.

Supported pattern types:
- Exact matches: "TCP.dport", "*.checksum", "TCP.*" 
- Enhanced wildcards: "HTTP*.port*", "TCP*.d*", "*.*addr*"
- Pattern types: layer_field_wildcard, layer_wildcard, field_wildcard
"""

import fnmatch
from typing import Any, Dict, List, Set


def has_wildcards(text: str) -> bool:
    """Check if text contains wildcard characters (* or ?)."""
    return '*' in text or '?' in text


def wildcard_match(field_pattern: str, wildcard_pattern: str) -> bool:
    """
    Match a field pattern against a wildcard pattern using enhanced matching.
    
    Examples:
    - field_pattern="HTTP.port", wildcard_pattern="HTTP*.port*" -> True
    - field_pattern="TCP.dport", wildcard_pattern="TCP*.port*" -> True
    - field_pattern="IP.version", wildcard_pattern="HTTP*.*" -> False
    
    Args:
        field_pattern: Pattern to check (e.g., "TCP.dport")
        wildcard_pattern: Wildcard pattern to match against (e.g., "HTTP*.port*")
        
    Returns:
        True if the field pattern matches the wildcard pattern
    """
    # Handle *.* pattern (matches everything)
    if wildcard_pattern == "*.*":
        return True
    
    # For patterns without dots, treat as field-only wildcard
    if '.' not in wildcard_pattern:
        if '.' in field_pattern:
            _, field_part = field_pattern.split('.', 1)
            return fnmatch.fnmatch(field_part, wildcard_pattern)
        else:
            return fnmatch.fnmatch(field_pattern, wildcard_pattern)
    
    # Handle layer.field wildcard patterns
    if '.' in field_pattern and '.' in wildcard_pattern:
        field_layer, field_name = field_pattern.split('.', 1)
        pattern_layer, pattern_field = wildcard_pattern.split('.', 1)
        
        # Match both layer and field parts
        layer_match = fnmatch.fnmatch(field_layer, pattern_layer)
        field_match = fnmatch.fnmatch(field_name, pattern_field)
        
        return layer_match and field_match
    
    # Fallback to simple fnmatch
    return fnmatch.fnmatch(field_pattern, wildcard_pattern)


def pattern_matches_any(field_pattern: str, whitelist_patterns: Set[str]) -> bool:
    """
    Check if a field pattern matches any pattern in the whitelist.
    
    Supports enhanced wildcard matching:
    - Exact matches: "TCP.dport"
    - Layer wildcards: "TCP*" matches TCP, TCPAO, etc.
    - Field wildcards: "port*" matches port, portnum, etc.
    - Combined wildcards: "HTTP*.port*"
    
    Args:
        field_pattern: Pattern to check (e.g., "TCP.dport")
        whitelist_patterns: Set of whitelisted patterns
        
    Returns:
        True if the pattern matches any whitelist entry
    """
    # Direct match
    if field_pattern in whitelist_patterns:
        return True
    
    # Check against each whitelist pattern
    for whitelist_pattern in whitelist_patterns:
        # Handle enhanced wildcard patterns
        if has_wildcards(whitelist_pattern):
            if wildcard_match(field_pattern, whitelist_pattern):
                return True
        else:
            # Handle traditional patterns
            if '.' in field_pattern:
                layer_part, field_part = field_pattern.split('.', 1)
                
                # Check if *.field matches
                if f"*.{field_part}" in whitelist_patterns:
                    return True
                    
                # Check if Layer.* matches  
                if f"{layer_part}.*" in whitelist_patterns:
                    return True
                    
                # Check if just field name matches (treated as *.field)
                if field_part in whitelist_patterns:
                    return True
    
    return False


def matches_enhanced_pattern(layer_name: str, field_name: str, override: Dict[str, Any]) -> bool:
    """
    Check if a layer.field matches an enhanced wildcard pattern from an override entry.
    
    Supports pattern types:
    - layer_field_wildcard: Both layer and field have wildcards (e.g., HTTP*.port*)
    - layer_wildcard: Only layer has wildcards (e.g., HTTP*.dport)
    - field_wildcard: Only field has wildcards (e.g., TCP.port*)
    
    Args:
        layer_name: Name of the layer (e.g., "HTTP", "TCP")
        field_name: Name of the field (e.g., "dport", "version")
        override: Override entry with pattern information
        
    Returns:
        True if the layer.field matches the pattern
    """
    pattern = override.get('pattern', '')
    pattern_type = override.get('pattern_type', '')
    
    if pattern_type == 'layer_field_wildcard':
        # Pattern like "HTTP*.port*" - both layer and field have wildcards
        if '.' in pattern:
            pattern_layer, pattern_field = pattern.split('.', 1)
            layer_match = fnmatch.fnmatch(layer_name, pattern_layer)
            field_match = fnmatch.fnmatch(field_name, pattern_field)
            return layer_match and field_match
        else:
            # Fallback to simple field matching
            return fnmatch.fnmatch(field_name, pattern)
    
    elif pattern_type == 'layer_wildcard':
        # Pattern like "HTTP*" with specific field
        pattern_layer = pattern.split('.')[0] if '.' in pattern else pattern
        specific_field = override.get('field', '')
        layer_match = fnmatch.fnmatch(layer_name, pattern_layer)
        field_match = (field_name == specific_field)
        return layer_match and field_match
    
    elif pattern_type == 'field_wildcard':
        # Pattern like "port*" with specific layer
        specific_layer = override.get('layer', '')
        pattern_field = pattern.split('.')[1] if '.' in pattern else pattern
        layer_match = (layer_name == specific_layer)
        field_match = fnmatch.fnmatch(field_name, pattern_field)
        return layer_match and field_match
    
    # Fallback: try to match the full pattern against layer.field
    full_field_name = f"{layer_name}.{field_name}"
    return fnmatch.fnmatch(full_field_name, pattern)


def parse_field_patterns(patterns: List[str], exclude: bool = True) -> List[Dict[str, Any]]:
    """
    Parse field patterns and convert them to advanced_field_mapping_overrides entries.
    
    Supported patterns:
    - "TCP.dport" - specific field in specific layer
    - "*.dport" - field in any layer  
    - "TCP.*" - all fields in specific layer
    - "dport" - field name only (treated as *.dport)
    - "HTTP*.port*" - layers starting with "HTTP", fields starting with "port"
    - "*.*" - all fields in all layers (use with caution)
    
    Enhanced wildcard support:
    - Layer wildcards: "HTTP*" matches HTTP, HTTPRequest, HTTPResponse, etc.
    - Field wildcards: "port*" matches port, portnum, etc.
    - Combined: "TCP*.port*" matches TCP.dport, TCPAO.portnum, etc.
    
    Args:
        patterns: List of field patterns to parse
        exclude: If True, set fuzz_weight=0.0, if False set fuzz_weight=1.0
        
    Returns:
        List of mapping entries for advanced_field_mapping_overrides
    """
    entries = []
    weight = 0.0 if exclude else 1.0
    
    for pattern in patterns:
        if '.' in pattern:
            layer_part, field_part = pattern.split('.', 1)
            
            # Handle *.* (all fields, all layers) - broad match
            if layer_part == '*' and field_part == '*':
                entries.append({
                    "fuzz_weight": weight,
                    "description": f"Pattern match: {pattern} (all fields in all layers)"
                })
            
            # Handle *.field - field in any layer
            elif layer_part == '*' and not has_wildcards(field_part):
                entries.append({
                    "field": field_part,
                    "fuzz_weight": weight,
                    "description": f"Pattern match: {pattern}"
                })
            
            # Handle layer.* - all fields in specific layer
            elif not has_wildcards(layer_part) and field_part == '*':
                entries.append({
                    "layer": layer_part,
                    "fuzz_weight": weight,
                    "description": f"Pattern match: {pattern}"
                })
            
            # Handle specific layer.field - exact match
            elif not has_wildcards(layer_part) and not has_wildcards(field_part):
                entries.append({
                    "layer": layer_part,
                    "field": field_part,
                    "fuzz_weight": weight,
                    "description": f"Pattern match: {pattern}"
                })
            
            # Handle enhanced wildcard patterns (layer*.field*, *.field*, layer*.*)
            else:
                # Use regex-style pattern matching for complex wildcards
                entry = {
                    "pattern": pattern,
                    "fuzz_weight": weight,
                    "description": f"Pattern match: {pattern} (enhanced wildcard)"
                }
                
                # Add pattern type for the mutator system to handle
                if has_wildcards(layer_part) and has_wildcards(field_part):
                    entry["pattern_type"] = "layer_field_wildcard"
                elif has_wildcards(layer_part):
                    entry["pattern_type"] = "layer_wildcard"
                    entry["field"] = field_part
                elif has_wildcards(field_part):
                    entry["pattern_type"] = "field_wildcard"
                    entry["layer"] = layer_part
                
                entries.append(entry)
        else:
            # Pattern: field_name - treat as *.field_name
            if has_wildcards(pattern):
                # Enhanced field wildcard (e.g., "port*")
                entries.append({
                    "pattern": f"*.{pattern}",
                    "pattern_type": "field_wildcard",
                    "fuzz_weight": weight,
                    "description": f"Pattern match: *.{pattern} (field wildcard)"
                })
            else:
                # Exact field name in any layer
                entries.append({
                    "field": pattern,
                    "fuzz_weight": weight,
                    "description": f"Pattern match: *.{pattern}"
                })
    
    return entries
