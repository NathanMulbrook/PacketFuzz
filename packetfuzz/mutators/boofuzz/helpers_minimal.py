"""
Minimal helpers module for boofuzz primitive support.

Contains only the essential functions needed by the boofuzz primitives.
"""


def str_to_bytes(value, encoding="utf-8", errors="replace"):
    """Convert a string or other value to bytes.
    
    Args:
        value: Value to convert to bytes
        encoding: Text encoding to use
        errors: How to handle encoding errors
        
    Returns:
        bytes: The value as bytes
    """
    if isinstance(value, bytes):
        return value
    return str(value).encode(encoding, errors)
