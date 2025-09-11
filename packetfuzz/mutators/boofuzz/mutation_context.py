"""
Minimal mutation context module for boofuzz primitive support.

Contains simplified versions of classes needed by the boofuzz primitives.
"""


class MutationContext:
    """Simplified mutation context for basic primitive operations."""
    
    def __init__(self, mutations=None):
        self.mutations = mutations or {}
        self.message_path = []
        self.protocol_session = None
