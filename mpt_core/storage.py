"""Content-addressed memory storage with immutable serialized node snapshots."""
from collections.abc import Mapping

from .codec import decode_node
from .encoding import sha256_hex


class MemoryNodeStore(Mapping):
    """Reads return detached nodes so external mutation cannot change a root.

    Previous nodes are retained for explicit historical-root queries.
    This is an in-memory store, not a persistent database.
    """

    def __init__(self):
        self._encoded = {}

    def put(self, node):
        encoded = node.serialize()
        digest = sha256_hex(encoded)
        self._encoded[digest] = encoded
        return digest

    def serialized(self, digest):
        # Missing storage data raises KeyError, never produces non-membership.
        return self._encoded[digest]

    def __getitem__(self, digest):
        return decode_node(self._encoded[digest])

    def __iter__(self):
        return iter(self._encoded)

    def __len__(self):
        return len(self._encoded)
