"""Hexary Patricia trie with SHA-256 roots and synchronous path updates."""
from __future__ import annotations

from threading import RLock
from typing import Any, Iterator, Optional

from .encoding import canonical_json, decode_json
from .keys import nibbles as _nibbles, common_prefix as _common_prefix
from .nodes import BranchNode, ExtensionNode, LeafNode, Node
from .proofs import create_path_proof, verify_membership_proof, verify_non_membership_proof
from .storage import MemoryNodeStore

_MISSING = object()
_CURRENT = object()


class MerklePatriciaTrie:
    """Generic hex-key MPT. Use TraceabilityIndex for 128-bit collision buckets.

    Values are non-null JSON values. ``put`` replaces the value of an exact
    trie key. Writes and point reads are serialized within this instance.
    Historical nodes remain available until the instance is discarded.
    """

    def __init__(self) -> None:
        self.root_hash: Optional[str] = None
        self.db = MemoryNodeStore()
        self._lock = RLock()

    def _store(self, node: Node) -> str:
        return self.db.put(node)

    def put(self, key_hex: str, value: Any) -> None:
        key = _nibbles(key_hex)
        if value is None:
            raise ValueError("Top-level null is reserved for an absent branch value")
        # Detach caller-owned dictionaries/lists before committing them.
        value = decode_json(canonical_json(value))
        with self._lock:
            self.root_hash = self._put(self.root_hash, key, value)

    def get(self, key_hex: str, default: Any = None, *, root_hash: Any = _CURRENT) -> Any:
        key = _nibbles(key_hex)
        with self._lock:
            root = self.root_hash if root_hash is _CURRENT else root_hash
            result = self._get(root, key)
            return default if result is _MISSING else result

    def create_proof(self, key_hex: str, *, root_hash: Any = _CURRENT) -> tuple[bytes, ...]:
        key = _nibbles(key_hex)
        with self._lock:
            root = self.root_hash if root_hash is _CURRENT else root_hash
            return create_path_proof(self.db, root, key)

    @staticmethod
    def verify_proof(root_hash, key_hex, proof):
        """Compatibility API returning (valid_membership, authenticated_value)."""
        return verify_membership_proof(root_hash, key_hex, proof)

    @staticmethod
    def verify_non_membership_proof(root_hash, key_hex, proof):
        return verify_non_membership_proof(root_hash, key_hex, proof)


    def _put(self, node_hash: Optional[str], key: tuple[int, ...], value: Any) -> str:
        if node_hash is None:
            return self._store(LeafNode(key, value))
        node = self.db[node_hash]

        if isinstance(node, LeafNode):
            common = _common_prefix(node.key, key)
            if common == len(node.key) == len(key):
                return self._store(LeafNode(node.key, value))

            branch = BranchNode()
            old_suffix = node.key[common:]
            if old_suffix:
                child = self._store(LeafNode(old_suffix[1:], node.value))
                branch = branch.with_child(old_suffix[0], child)
            else:
                branch = BranchNode(branch.children, node.value)

            new_suffix = key[common:]
            if new_suffix:
                child = self._store(LeafNode(new_suffix[1:], value))
                branch = branch.with_child(new_suffix[0], child)
            else:
                branch = BranchNode(branch.children, value)

            branch_hash = self._store(branch)
            return self._store(ExtensionNode(key[:common], branch_hash)) if common else branch_hash

        if isinstance(node, ExtensionNode):
            common = _common_prefix(node.key, key)
            if common == len(node.key):
                child = self._put(node.child_hash, key[common:], value)
                return self._store(ExtensionNode(node.key, child))

            shared = node.key[:common]
            old_suffix = node.key[common:]
            new_suffix = key[common:]
            branch = BranchNode()
            old_child = node.child_hash
            if len(old_suffix) > 1:
                old_child = self._store(ExtensionNode(old_suffix[1:], old_child))
            branch = branch.with_child(old_suffix[0], old_child)
            if new_suffix:
                new_child = self._store(LeafNode(new_suffix[1:], value))
                branch = branch.with_child(new_suffix[0], new_child)
            else:
                branch = BranchNode(branch.children, value)
            branch_hash = self._store(branch)
            return self._store(ExtensionNode(shared, branch_hash)) if shared else branch_hash

        if not key:
            return self._store(BranchNode(node.children, value))
        child = self._put(node.children[key[0]], key[1:], value)
        return self._store(node.with_child(key[0], child))

    def _get(self, node_hash: Optional[str], key: tuple[int, ...]) -> Any:
        if node_hash is None:
            return _MISSING
        node = self.db[node_hash]
        if isinstance(node, LeafNode):
            return node.value if node.key == key else _MISSING
        if isinstance(node, ExtensionNode):
            if key[: len(node.key)] != node.key:
                return _MISSING
            return self._get(node.child_hash, key[len(node.key) :])
        if not key:
            return node.value if node.value is not None else _MISSING
        return self._get(node.children[key[0]], key[1:])

    def __len__(self) -> int:
        return sum(1 for _ in self.items())

    def items(self) -> Iterator[tuple[str, Any]]:
        if self.root_hash is not None:
            yield from self._items(self.root_hash, ())

    def _items(self, node_hash: str, prefix: tuple[int, ...]) -> Iterator[tuple[str, Any]]:
        node = self.db[node_hash]
        if isinstance(node, LeafNode):
            yield "".join(format(x, "x") for x in prefix + node.key), node.value
        elif isinstance(node, ExtensionNode):
            yield from self._items(node.child_hash, prefix + node.key)
        else:
            if node.value is not None:
                yield "".join(format(x, "x") for x in prefix), node.value
            for index, child in enumerate(node.children):
                if child is not None:
                    yield from self._items(child, prefix + (index,))

    def structural_depth(self) -> int:
        def visit(node_hash: Optional[str]) -> int:
            if node_hash is None:
                return 0
            node = self.db[node_hash]
            if isinstance(node, LeafNode):
                return 1
            if isinstance(node, ExtensionNode):
                return 1 + visit(node.child_hash)
            return 1 + max((visit(child) for child in node.children), default=0)

        return visit(self.root_hash)

    def node_counts(self) -> dict[str, int]:
        reachable: set[str] = set()

        def visit(node_hash: Optional[str]) -> None:
            if node_hash is None or node_hash in reachable:
                return
            reachable.add(node_hash)
            node = self.db[node_hash]
            if isinstance(node, ExtensionNode):
                visit(node.child_hash)
            elif isinstance(node, BranchNode):
                for child in node.children:
                    visit(child)

        visit(self.root_hash)
        nodes = [self.db[digest] for digest in reachable]
        return {
            "reachable": len(nodes),
            "leaf": sum(isinstance(node, LeafNode) for node in nodes),
            "extension": sum(isinstance(node, ExtensionNode) for node in nodes),
            "branch": sum(isinstance(node, BranchNode) for node in nodes),
        }
