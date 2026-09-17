"""Branch, extension and leaf node encodings used by the application MPT."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Optional, Union
from .encoding import canonical_json as _canonical
@dataclass(frozen=True)
class LeafNode:
    key: tuple[int, ...]
    value: Any

    def serialize(self) -> bytes:
        return _canonical({"type": "leaf", "key": self.key, "value": self.value})

@dataclass(frozen=True)
class ExtensionNode:
    key: tuple[int, ...]
    child_hash: str

    def serialize(self) -> bytes:
        return _canonical({"type": "extension", "key": self.key, "child": self.child_hash})

@dataclass(frozen=True)
class BranchNode:
    children: tuple[Optional[str], ...] = (None,) * 16
    value: Any = None

    def serialize(self) -> bytes:
        return _canonical({"type": "branch", "children": self.children, "value": self.value})

    def with_child(self, index: int, child_hash: Optional[str]) -> "BranchNode":
        children = list(self.children)
        children[index] = child_hash
        return BranchNode(tuple(children), self.value)

Node = Union[LeafNode, ExtensionNode, BranchNode]
