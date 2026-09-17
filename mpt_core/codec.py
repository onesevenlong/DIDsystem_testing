"""Strict decoding of the node format committed by the root."""
from .encoding import canonical_json, decode_json
from .keys import full_digest
from .nodes import BranchNode, ExtensionNode, LeafNode


def _path(value, nonempty=False):
    if not isinstance(value, list) or (nonempty and not value):
        raise ValueError("Invalid node path")
    if any(type(n) is not int or not 0 <= n < 16 for n in value):
        raise ValueError("Path entries must be integer nibbles")
    return tuple(value)


def _digest(value):
    if full_digest(value) != value:
        raise ValueError("Node references must use lowercase hexadecimal")
    return value


def decode_node(data):
    if not isinstance(data, bytes):
        raise ValueError("Serialized nodes must be bytes")
    obj = decode_json(data)
    if not isinstance(obj, dict) or canonical_json(obj) != data:
        raise ValueError("Invalid or noncanonical node encoding")
    kind = obj.get("type")
    if kind == "leaf" and set(obj) == {"type", "key", "value"}:
        if obj["value"] is None:
            raise ValueError("Leaf value cannot be null")
        return LeafNode(_path(obj["key"]), obj["value"])
    if kind == "extension" and set(obj) == {"type", "key", "child"}:
        return ExtensionNode(_path(obj["key"], nonempty=True), _digest(obj["child"]))
    if kind == "branch" and set(obj) == {"type", "children", "value"}:
        children = obj["children"]
        if not isinstance(children, list) or len(children) != 16:
            raise ValueError("A branch must have 16 children")
        return BranchNode(tuple(None if c is None else _digest(c) for c in children), obj["value"])
    raise ValueError("Invalid node type or fields")
