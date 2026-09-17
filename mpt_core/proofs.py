"""Root-bound membership and non-membership proofs with explicit failure states."""
from dataclasses import dataclass
from typing import Any

from .codec import decode_node
from .encoding import sha256_hex
from .keys import full_digest, nibbles
from .nodes import BranchNode, ExtensionNode, LeafNode


@dataclass(frozen=True)
class ProofResult:
    valid: bool
    exists: bool
    value: Any = None


def create_path_proof(store, root_hash, key):
    proof = []
    while root_hash is not None:
        data = store.serialized(root_hash)
        proof.append(data)
        node = decode_node(data)
        if isinstance(node, LeafNode):
            break
        if isinstance(node, ExtensionNode):
            if key[:len(node.key)] != node.key:
                break
            key, root_hash = key[len(node.key):], node.child_hash
        else:
            if not key:
                break
            root_hash, key = node.children[key[0]], key[1:]
    return tuple(proof)


def verify_path(root_hash, key_hex, proof):
    """Return valid/existing/value. Invalid evidence is never verified absence.

    A trusted, non-empty root must be supplied by the caller. ``None`` means
    no authenticated root, not a proof that the application has no records.
    """
    invalid = ProofResult(False, False)
    try:
        expected = full_digest(root_hash)
        key = nibbles(key_hex)
        if not isinstance(proof, (tuple, list)) or not proof:
            return invalid
        for position, data in enumerate(proof):
            if not isinstance(data, bytes) or sha256_hex(data) != expected:
                return invalid
            node = decode_node(data)
            last = position == len(proof) - 1
            if isinstance(node, LeafNode):
                if not last:
                    return invalid
                exists = node.key == key
                return ProofResult(True, exists, node.value if exists else None)
            if isinstance(node, ExtensionNode):
                if node.key != key[:len(node.key)]:
                    return ProofResult(True, False) if last else invalid
                expected, key = node.child_hash, key[len(node.key):]
                if last:
                    return invalid
            elif isinstance(node, BranchNode):
                if not key:
                    return ProofResult(True, node.value is not None, node.value) if last else invalid
                expected, key = node.children[key[0]], key[1:]
                if expected is None:
                    return ProofResult(True, False) if last else invalid
                if last:
                    return invalid
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return invalid
    return invalid


def verify_membership_proof(root_hash, key_hex, proof):
    result = verify_path(root_hash, key_hex, proof)
    return (True, result.value) if result.valid and result.exists else (False, None)


def verify_non_membership_proof(root_hash, key_hex, proof):
    result = verify_path(root_hash, key_hex, proof)
    return result.valid and not result.exists


def proof_size(proof):
    """Serialized node bytes only, excluding framing and external evidence."""
    return sum(len(node) for node in proof)
