"""Full digest validation and fixed 128-bit primary indexing."""
import string

HEX = frozenset(string.hexdigits)


def nibbles(key_hex):
    if not isinstance(key_hex, str) or not key_hex or any(c not in HEX for c in key_hex):
        raise ValueError("MPT keys must be non-empty hexadecimal strings")
    return tuple(int(c, 16) for c in key_hex)


def common_prefix(left, right):
    length = 0
    for a, b in zip(left, right):
        if a != b:
            break
        length += 1
    return length


def full_digest(digest):
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in HEX for c in digest):
        raise ValueError("Expected a full SHA-256 digest (64 hexadecimal characters)")
    return digest.lower()


def primary_key(digest):
    """First 32 hex characters = 16 bytes = 128 bits."""
    return full_digest(digest)[:32]
