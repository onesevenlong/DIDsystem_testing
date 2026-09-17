"""Deterministic application JSON encoding (not Ethereum RLP)."""
import hashlib
import json
import math


def _validate(value):
    if value is None or type(value) in (str, int, bool):
        return
    if type(value) is float and math.isfinite(value):
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _validate(item)
        return
    if isinstance(value, dict) and all(isinstance(k, str) for k in value):
        for item in value.values():
            _validate(item)
        return
    raise ValueError("Values must contain JSON data with string object keys and finite numbers")


def canonical_json(value):
    """Sorted keys, compact separators, ASCII escaping, and UTF-8 bytes."""
    _validate(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def decode_json(data):
    return json.loads(data.decode("utf-8"))


def sha256_hex(data):
    if not isinstance(data, bytes):
        raise TypeError("Hash input must be bytes")
    return hashlib.sha256(data).hexdigest()
