"""Full-digest selection inside a fixed-length trie index."""
from .keys import full_digest, primary_key

BUCKET_TYPE = "collision_bucket"


def entries_for(value, key):
    """Validate the complete authenticated value before selecting an entry."""
    if not isinstance(value, dict):
        raise ValueError("Traceability values must be objects")
    if value.get("type") == BUCKET_TYPE:
        if set(value) != {"type", "entries"} or not isinstance(value["entries"], dict):
            raise ValueError("Invalid collision bucket")
        entries = value["entries"]
        if len(entries) < 2:
            raise ValueError("A collision bucket must contain at least two records")
    else:
        entries = {full_digest(value.get("hash")): value}
    for digest, record in entries.items():
        if full_digest(digest) != digest or primary_key(digest) != key:
            raise ValueError("Bucket digest does not match its primary index")
        if not isinstance(record, dict) or record.get("hash") != digest:
            raise ValueError("Record hash does not match the full-digest selector")
        if record.get("type") == BUCKET_TYPE:
            raise ValueError("Nested collision buckets are not record values")
    return entries


def encode_entries(entries):
    if len(entries) == 1:
        return next(iter(entries.values()))
    return {"type": BUCKET_TYPE, "entries": dict(sorted(entries.items()))}
