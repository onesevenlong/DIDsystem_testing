"""128-bit traceability index with atomic collision-bucket insertion."""
from dataclasses import dataclass
from threading import RLock
from typing import Optional, Tuple

from .buckets import BUCKET_TYPE, encode_entries, entries_for
from .encoding import canonical_json, decode_json
from .keys import full_digest, primary_key
from .proofs import ProofResult, verify_path
from .trie import MerklePatriciaTrie


@dataclass(frozen=True)
class RecordProof:
    """Root and nodes captured together. The root still needs external trust."""
    root_hash: Optional[str]
    digest: str
    nodes: Tuple[bytes, ...]


class TraceabilityIndex:
    """Use full SHA-256 digests to select records under 128-bit trie keys.

    Operations are atomic within this instance, not across independent
    processes. Existing records are preserved unless replace=True is explicit.
    """

    def __init__(self):
        self._trie = MerklePatriciaTrie()
        self._lock = RLock()

    @property
    def root_hash(self):
        with self._lock:
            return self._trie.root_hash

    def put_digest(self, digest, record, *, replace=False):
        digest = full_digest(digest)
        key = primary_key(digest)
        if not isinstance(record, dict) or record.get("type") == BUCKET_TYPE:
            raise ValueError("Expected record metadata, not a collision bucket")
        record = decode_json(canonical_json(record))
        if "hash" in record and record["hash"] != digest:
            raise ValueError("Record hash must equal the full index digest")
        record["hash"] = digest
        with self._lock:
            current = self._trie.get(key)
            entries = {} if current is None else dict(entries_for(current, key))
            if digest in entries and entries[digest] != record and not replace:
                raise ValueError("An existing record requires explicit replace=True to change")
            entries[digest] = record
            self._trie.put(key, encode_entries(entries))
        return key

    def get_digest(self, digest, default=None):
        digest = full_digest(digest)
        key = primary_key(digest)
        with self._lock:
            value = self._trie.get(key)
            if value is None:
                return default
            return entries_for(value, key).get(digest, default)

    def prove(self, digest):
        digest = full_digest(digest)
        with self._lock:
            return RecordProof(self._trie.root_hash, digest,
                               self._trie.create_proof(primary_key(digest)))

    def primary_items(self):
        """Detached snapshot of primary keys and their full authenticated values."""
        with self._lock:
            return tuple(self._trie.items())


def verify_record_proof(trusted_root, digest, proof_nodes):
    """Verify an exact full digest, including absence within an occupied bucket.

    Do not obtain trusted_root only from the untrusted proof sender.
    Invalid, missing or malformed evidence yields valid=False.
    """
    try:
        digest = full_digest(digest)
        key = primary_key(digest)
        result = verify_path(trusted_root, key, proof_nodes)
        if not result.valid or not result.exists:
            return result
        entries = entries_for(result.value, key)
        return ProofResult(True, digest in entries, entries.get(digest))
    except (ValueError, TypeError):
        return ProofResult(False, False)
