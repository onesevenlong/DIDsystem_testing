# Data model and API

## Node commitment

Node identifiers are lowercase SHA-256 hexadecimal digests of serialized node
bytes. JSON uses sorted object keys, compact separators, ASCII escaping and
UTF-8 encoding. Non-finite numbers and non-string object keys are rejected.
The supported node shapes are:

```text
leaf       {"type":"leaf", "key":[nibbles...], "value":record}
extension  {"type":"extension", "key":[nibbles...], "child":node_hash}
branch     {"type":"branch", "children":[16 hashes or nulls], "value":record_or_null}
```

Whitespace above is illustrative. The encoder determines the actual bytes.
This is an application-specific JSON format, not a cross-language JSON
canonicalization standard. Cross-language implementations must reproduce the
same bytes, including string and number encoding, to obtain matching roots.

The generic trie accepts non-empty hexadecimal keys. A top-level JSON null is
reserved for absence and cannot be inserted as a record. Nested nulls are
allowed. New immutable node snapshots are stored as affected paths are rebuilt.
Historical nodes are retained in memory. There is no deletion or garbage
collection API in this release.

## Record indexing

`TraceabilityIndex` always uses `full_digest[:32]` as its primary key. The result
is exactly 32 hexadecimal characters (128 bits), including when a bucket forms.
The full 64-character digest selects the record inside that value.

- Artifacts and logs: digest the exact content bytes supplied by the caller.
- Revocation records: digest the UTF-8 credential identifier.
- An ordinary record remains a single JSON object with a `hash` field.
- Distinct full digests sharing the primary key use this envelope:

```json
{
  "type": "collision_bucket",
  "entries": {
    "<full digest 1>": {"hash": "<full digest 1>", "ref": "..."},
    "<full digest 2>": {"hash": "<full digest 2>", "ref": "..."}
  }
}
```

The `hash` field is the index-source digest. For a revocation record it is the
credential-identifier digest, not a digest of the revocation JSON object. The
node hash commits the complete stored value in either case.

Entries are sorted deterministically. Bucket checking and insertion are guarded
by the same instance lock. This does not coordinate separate processes.
`put_digest` preserves existing records by default. Identical reinsertion is
idempotent. Changing metadata for an existing full digest requires explicit
`replace=True`, which is an application-controlled operation. The MPT does not
enforce revocation-retention policy or validate the semantic correctness of
metadata. Full SHA-256 collisions remain outside the bucket mechanism.

## Public interfaces

| Interface | Purpose |
| --- | --- |
| `MerklePatriciaTrie.put(key_hex, value)` | Insert or replace an exact trie key |
| `get(key_hex, default=None, root_hash=...)` | Lookup under the current or a retained root |
| `create_proof(key_hex, root_hash=...)` | Serialize the authenticated search path |
| `verify_path(root, key, nodes)` | Return `ProofResult(valid, exists, value)` |
| `verify_membership_proof(root, key, nodes)` | Return `(True, value)` only for verified membership |
| `verify_non_membership_proof(root, key, nodes)` | Return true only for verified key absence |
| `proof_size(nodes)` | Sum serialized node byte lengths, excluding framing |
| `TraceabilityIndex.put_digest(digest, record, replace=False)` | Insert using a fixed 128-bit index |
| `get_digest(digest, default=None)` | Select an exact full-digest record |
| `prove(digest)` | Capture a root and proof nodes atomically |
| `verify_record_proof(trusted_root, digest, nodes)` | Verify and select a record, including bucket absence |

The returned `RecordProof.root_hash` identifies the snapshot. It is not, on its
own, evidence that a ledger accepted that root. The verifier must compare it to
its independently authenticated root reference.

## Proof rules

Proof verification checks each serialized node against the expected node hash,
validates node fields and follows the query path. Truncated paths, additional
unnecessary nodes, malformed nodes and modified bytes are rejected.

Authenticated absence can terminate at a mismatching leaf, a mismatching
extension, an empty branch child or an empty branch value. For the record index,
an occupied primary key can also prove absence if the complete authenticated
value contains no matching full digest. The complete bucket is validated before
any record is selected. Bucket contents contribute to proof size.

An empty trie has `root_hash=None`. This API does not accept `None` as a trusted
empty-state commitment. Proof verification without a non-empty trusted root
fails. Unavailable local nodes raise an error rather than becoming evidence of
absence. Supplying missing or invalid remote evidence returns `valid=False`.

These checks concern records represented in one authenticated state. They do
not guarantee real-world event completeness, availability, historical-state
preservation by an external service or correct execution of a reported test.
