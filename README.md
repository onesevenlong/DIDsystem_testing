# MPT Core for Testing Traceability

A small Python implementation of the application-level Merkle Patricia Trie
used to organize testing-artifact commitments, log metadata and credential
revocation records in a shared authenticated state.

The code is split into focused modules and uses the Python standard library.
It includes no plotting scripts, experiment datasets or benchmark results.

## Features

- Hexary branch, extension and leaf nodes with deterministic JSON serialization.
- SHA-256 node addressing and synchronous root updates on insertion.
- Record lookup and root-bound membership and non-membership verification.
- A 128-bit primary record index with full SHA-256 digest selection inside
  collision buckets. Distinct colliding records are preserved.
- In-memory node storage that retains previous nodes for historical-root queries.
- Small examples and functional tests, including concurrent bucket insertion.

## Quick start

Python 3.8 or newer is required. No third-party runtime packages are needed.
Run these commands from the repository root, where this README is located:

```sh
python -m examples.basic_usage
python -m examples.collision_bucket
python -m unittest discover -s tests -v
```

Optional installation for use from another project:

```sh
python -m pip install .
```

## Minimal use

```python
from mpt_core import TraceabilityIndex, log_record, verify_record_proof

index = TraceabilityIndex()
digest, record = log_record(b"example log", "memory://log/1")
index.put_digest(digest, record)

# In this local example the owner of the index supplies the trusted root.
# In a deployment, obtain it from an authenticated ledger reference.
trusted_root = index.root_hash
evidence = index.prove(digest)
result = verify_record_proof(trusted_root, digest, evidence.nodes)
assert result.valid and result.exists
assert result.value == record
```

`valid=False` means verification failed. `valid=True, exists=False` means the
specific full digest is absent from the authenticated state. Missing evidence
must never be interpreted as verified absence. A root supplied only by an
untrusted proof sender is not an independent trust reference.

## Layout

| File | Responsibility |
| --- | --- |
| `mpt_core/encoding.py` | Deterministic JSON encoding and SHA-256 |
| `mpt_core/keys.py` | Hex paths, full digests and 128-bit indices |
| `mpt_core/nodes.py` | Branch, extension and leaf node definitions |
| `mpt_core/codec.py` | Strict serialized-node decoding |
| `mpt_core/storage.py` | Immutable serialized node storage in memory |
| `mpt_core/trie.py` | Trie insertion, lookup and structural traversal |
| `mpt_core/proofs.py` | Path proofs and membership/non-membership verification |
| `mpt_core/buckets.py` | Collision-bucket encoding and record selection |
| `mpt_core/index.py` | Atomic full-digest record insertion and proof APIs |
| `mpt_core/records.py` | Artifact, log and revocation metadata constructors |
| `mpt_core/__init__.py` | Public exports |
| `examples/` | Two short runnable examples |
| `tests/` | Functional and verification tests |
| `docs/design.md` | Key format, proof rules and API details |

## Scope

This is a standalone MPT core. Ledger integration, DID resolution, credential
signatures and application authorization belong to the surrounding framework.
The node format uses JSON and SHA-256, not Ethereum RLP or Keccak.

Proofs authenticate the specified committed state. They do not establish that
all real-world events were recorded, that raw evidence is available, or that a
reported test actually occurred. The in-memory store is not persistent across
process restarts. The collision example uses deliberately constructed digest
strings and does not claim to have found a SHA-256 collision.

The core is organized from the traceability implementation, with standalone
proof validation and a record-index layer. Its insertion structure and node
encoding are retained. This release also protects stored values from caller
mutation and keeps collision checks and bucket writes within one instance lock.
It is a functional code release, not a benchmark reproduction package.
