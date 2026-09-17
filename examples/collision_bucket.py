"""Exercise collision handling with constructed digest strings, not a real SHA-256 collision."""
from mpt_core import TraceabilityIndex, primary_key, verify_record_proof


def main():
    # Synthetic full digests share 128 prefix bits and differ in their suffixes.
    # This is a deterministic functional example, not an observed hash collision.
    first = "ab" * 16 + "01" * 16
    second = "ab" * 16 + "02" * 16
    absent = "ab" * 16 + "03" * 16
    index = TraceabilityIndex()
    index.put_digest(first, {"type": "TestingLog", "ref": "memory://first"})
    index.put_digest(second, {"type": "TestingLog", "ref": "memory://second"})
    assert len(index.primary_items()) == 1
    for digest in (first, second):
        proof = index.prove(digest)
        result = verify_record_proof(index.root_hash, digest, proof.nodes)
        assert result.valid and result.exists
    proof = index.prove(absent)
    result = verify_record_proof(index.root_hash, absent, proof.nodes)
    assert result.valid and not result.exists
    print("Primary key:", primary_key(first))
    print("Primary key bits:", len(primary_key(first)) * 4)
    print("Preserved records in the bucket: 2")
    print("Absent full digest verified inside occupied bucket: True")


if __name__ == "__main__":
    main()
