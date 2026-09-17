"""Run from the repository root: python -m examples.basic_usage"""
from mpt_core import (TraceabilityIndex, artifact_record, log_record, proof_size,
                      revocation_record, sha256_hex, verify_record_proof)


def main():
    index = TraceabilityIndex()
    artifact_hash, artifact = artifact_record(b"synthetic test artifact", "memory://artifact/1")
    log_hash, log = log_record(b"synthetic test log", "memory://log/1",
                              {"submitterDID": "did:example:tester",
                               "projectDID": "did:example:project",
                               "credentialIdentifier": "urn:example:vc:1"})
    vc_hash, revoked = revocation_record("urn:example:vc:1", "2026-01-01T12:00:00Z")
    for digest, record in ((artifact_hash, artifact), (log_hash, log), (vc_hash, revoked)):
        index.put_digest(digest, record)

    # Local demo only: a deployed verifier obtains this root from its trusted ledger view.
    trusted_root = index.root_hash
    proof = index.prove(log_hash)
    result = verify_record_proof(trusted_root, log_hash, proof.nodes)
    assert result.valid and result.exists and result.value == log
    print("Root:", trusted_root)
    print("Log membership:", result.valid and result.exists)
    print("Serialized proof bytes:", proof_size(proof.nodes))

    missing_hash = sha256_hex(b"a record that was not inserted")
    missing_proof = index.prove(missing_hash)
    missing = verify_record_proof(trusted_root, missing_hash, missing_proof.nodes)
    assert missing.valid and not missing.exists
    print("Verified record absence:", missing.valid and not missing.exists)

    corrupt = list(proof.nodes)
    corrupt[-1] += b" "
    assert not verify_record_proof(trusted_root, log_hash, corrupt).valid
    print("Tampered proof rejected: True")


if __name__ == "__main__":
    main()
