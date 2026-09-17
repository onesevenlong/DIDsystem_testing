import unittest

from mpt_core import (TraceabilityIndex, artifact_record, log_record,
                      revocation_record, sha256_hex, verify_record_proof)


class RecordTests(unittest.TestCase):
    def test_record_types_share_an_authenticated_state(self):
        index = TraceabilityIndex()
        pairs = [artifact_record(b"artifact", "memory://artifact"),
                 log_record(b"log", "memory://log", {"projectDID": "did:example:p"}),
                 revocation_record("urn:example:vc:1", "2026-01-01T12:00:00Z")]
        for digest, record in pairs:
            index.put_digest(digest, record)
        trusted_root = index.root_hash
        for digest, record in pairs:
            proof = index.prove(digest)
            result = verify_record_proof(trusted_root, digest, proof.nodes)
            self.assertTrue(result.valid and result.exists)
            self.assertEqual(result.value, record)
        self.assertEqual(pairs[-1][0], sha256_hex(b"urn:example:vc:1"))
        self.assertEqual(pairs[-1][1]["revocationTime"], "2026-01-01T12:00:00Z")


if __name__ == "__main__":
    unittest.main()
