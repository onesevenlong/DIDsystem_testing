from concurrent.futures import ThreadPoolExecutor
import unittest

from mpt_core import (MerklePatriciaTrie, TraceabilityIndex, primary_key,
                      sha256_hex, verify_record_proof)


def synthetic_digest(i):
    # Constructed digest strings for testing only, not mined hash collisions.
    return "ab" * 16 + format(i, "032x")


class IndexTests(unittest.TestCase):
    def test_collision_preserves_records_and_fixed_key(self):
        index = TraceabilityIndex()
        first, second, absent = map(synthetic_digest, (1, 2, 3))
        index.put_digest(first, {"ref": "first"})
        self.assertEqual(index.primary_items()[0][1], {"hash": first, "ref": "first"})
        index.put_digest(second, {"ref": "second"})
        self.assertEqual(len(index.primary_items()), 1)
        self.assertEqual(len(index.primary_items()[0][0]), 32)
        for digest, ref in ((first, "first"), (second, "second")):
            self.assertEqual(index.get_digest(digest)["ref"], ref)
            evidence = index.prove(digest)
            verified = verify_record_proof(index.root_hash, digest, evidence.nodes)
            self.assertTrue(verified.valid and verified.exists)
        evidence = index.prove(absent)
        result = verify_record_proof(index.root_hash, absent, evidence.nodes)
        self.assertTrue(result.valid)
        self.assertFalse(result.exists)

    def test_non_membership_in_single_record_value(self):
        index = TraceabilityIndex()
        index.put_digest(synthetic_digest(1), {"ref": "first"})
        absent = synthetic_digest(2)
        result = verify_record_proof(index.root_hash, absent, index.prove(absent).nodes)
        self.assertTrue(result.valid and not result.exists)

    def test_bucket_encoding_is_insertion_order_independent(self):
        roots = []
        for order in ((1, 2, 3), (3, 1, 2)):
            index = TraceabilityIndex()
            for i in order:
                index.put_digest(synthetic_digest(i), {"i": i})
            roots.append(index.root_hash)
        self.assertEqual(roots[0], roots[1])

    def test_concurrent_bucket_insertions_do_not_lose_records(self):
        index = TraceabilityIndex()
        def insert(i):
            index.put_digest(synthetic_digest(i), {"i": i})
        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(insert, range(40)))
        for i in range(40):
            self.assertEqual(index.get_digest(synthetic_digest(i))["i"], i)
        self.assertEqual(len(index.primary_items()), 1)

    def test_explicit_update_and_input_validation(self):
        index = TraceabilityIndex()
        digest = sha256_hex(b"record")
        index.put_digest(digest, {"ref": "old"})
        root = index.root_hash
        with self.assertRaises(ValueError):
            index.put_digest(digest, {"ref": "new"})
        self.assertEqual(root, index.root_hash)
        with self.assertRaises(ValueError):
            index.put_digest(digest, {"hash": "00" * 32})
        index.put_digest(digest, {"ref": "new"}, replace=True)
        self.assertEqual(index.get_digest(digest)["ref"], "new")

    def test_historical_bucket_proof_and_omitted_entry_tampering(self):
        index = TraceabilityIndex()
        index.put_digest(synthetic_digest(1), {"i": 1})
        index.put_digest(synthetic_digest(2), {"i": 2})
        proof = index.prove(synthetic_digest(1))
        index.put_digest(synthetic_digest(3), {"i": 3})
        self.assertTrue(verify_record_proof(proof.root_hash, proof.digest, proof.nodes).exists)
        self.assertFalse(verify_record_proof(index.root_hash, proof.digest, proof.nodes).valid)
        import json
        from mpt_core import canonical_json
        leaf = json.loads(proof.nodes[-1])
        del leaf["value"]["entries"][synthetic_digest(1)]
        corrupt = proof.nodes[:-1] + (canonical_json(leaf),)
        self.assertFalse(verify_record_proof(proof.root_hash, proof.digest, corrupt).valid)

    def test_malformed_authenticated_bucket_is_invalid_not_absent(self):
        trie = MerklePatriciaTrie()
        digest = synthetic_digest(1)
        trie.put(primary_key(digest), {"type": "collision_bucket", "entries": {}})
        result = verify_record_proof(trie.root_hash, digest, trie.create_proof(primary_key(digest)))
        self.assertFalse(result.valid)


if __name__ == "__main__":
    unittest.main()
