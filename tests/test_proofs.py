import unittest

from mpt_core import (MerklePatriciaTrie, canonical_json, proof_size, sha256_hex,
                      verify_non_membership_proof, verify_path)


class ProofTests(unittest.TestCase):
    def test_non_membership_at_every_terminal_shape(self):
        cases = [(["abcd"], "abce"),                 # leaf mismatch
                 (["ab01", "ab02"], "ff"),        # extension mismatch
                 (["ab01", "ab02"], "ab"),        # branch has no value
                 (["a0", "b0"], "c0"),            # branch child absent
                 (["abc", "abcd"], "ab")]         # requested key ends in extension
        for keys, absent in cases:
            with self.subTest(keys=keys, absent=absent):
                trie = MerklePatriciaTrie()
                for i, key in enumerate(keys):
                    trie.put(key, i)
                nodes = trie.create_proof(absent)
                self.assertTrue(verify_non_membership_proof(trie.root_hash, absent, nodes))
                self.assertEqual(trie.verify_proof(trie.root_hash, absent, nodes), (False, None))

    def test_tampering_truncation_extra_nodes_and_wrong_root(self):
        trie = MerklePatriciaTrie()
        trie.put("aa01", 1)
        trie.put("aa02", 2)
        nodes = trie.create_proof("aa01")
        self.assertGreater(len(nodes), 1)
        damaged = [(), nodes[:-1], nodes + nodes[-1:], nodes[::-1],
                   nodes[:-1] + (nodes[-1] + b" ",), (None,), (b"bad json",)]
        for proof in damaged:
            self.assertFalse(verify_path(trie.root_hash, "aa01", proof).valid)
            self.assertFalse(verify_non_membership_proof(trie.root_hash, "aa01", proof))
        self.assertFalse(verify_path("00" * 32, "aa01", nodes).valid)
        self.assertEqual(proof_size(nodes), sum(map(len, nodes)))

    def test_valid_membership_is_not_non_membership(self):
        trie = MerklePatriciaTrie()
        for value in (False, 0, "", [], {}):
            trie.put("aa", value)
            proof = trie.create_proof("aa")
            self.assertEqual(trie.verify_proof(trie.root_hash, "aa", proof), (True, value))
            self.assertFalse(verify_non_membership_proof(trie.root_hash, "aa", proof))

    def test_missing_root_and_bad_query_fail_closed(self):
        for root in (None, "", 42, "bad root"):
            self.assertFalse(verify_path(root, "aa", ()).valid)
        trie = MerklePatriciaTrie()
        trie.put("aa", 1)
        for key in (None, "", "xyz"):
            self.assertFalse(verify_path(trie.root_hash, key, trie.create_proof("aa")).valid)

    def test_hash_matching_but_malformed_nodes_are_rejected(self):
        bad_nodes = [
            {"type": "leaf", "key": [True], "value": 1},
            {"type": "leaf", "key": [16], "value": 1},
            {"type": "leaf", "key": [10, 10], "value": None},
            {"type": "extension", "key": [], "child": "00" * 32},
            {"type": "branch", "children": [None], "value": None},
            {"type": "branch", "children": [None] * 15 + ["bad"], "value": None},
            {"type": "other"}, [],
        ]
        for node in bad_nodes:
            data = canonical_json(node)
            self.assertFalse(verify_path(sha256_hex(data), "aa", (data,)).valid)
        duplicate = b'{"key":[10,10],"type":"leaf","value":1,"value":2}'
        self.assertFalse(verify_path(sha256_hex(duplicate), "aa", (duplicate,)).valid)


if __name__ == "__main__":
    unittest.main()
