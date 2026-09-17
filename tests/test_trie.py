import itertools
import random
import unittest

from mpt_core import MerklePatriciaTrie, sha256_hex


class TrieTests(unittest.TestCase):
    def test_root_matches_source_implementation_fixture(self):
        trie = MerklePatriciaTrie()
        for key, value in (("abcd", {"value": 1}), ("abef", {"value": 2}), ("ab", {"value": 3})):
            trie.put(key, value)
        self.assertEqual(trie.root_hash,
                         "b42c01741279bd77ea52a3c79e97296508fe6b2e7d769d0e7f993412a87d2725")

    def test_split_prefix_lookup_update_and_structure(self):
        trie = MerklePatriciaTrie()
        expected = {"ab": 1, "abcd": 2, "abcf": 3, "abef": 4, "f": 5}
        for key, value in expected.items():
            trie.put(key, value)
        trie.put("abcd", 20)
        expected["abcd"] = 20
        self.assertEqual(dict(trie.items()), expected)
        for key, value in expected.items():
            self.assertEqual(trie.get(key.upper()), value)
        self.assertIsNone(trie.get("ffff"))
        self.assertEqual(len(trie), len(expected))
        self.assertGreater(trie.structural_depth(), 1)
        self.assertGreater(trie.node_counts()["branch"], 0)

    def test_insertion_order_does_not_change_root(self):
        records = [("ab", {"x": 1}), ("ab01", {"x": 2}), ("ab02", {"x": 3}), ("f", False)]
        roots = set()
        for order in itertools.permutations(records):
            trie = MerklePatriciaTrie()
            for key, value in order:
                trie.put(key, value)
            roots.add(trie.root_hash)
        self.assertEqual(len(roots), 1)

    def test_random_operations_match_dictionary(self):
        rng = random.Random(2026)
        trie, expected = MerklePatriciaTrie(), {}
        for i in range(400):
            key = "".join(rng.choice("0123456789abcdef") for _ in range(rng.randint(1, 12)))
            value = {"i": i, "nested": [False, None, "test"]}
            trie.put(key, value)
            expected[key] = value
        self.assertEqual(dict(trie.items()), expected)
        for key, value in expected.items():
            self.assertEqual(trie.verify_proof(trie.root_hash, key, trie.create_proof(key)), (True, value))

    def test_caller_mutation_cannot_change_committed_nodes(self):
        trie = MerklePatriciaTrie()
        original = {"nested": [1, {"a": 2}]}
        trie.put("aa", original)
        root = trie.root_hash
        proof = trie.create_proof("aa")
        original["nested"][1]["a"] = 999
        trie.get("aa")["nested"].append(3)
        trie.db[root].value["nested"].clear()
        self.assertEqual(trie.create_proof("aa"), proof)
        self.assertEqual(trie.get("aa"), {"nested": [1, {"a": 2}]})
        for digest, node in trie.db.items():
            self.assertEqual(digest, sha256_hex(node.serialize()))

    def test_historical_root_and_idempotent_write(self):
        trie = MerklePatriciaTrie()
        trie.put("aa", {"a": 1})
        old_root, old_proof = trie.root_hash, trie.create_proof("aa")
        trie.put("aa", {"a": 1})
        self.assertEqual(old_root, trie.root_hash)
        trie.put("aa", {"a": 2})
        self.assertEqual(trie.get("aa", root_hash=old_root), {"a": 1})
        self.assertEqual(trie.create_proof("aa", root_hash=old_root), old_proof)
        self.assertEqual(trie.verify_proof(old_root, "aa", old_proof), (True, {"a": 1}))
        self.assertEqual(trie.verify_proof(trie.root_hash, "aa", old_proof), (False, None))

    def test_invalid_key_and_non_json_values(self):
        trie = MerklePatriciaTrie()
        for key in ("", "no", "a b", None, 7):
            with self.assertRaises(ValueError):
                trie.put(key, 1)
        for value in (None, float("nan"), float("inf"), {1: "bad"}, {"bad": object()}):
            with self.assertRaises(ValueError):
                trie.put("aa", value)
        self.assertIsNone(trie.root_hash)

    def test_missing_storage_is_not_record_absence(self):
        trie = MerklePatriciaTrie()
        trie.put("aa", 1)
        # Simulate storage failure below the public API.
        trie.db._encoded.clear()
        with self.assertRaises(KeyError):
            trie.get("aa")
        with self.assertRaises(KeyError):
            trie.create_proof("aa")


if __name__ == "__main__":
    unittest.main()
