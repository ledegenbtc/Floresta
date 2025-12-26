"""
Test the floresta's descriptor management commands:
- loaddescriptor
- listdescriptors
- removedescriptor
"""

from test_framework import FlorestaTestFramework

DATA_DIR = FlorestaTestFramework.get_integration_test_dir()

TEST_DESCRIPTOR = "wsh(sortedmulti(1,[54ff5a12/48h/1h/0h/2h]tpubDDw6pwZA3hYxcSN32q7a5ynsKmWr4BbkBNHydHPKkM4BZwUfiK7tQ26h7USm8kA1E2FvCy7f7Er7QXKF8RNptATywydARtzgrxuPDwyYv4x/<0;1>/*,[bcf969c0/48h/1h/0h/2h]tpubDEFdgZdCPgQBTNtGj4h6AehK79Jm4LH54JrYBJjAtHMLEAth7LuY87awx9ZMiCURFzFWhxToRJK6xp39aqeJWrG5nuW3eBnXeMJcvDeDxfp/<0;1>/*))#fuw35j0q"


class DescriptorsTest(FlorestaTestFramework):
    """
    Test florestad's descriptor management RPC commands:
    loaddescriptor, listdescriptors, and removedescriptor.
    """

    def set_test_params(self):
        """
        Setup a single florestad node
        """
        name = self.__class__.__name__.lower()
        self.data_dirs = DescriptorsTest.create_data_dirs(DATA_DIR, name, 1)
        self.florestad = self.add_node(
            variant="florestad", extra_args=[f"--data-dir={self.data_dirs[0]}"]
        )

    def run_test(self):
        """
        Test the descriptor management commands.
        """
        self.run_node(self.florestad)

        # Test 1: Initially empty
        self.log("=== Test listdescriptors returns empty initially")
        descriptors = self.florestad.rpc.list_descriptors()
        self.assertEqual(descriptors, [])

        # Test 2: Load descriptor
        self.log("=== Test loaddescriptor")
        result = self.florestad.rpc.load_descriptor(TEST_DESCRIPTOR)
        self.assertTrue(result)

        # Test 3: Verify persistence
        self.log("=== Test descriptor persisted")
        descriptors = self.florestad.rpc.list_descriptors()
        self.assertEqual(len(descriptors), 1)
        self.assertEqual(descriptors[0], TEST_DESCRIPTOR)

        # Test 4: Remove descriptor
        self.log("=== Test removedescriptor")
        result = self.florestad.rpc.remove_descriptor(TEST_DESCRIPTOR)
        self.assertTrue(result)

        # Test 5: Verify removal
        self.log("=== Test descriptor removed")
        descriptors = self.florestad.rpc.list_descriptors()
        self.assertEqual(descriptors, [])

        # Test 6: Remove non-existent returns false
        self.log("=== Test remove non-existent descriptor")
        result = self.florestad.rpc.remove_descriptor(TEST_DESCRIPTOR)
        self.assertFalse(result)

        # Test 7: getwalletinfo returns valid structure
        self.log("=== Test getwalletinfo")
        wallet_info = self.florestad.rpc.get_wallet_info()
        self.assertIn("balance", wallet_info)
        self.assertIn("tx_count", wallet_info)
        self.assertIn("utxo_count", wallet_info)
        self.assertIn("address_count", wallet_info)
        self.assertIn("descriptor_count", wallet_info)
        self.assertIn("derivation_index", wallet_info)
        self.assertEqual(wallet_info["descriptor_count"], 0)  # No descriptors loaded

        # Test 8: listtransactions returns empty list when no descriptors
        self.log("=== Test listtransactions (empty)")
        transactions = self.florestad.rpc.list_wallet_transactions()
        self.assertEqual(transactions, [])

        # Test 9: Load descriptor and check wallet info updates
        self.log("=== Test wallet info after loading descriptor")
        self.florestad.rpc.load_descriptor(TEST_DESCRIPTOR)
        wallet_info = self.florestad.rpc.get_wallet_info()
        self.assertEqual(wallet_info["descriptor_count"], 1)
        self.assertGreater(wallet_info["address_count"], 0)  # Should have derived addresses


if __name__ == "__main__":
    DescriptorsTest().main()
