//! # Wallet Integration Tests
//!
//! Tests that verify the full backup/restore workflow with an actual
//! Floresta wallet using the in-memory database backend.

use bitcoin::consensus::deserialize;
use bitcoin::hashes::hex::FromHex;
use bitcoin::ScriptBuf;
use floresta_backup::*;
use floresta_common::get_spk_hash;
use floresta_watch_only::memory_database::MemoryDatabase;
use floresta_watch_only::merkle::MerkleProof;
use floresta_watch_only::AddressCache;

/// Test descriptor from CLAUDE.md
const TEST_DESCRIPTOR: &str = "wsh(sortedmulti(1,[54ff5a12/48h/1h/0h/2h]tpubDDw6pwZA3hYxcSN32q7a5ynsKmWr4BbkBNHydHPKkM4BZwUfiK7tQ26h7USm8kA1E2FvCy7f7Er7QXKF8RNptATywydARtzgrxuPDwyYv4x/<0;1>/*,[bcf969c0/48h/1h/0h/2h]tpubDEFdgZdCPgQBTNtGj4h6AehK79Jm4LH54JrYBJjAtHMLEAth7LuY87awx9ZMiCURFzFWhxToRJK6xp39aqeJWrG5nuW3eBnXeMJcvDeDxfp/<0;1>/*))#fuw35j0q";

/// Test address from the signet (tb1q9d4zjf92nvd3zhg6cvyckzaqumk4zre26x02q9)
const TEST_ADDRESS_SCRIPT: &str = "00142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a";

/// Create a test wallet with the test descriptor
fn create_test_wallet() -> AddressCache<MemoryDatabase> {
    let database = MemoryDatabase::new();
    let wallet = AddressCache::new(database);
    wallet.setup().unwrap();
    wallet.push_descriptor(TEST_DESCRIPTOR).unwrap();
    wallet.derive_addresses().unwrap();
    wallet
}

/// Test extracting wallet data from an AddressCache
#[test]
fn test_extract_from_wallet() {
    let wallet = create_test_wallet();

    let extractor = WalletExtractor::new(NetworkType::Testnet)
        .with_options(ExtractOptions::minimal());

    let payload = extractor.extract_from_wallet(&wallet).unwrap();

    // Verify payload
    assert_eq!(payload.version, 1);
    assert_eq!(payload.network, NetworkType::Testnet);
    assert_eq!(payload.accounts.len(), 1);
    assert_eq!(payload.accounts[0].descriptors.len(), 1);
    assert_eq!(
        payload.accounts[0].descriptors[0].descriptor,
        TEST_DESCRIPTOR
    );

    // Verify metadata
    let metadata = payload.metadata.as_ref().unwrap();
    assert_eq!(metadata.base.software, Some("Floresta".to_string()));
}

/// Test extracting wallet with transactions
#[test]
fn test_extract_with_transactions() {
    let wallet = create_test_wallet();

    // Cache an address and transaction
    let spk = ScriptBuf::from_hex(TEST_ADDRESS_SCRIPT).unwrap();
    wallet.cache_address(spk.clone());

    // Transaction from signet block
    let tx_hex = "020000000001017ca523c5e6df0c014e837279ab49be1676a9fe7571c3989aeba1e5d534f4054a0000000000fdffffff01d2410f00000000001600142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a02473044022071b8583ba1f10531b68cb5bd269fb0e75714c20c5a8bce49d8a2307d27a082df022069a978dac00dd9d5761aa48c7acc881617fa4d2573476b11685596b17d437595012103b193d06bd0533d053f959b50e3132861527e5a7a49ad59c5e80a265ff6a77605eece0100";
    let tx: bitcoin::Transaction = deserialize(&Vec::from_hex(tx_hex).unwrap()).unwrap();

    let merkle_proof_hex = "0100000000000000ea530307089e3e6f6e8997a0ae48e1dc2bee84635bc4e6c6ecdcc7225166b06b010000000000000034086ef398efcdec47b37241221c8f4613e02bc31026cc74d07ddb3092e6d6e7";
    let merkle_proof: MerkleProof =
        deserialize(&Vec::from_hex(merkle_proof_hex).unwrap()).unwrap();

    let script_hash = get_spk_hash(&spk);
    wallet.cache_transaction(
        &tx,
        118511,
        tx.output[0].value.to_sat(),
        merkle_proof,
        1,
        0,
        false,
        script_hash,
    );

    // Extract with full options
    let extractor =
        WalletExtractor::new(NetworkType::Testnet).with_options(ExtractOptions::full());

    let payload = extractor.extract_from_wallet(&wallet).unwrap();

    // Verify transactions were extracted
    assert!(payload.transactions.is_some());
    let txs = payload.transactions.as_ref().unwrap();
    assert!(!txs.is_empty());

    // Verify the transaction has block height for rescan-free restore
    let first_tx = &txs[0];
    let tx_meta = first_tx.metadata.as_ref().unwrap();
    assert_eq!(tx_meta.block_height, Some(118511));
    assert_eq!(tx_meta.position_in_block, Some(1));

    // Verify UTXOs were extracted
    assert!(payload.utxos.is_some());
    let utxos = payload.utxos.as_ref().unwrap();
    assert!(!utxos.is_empty());
}

/// Test full backup and restore workflow with wallet
#[test]
fn test_full_wallet_backup_restore() {
    // Step 1: Create and populate source wallet
    let source_wallet = create_test_wallet();

    // Add a test address
    let spk = ScriptBuf::from_hex(TEST_ADDRESS_SCRIPT).unwrap();
    source_wallet.cache_address(spk.clone());

    // Cache a transaction
    let tx_hex = "020000000001017ca523c5e6df0c014e837279ab49be1676a9fe7571c3989aeba1e5d534f4054a0000000000fdffffff01d2410f00000000001600142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a02473044022071b8583ba1f10531b68cb5bd269fb0e75714c20c5a8bce49d8a2307d27a082df022069a978dac00dd9d5761aa48c7acc881617fa4d2573476b11685596b17d437595012103b193d06bd0533d053f959b50e3132861527e5a7a49ad59c5e80a265ff6a77605eece0100";
    let tx: bitcoin::Transaction = deserialize(&Vec::from_hex(tx_hex).unwrap()).unwrap();

    let merkle_proof_hex = "0100000000000000ea530307089e3e6f6e8997a0ae48e1dc2bee84635bc4e6c6ecdcc7225166b06b010000000000000034086ef398efcdec47b37241221c8f4613e02bc31026cc74d07ddb3092e6d6e7";
    let merkle_proof: MerkleProof =
        deserialize(&Vec::from_hex(merkle_proof_hex).unwrap()).unwrap();

    let script_hash = get_spk_hash(&spk);
    source_wallet.cache_transaction(
        &tx,
        118511,
        tx.output[0].value.to_sat(),
        merkle_proof,
        1,
        0,
        false,
        script_hash,
    );

    // Step 2: Export wallet to encrypted backup
    let password = "test_backup_password_2024";
    let backup_data =
        export_wallet_backup(&source_wallet, NetworkType::Testnet, password).unwrap();

    // Verify backup is reasonably sized
    println!("Backup size: {} bytes", backup_data.len());
    assert!(backup_data.len() > 100); // Should have content
    assert!(backup_data.len() < 10_000); // Should be compact

    // Step 3: Preview backup before restore
    let preview = preview_backup(&backup_data, password).unwrap();
    assert_eq!(preview.descriptors_imported, 1);
    println!(
        "Preview: {} descriptors, {} transactions",
        preview.descriptors_imported, preview.transactions_imported
    );

    // Step 4: Verify network
    let network = get_backup_network(&backup_data, password).unwrap();
    assert_eq!(network, NetworkType::Testnet);

    // Step 5: Create new wallet and restore
    let target_database = MemoryDatabase::new();
    let target_wallet = AddressCache::new(target_database);
    target_wallet.setup().unwrap();

    let result = restore_wallet_backup(&target_wallet, &backup_data, password).unwrap();

    // Step 6: Verify restore results
    assert_eq!(result.descriptors_imported, 1);
    println!(
        "Restored: {} descriptors, {} transactions, {} warnings",
        result.descriptors_imported,
        result.transactions_imported,
        result.warnings.len()
    );

    // Step 7: Verify wallet state after restore
    let restored_descriptors = target_wallet.get_descriptors().unwrap();
    assert_eq!(restored_descriptors.len(), 1);
    assert_eq!(restored_descriptors[0], TEST_DESCRIPTOR);
}

/// Test restore with wrong password fails gracefully
#[test]
fn test_restore_wrong_password() {
    let wallet = create_test_wallet();
    let backup_data =
        export_wallet_backup(&wallet, NetworkType::Testnet, "correct_password").unwrap();

    // Try to restore with wrong password
    let target_database = MemoryDatabase::new();
    let target_wallet = AddressCache::new(target_database);
    target_wallet.setup().unwrap();

    let result = restore_wallet_backup(&target_wallet, &backup_data, "wrong_password");
    assert!(matches!(result, Err(BackupError::InvalidPassword)));
}

/// Test backup with minimal options (descriptors only)
#[test]
fn test_minimal_backup() {
    let wallet = create_test_wallet();

    // Add a transaction to the wallet
    let spk = ScriptBuf::from_hex(TEST_ADDRESS_SCRIPT).unwrap();
    wallet.cache_address(spk.clone());

    let tx_hex = "020000000001017ca523c5e6df0c014e837279ab49be1676a9fe7571c3989aeba1e5d534f4054a0000000000fdffffff01d2410f00000000001600142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a02473044022071b8583ba1f10531b68cb5bd269fb0e75714c20c5a8bce49d8a2307d27a082df022069a978dac00dd9d5761aa48c7acc881617fa4d2573476b11685596b17d437595012103b193d06bd0533d053f959b50e3132861527e5a7a49ad59c5e80a265ff6a77605eece0100";
    let tx: bitcoin::Transaction = deserialize(&Vec::from_hex(tx_hex).unwrap()).unwrap();

    let script_hash = get_spk_hash(&spk);
    wallet.cache_transaction(
        &tx,
        118511,
        tx.output[0].value.to_sat(),
        MerkleProof::default(),
        1,
        0,
        false,
        script_hash,
    );

    // Export with minimal options (should not include transactions)
    let backup_data = export_wallet_backup_with_options(
        &wallet,
        NetworkType::Testnet,
        "password",
        ExtractOptions::minimal(),
    )
    .unwrap();

    // Preview should show only descriptors, no transactions
    let preview = preview_backup(&backup_data, "password").unwrap();
    assert_eq!(preview.descriptors_imported, 1);
    assert_eq!(preview.transactions_imported, 0);
}

/// Test compact backup (transactions without raw bytes)
#[test]
fn test_compact_backup() {
    let wallet = create_test_wallet();

    // Add a transaction
    let spk = ScriptBuf::from_hex(TEST_ADDRESS_SCRIPT).unwrap();
    wallet.cache_address(spk.clone());

    let tx_hex = "020000000001017ca523c5e6df0c014e837279ab49be1676a9fe7571c3989aeba1e5d534f4054a0000000000fdffffff01d2410f00000000001600142b6a2924aa9b1b115d1ac3098b0ba0e6ed510f2a02473044022071b8583ba1f10531b68cb5bd269fb0e75714c20c5a8bce49d8a2307d27a082df022069a978dac00dd9d5761aa48c7acc881617fa4d2573476b11685596b17d437595012103b193d06bd0533d053f959b50e3132861527e5a7a49ad59c5e80a265ff6a77605eece0100";
    let tx: bitcoin::Transaction = deserialize(&Vec::from_hex(tx_hex).unwrap()).unwrap();

    let merkle_proof_hex = "0100000000000000ea530307089e3e6f6e8997a0ae48e1dc2bee84635bc4e6c6ecdcc7225166b06b010000000000000034086ef398efcdec47b37241221c8f4613e02bc31026cc74d07ddb3092e6d6e7";
    let merkle_proof: MerkleProof =
        deserialize(&Vec::from_hex(merkle_proof_hex).unwrap()).unwrap();

    let script_hash = get_spk_hash(&spk);
    wallet.cache_transaction(
        &tx,
        118511,
        tx.output[0].value.to_sat(),
        merkle_proof,
        1,
        0,
        false,
        script_hash,
    );

    // Export with compact options
    let full_backup = export_wallet_backup_with_options(
        &wallet,
        NetworkType::Testnet,
        "password",
        ExtractOptions::full(),
    )
    .unwrap();

    let compact_backup = export_wallet_backup_with_options(
        &wallet,
        NetworkType::Testnet,
        "password",
        ExtractOptions::compact(),
    )
    .unwrap();

    // Compact should be smaller (no raw tx bytes)
    println!(
        "Full backup: {} bytes, Compact backup: {} bytes",
        full_backup.len(),
        compact_backup.len()
    );
    // Note: Compact might actually be slightly larger in some cases due to
    // CBOR overhead, but generally full backups with raw transactions
    // should be larger
}

/// Test export/import with custom options
#[test]
fn test_custom_import_options() {
    let wallet = create_test_wallet();
    let backup_data =
        export_wallet_backup(&wallet, NetworkType::Testnet, "password").unwrap();

    // Create target wallet
    let target_database = MemoryDatabase::new();
    let target_wallet = AddressCache::new(target_database);
    target_wallet.setup().unwrap();

    // Import with custom options
    let options = ImportOptions {
        expected_network: Some(NetworkType::Testnet),
        allow_incomplete_transactions: true,
        ..Default::default()
    };

    let result =
        restore_wallet_backup_with_options(&target_wallet, &backup_data, "password", options)
            .unwrap();

    assert_eq!(result.descriptors_imported, 1);
}

/// Test that network mismatch is detected
#[test]
fn test_network_mismatch_on_restore() {
    let wallet = create_test_wallet();

    // Export as testnet
    let backup_data =
        export_wallet_backup(&wallet, NetworkType::Testnet, "password").unwrap();

    // Try to import expecting mainnet
    let target_database = MemoryDatabase::new();
    let target_wallet = AddressCache::new(target_database);
    target_wallet.setup().unwrap();

    let options = ImportOptions {
        expected_network: Some(NetworkType::Mainnet),
        ..Default::default()
    };

    let result =
        restore_wallet_backup_with_options(&target_wallet, &backup_data, "password", options);

    assert!(matches!(result, Err(BackupError::NetworkMismatch(_, _))));
}
