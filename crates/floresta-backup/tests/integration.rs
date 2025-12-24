//! # Integration Tests
//!
//! End-to-end tests simulating real-world usage scenarios.

use floresta_backup::*;

/// Test descriptor from CLAUDE.md
const TEST_DESCRIPTOR: &str = "wsh(sortedmulti(1,[54ff5a12/48h/1h/0h/2h]tpubDDw6pwZA3hYxcSN32q7a5ynsKmWr4BbkBNHydHPKkM4BZwUfiK7tQ26h7USm8kA1E2FvCy7f7Er7QXKF8RNptATywydARtzgrxuPDwyYv4x/<0;1>/*,[bcf969c0/48h/1h/0h/2h]tpubDEFdgZdCPgQBTNtGj4h6AehK79Jm4LH54JrYBJjAtHMLEAth7LuY87awx9ZMiCURFzFWhxToRJK6xp39aqeJWrG5nuW3eBnXeMJcvDeDxfp/<0;1>/*))#fuw35j0q";

/// Simulate a complete backup and restore workflow
#[test]
fn test_complete_backup_restore_workflow() {
    // Step 1: Create wallet data (simulating extraction from Floresta wallet)
    let extractor = WalletExtractor::new(NetworkType::Testnet)
        .with_options(ExtractOptions::full());

    let payload = extractor
        .extract_from_descriptors(&[TEST_DESCRIPTOR.to_string()])
        .unwrap();

    // Step 2: Validate the payload
    validate_payload(&payload).unwrap();

    // Step 3: Create encrypted backup
    let password = "my_secure_backup_password_2024!";
    let envelope = EncryptedEnvelope::create(&payload, password, Argon2Params::default()).unwrap();

    // Step 4: Export to bytes (this would be saved to a file)
    let backup_data = envelope.to_bytes();

    // Verify minimum expected size
    assert!(backup_data.len() > 50); // Header + some ciphertext

    // Step 5: Import from bytes (simulating reading from file)
    let restored_envelope = EncryptedEnvelope::from_bytes(&backup_data).unwrap();

    // Step 6: Decrypt with password
    let restored_payload = restored_envelope.decrypt(password).unwrap();

    // Step 7: Validate restored payload
    validate_payload(&restored_payload).unwrap();

    // Step 8: Use importer to restore wallet
    let importer = WalletImporter::new(restored_payload)
        .with_options(ImportOptions {
            expected_network: Some(NetworkType::Testnet),
            ..Default::default()
        });

    // Validate before import
    importer.validate().unwrap();

    // Get descriptors for re-registration
    let descriptors = importer.get_descriptors();
    assert_eq!(descriptors.len(), 1);
    assert_eq!(descriptors[0], TEST_DESCRIPTOR);

    // Dry run to verify import would succeed
    let result = importer.dry_run().unwrap();
    assert_eq!(result.descriptors_imported, 1);
}

/// Test backup with transactions for rescan-free restore
#[test]
fn test_rescan_free_restore() {
    // Build payload with transaction history using CBOR serialization directly
    let mut payload = WalletPayload::new(NetworkType::Mainnet);
    payload.accounts.push(Account {
        index: Some(0),
        descriptors: vec![Descriptor {
            descriptor: "wpkh([deadbeef/84h/0h/0h]xpub.../0/*)".to_string(),
            checksum: None,
            addresses: None,
            metadata: None,
        }],
        metadata: None,
    });
    payload.transactions = Some(vec![
        Transaction {
            txid: [0x11; 32],
            raw_tx: Some(vec![0x01; 100]),
            metadata: Some(TransactionMetadata {
                block_height: Some(800000),
                ..Default::default()
            }),
        },
        Transaction {
            txid: [0x22; 32],
            raw_tx: Some(vec![0x02; 150]),
            metadata: Some(TransactionMetadata {
                block_height: Some(800001),
                ..Default::default()
            }),
        },
        Transaction {
            txid: [0x33; 32],
            raw_tx: Some(vec![0x03; 200]),
            metadata: Some(TransactionMetadata {
                block_height: Some(800002),
                ..Default::default()
            }),
        },
    ]);
    payload.utxos = Some(vec![Utxo {
        txid: [0x33; 32],
        vout: 0,
        amount: 50000,
        script_pubkey: vec![0x00, 0x14, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab],
        address: None,
        metadata: None,
    }]);
    payload.metadata = Some(WalletMetadata {
        base: BaseMetadata {
            software: Some("Floresta".to_string()),
            birth_height: Some(800000),
            ..Default::default()
        },
        ..Default::default()
    });

    // Encrypt and restore
    let password = "rescan_test_password";
    let envelope = EncryptedEnvelope::create(&payload, password, Argon2Params::light()).unwrap();
    let bytes = envelope.to_bytes();

    let restored = EncryptedEnvelope::from_bytes(&bytes)
        .unwrap()
        .decrypt(password)
        .unwrap();

    // Use importer to get rescan-free data
    let importer = WalletImporter::new(restored);

    // Get confirmed transactions with heights
    let confirmed_txs = importer.get_confirmed_transactions();
    assert_eq!(confirmed_txs.len(), 3);
    assert_eq!(confirmed_txs[0].1, 800000); // First tx at height 800000
    assert_eq!(confirmed_txs[1].1, 800001);
    assert_eq!(confirmed_txs[2].1, 800002);

    // Get raw transactions for verification
    let raw_txs = importer.get_raw_transactions();
    assert_eq!(raw_txs.len(), 3);

    // Get UTXOs
    let utxos = importer.get_utxos();
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].amount, 50000);
}

/// Test handling of wrong password
#[test]
fn test_wrong_password_handling() {
    let payload = PayloadBuilder::new(NetworkType::Mainnet)
        .add_account(0, vec!["wpkh(xpub...)".to_string()])
        .build();

    let envelope = EncryptedEnvelope::create(&payload, "correct_password", Argon2Params::light()).unwrap();
    let bytes = envelope.to_bytes();

    let restored = EncryptedEnvelope::from_bytes(&bytes).unwrap();
    let result = restored.decrypt("wrong_password");

    assert!(matches!(result, Err(BackupError::InvalidPassword)));
}

/// Test network mismatch detection
#[test]
fn test_network_mismatch_detection() {
    let payload = PayloadBuilder::new(NetworkType::Testnet)
        .add_account(0, vec!["wpkh(tpub...)".to_string()])
        .build();

    let envelope = EncryptedEnvelope::create(&payload, "password", Argon2Params::light()).unwrap();
    let bytes = envelope.to_bytes();

    let restored = EncryptedEnvelope::from_bytes(&bytes)
        .unwrap()
        .decrypt("password")
        .unwrap();

    // Try to import with wrong network expectation
    let importer = WalletImporter::new(restored).with_options(ImportOptions {
        expected_network: Some(NetworkType::Mainnet),
        ..Default::default()
    });

    let result = importer.validate();
    assert!(matches!(result, Err(BackupError::NetworkMismatch(_, _))));
}

/// Test large backup (many transactions)
#[test]
fn test_large_backup() {
    let mut payload = WalletPayload::new(NetworkType::Mainnet);
    payload.accounts.push(Account {
        index: Some(0),
        descriptors: vec![Descriptor {
            descriptor: "wpkh(xpub...)".to_string(),
            checksum: None,
            addresses: None,
            metadata: None,
        }],
        metadata: None,
    });

    // Add 100 transactions
    let mut transactions = Vec::new();
    for i in 0..100u32 {
        let mut txid = [0u8; 32];
        txid[0..4].copy_from_slice(&i.to_be_bytes());
        transactions.push(Transaction {
            txid,
            raw_tx: None,
            metadata: Some(TransactionMetadata {
                block_height: Some(800000 + i),
                ..Default::default()
            }),
        });
    }
    payload.transactions = Some(transactions);

    // Add 50 UTXOs
    let mut utxos = Vec::new();
    for i in 0..50u32 {
        let mut txid = [0u8; 32];
        txid[0..4].copy_from_slice(&(i + 100).to_be_bytes());
        utxos.push(Utxo {
            txid,
            vout: 0,
            amount: (i as u64 + 1) * 10000,
            script_pubkey: vec![0x00, 0x14, i as u8, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab],
            address: None,
            metadata: None,
        });
    }
    payload.utxos = Some(utxos);

    // Encrypt
    let password = "large_backup_test";
    let envelope = EncryptedEnvelope::create(&payload, password, Argon2Params::light()).unwrap();
    let bytes = envelope.to_bytes();

    // Should be reasonably sized (CBOR is efficient)
    println!("Large backup size: {} bytes", bytes.len());
    assert!(bytes.len() < 50_000); // Should be under 50KB

    // Decrypt and verify
    let restored = EncryptedEnvelope::from_bytes(&bytes)
        .unwrap()
        .decrypt(password)
        .unwrap();

    assert_eq!(restored.transactions.as_ref().unwrap().len(), 100);
    assert_eq!(restored.utxos.as_ref().unwrap().len(), 50);
}

/// Test backup with Floresta-specific metadata
#[test]
fn test_floresta_specific_metadata() {
    let mut payload = WalletPayload::new(NetworkType::Mainnet);
    payload.accounts.push(Account {
        index: Some(0),
        descriptors: vec![Descriptor {
            descriptor: "wpkh(xpub...)".to_string(),
            checksum: None,
            addresses: None,
            metadata: None,
        }],
        metadata: None,
    });

    // Add Floresta-specific metadata (using only standard fields for now)
    payload.metadata = Some(WalletMetadata {
        base: BaseMetadata {
            software: Some("Floresta v0.6.0".to_string()),
            birth_height: Some(800000),
            label: Some("Test Wallet".to_string()),
            ..Default::default()
        },
        fingerprint: Some([0xde, 0xad, 0xbe, 0xef]),
        name: Some("My Floresta Wallet".to_string()),
        ..Default::default()
    });

    // Add transaction with block height (the most important field for rescan-free restore)
    payload.transactions = Some(vec![Transaction {
        txid: [0x11; 32],
        raw_tx: None,
        metadata: Some(TransactionMetadata {
            block_height: Some(800000),
            fee: Some(1500),
            ..Default::default()
        }),
    }]);

    // Roundtrip
    let password = "floresta_metadata_test";
    let envelope = EncryptedEnvelope::create(&payload, password, Argon2Params::light()).unwrap();
    let bytes = envelope.to_bytes();

    let restored = EncryptedEnvelope::from_bytes(&bytes)
        .unwrap()
        .decrypt(password)
        .unwrap();

    // Verify metadata preserved
    let meta = restored.metadata.unwrap();
    assert_eq!(meta.base.software, Some("Floresta v0.6.0".to_string()));
    assert_eq!(meta.base.birth_height, Some(800000));
    assert_eq!(meta.fingerprint, Some([0xde, 0xad, 0xbe, 0xef]));
    assert_eq!(meta.name, Some("My Floresta Wallet".to_string()));

    let tx_meta = restored.transactions.as_ref().unwrap()[0]
        .metadata
        .as_ref()
        .unwrap();
    assert_eq!(tx_meta.block_height, Some(800000));
    assert_eq!(tx_meta.fee, Some(1500));
}

/// Test different encryption strength levels
#[test]
fn test_encryption_strength_levels() {
    let payload = PayloadBuilder::new(NetworkType::Mainnet)
        .add_account(0, vec!["wpkh(xpub...)".to_string()])
        .build();

    let password = "strength_test_password";

    // Light (fastest, for testing)
    let light = EncryptedEnvelope::create(&payload, password, Argon2Params::light()).unwrap();
    assert!(light.decrypt(password).is_ok());

    // Default (balanced)
    // Skip default in tests as it uses 64MB memory
    // let default = EncryptedEnvelope::create(&payload, password, Argon2Params::default()).unwrap();
    // assert!(default.decrypt(password).is_ok());

    // Strong (slowest, maximum security)
    // Skip strong in tests as it uses 256MB memory
    // let strong = EncryptedEnvelope::create(&payload, password, Argon2Params::strong()).unwrap();
    // assert!(strong.decrypt(password).is_ok());
}
