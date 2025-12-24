//! # Roundtrip Tests
//!
//! Tests that verify serialization → deserialization → comparison works correctly.

use floresta_backup::*;

/// Test descriptor from CLAUDE.md for testnet
const TEST_DESCRIPTOR: &str = "wsh(sortedmulti(1,[54ff5a12/48h/1h/0h/2h]tpubDDw6pwZA3hYxcSN32q7a5ynsKmWr4BbkBNHydHPKkM4BZwUfiK7tQ26h7USm8kA1E2FvCy7f7Er7QXKF8RNptATywydARtzgrxuPDwyYv4x/<0;1>/*,[bcf969c0/48h/1h/0h/2h]tpubDEFdgZdCPgQBTNtGj4h6AehK79Jm4LH54JrYBJjAtHMLEAth7LuY87awx9ZMiCURFzFWhxToRJK6xp39aqeJWrG5nuW3eBnXeMJcvDeDxfp/<0;1>/*))#fuw35j0q";

#[test]
fn test_cbor_roundtrip_empty_payload() {
    let payload = WalletPayload::new(NetworkType::Mainnet);
    let bytes = serialize(&payload).unwrap();
    let restored: WalletPayload = deserialize(&bytes).unwrap();

    assert_eq!(restored.version, payload.version);
    assert_eq!(restored.network, payload.network);
    assert!(restored.accounts.is_empty());
}

#[test]
fn test_cbor_roundtrip_with_descriptor() {
    let mut payload = WalletPayload::new(NetworkType::Testnet);
    payload.accounts.push(Account {
        index: Some(0),
        descriptors: vec![Descriptor {
            descriptor: TEST_DESCRIPTOR.to_string(),
            checksum: Some("fuw35j0q".to_string()),
            addresses: None,
            metadata: None,
        }],
        metadata: None,
    });

    let bytes = serialize(&payload).unwrap();
    let restored = deserialize(&bytes).unwrap();

    assert_eq!(restored.accounts.len(), 1);
    assert_eq!(restored.accounts[0].descriptors[0].descriptor, TEST_DESCRIPTOR);
    assert_eq!(
        restored.accounts[0].descriptors[0].checksum,
        Some("fuw35j0q".to_string())
    );
}

#[test]
fn test_cbor_roundtrip_with_transactions() {
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
            txid: [0xab; 32],
            raw_tx: Some(vec![0x01; 200]), // Dummy tx bytes
            metadata: Some(TransactionMetadata {
                block_height: Some(800000),
                fee: Some(1000),
                ..Default::default()
            }),
        },
        Transaction {
            txid: [0xcd; 32],
            raw_tx: None,
            metadata: Some(TransactionMetadata {
                block_height: Some(800001),
                ..Default::default()
            }),
        },
    ]);

    let bytes = serialize(&payload).unwrap();
    let restored = deserialize(&bytes).unwrap();

    let txs = restored.transactions.unwrap();
    assert_eq!(txs.len(), 2);
    assert_eq!(txs[0].txid, [0xab; 32]);
    assert!(txs[0].raw_tx.is_some());
    assert_eq!(txs[0].metadata.as_ref().unwrap().block_height, Some(800000));
    assert_eq!(txs[1].txid, [0xcd; 32]);
    assert!(txs[1].raw_tx.is_none());
}

#[test]
fn test_cbor_roundtrip_with_utxos() {
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
    payload.utxos = Some(vec![Utxo {
        txid: [0x11; 32],
        vout: 0,
        amount: 100_000_000, // 1 BTC
        script_pubkey: vec![0x00, 0x14, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12], // P2WPKH script
        address: Some("bc1qtest...".to_string()),
        metadata: Some(UtxoMetadata {
            spendable: Some(true),
            frozen: Some(false),
            ..Default::default()
        }),
    }]);

    let bytes = serialize(&payload).unwrap();
    let restored = deserialize(&bytes).unwrap();

    let utxos = restored.utxos.unwrap();
    assert_eq!(utxos.len(), 1);
    assert_eq!(utxos[0].amount, 100_000_000);
    assert_eq!(utxos[0].vout, 0);
    assert!(utxos[0].metadata.as_ref().unwrap().spendable.unwrap());
}

#[test]
fn test_cbor_roundtrip_with_metadata() {
    let mut payload = WalletPayload::new(NetworkType::Mainnet);
    payload.accounts.push(Account {
        index: Some(0),
        descriptors: vec![Descriptor {
            descriptor: "wpkh([deadbeef/84h/0h/0h]xpub.../0/*)".to_string(),
            checksum: None,
            addresses: None,
            metadata: Some(DescriptorMetadata {
                role: Some(RoleType::External),
                next_index: Some(10),
                gap_limit: Some(20),
                watch_only: Some(true),
                ..Default::default()
            }),
        }],
        metadata: Some(AccountMetadata {
            gap_limit: Some(20),
            next_external_index: Some(10),
            next_internal_index: Some(5),
            ..Default::default()
        }),
    });
    payload.metadata = Some(WalletMetadata {
        base: BaseMetadata {
            label: Some("My Wallet".to_string()),
            software: Some("Floresta".to_string()),
            ..Default::default()
        },
        fingerprint: Some([0xde, 0xad, 0xbe, 0xef]),
        name: Some("Test Wallet".to_string()),
        ..Default::default()
    });

    let bytes = serialize(&payload).unwrap();
    let restored = deserialize(&bytes).unwrap();

    let meta = restored.metadata.unwrap();
    assert_eq!(meta.base.label, Some("My Wallet".to_string()));
    assert_eq!(meta.fingerprint, Some([0xde, 0xad, 0xbe, 0xef]));

    let acc_meta = restored.accounts[0].metadata.as_ref().unwrap();
    assert_eq!(acc_meta.gap_limit, Some(20));
}

#[test]
fn test_encrypted_envelope_roundtrip() {
    let mut payload = WalletPayload::new(NetworkType::Testnet);
    payload.accounts.push(Account {
        index: Some(0),
        descriptors: vec![Descriptor {
            descriptor: TEST_DESCRIPTOR.to_string(),
            checksum: Some("fuw35j0q".to_string()),
            addresses: None,
            metadata: None,
        }],
        metadata: None,
    });

    let password = "super_secret_password_123!";

    // Create encrypted envelope
    let envelope = EncryptedEnvelope::create(&payload, password, Argon2Params::light()).unwrap();

    // Serialize to bytes
    let bytes = envelope.to_bytes();

    // Verify magic bytes
    assert_eq!(&bytes[0..4], b"BEWP");

    // Parse back
    let restored_envelope = EncryptedEnvelope::from_bytes(&bytes).unwrap();

    // Decrypt
    let restored_payload = restored_envelope.decrypt(password).unwrap();

    assert_eq!(restored_payload.version, payload.version);
    assert_eq!(restored_payload.network, payload.network);
    assert_eq!(restored_payload.accounts.len(), 1);
    assert_eq!(
        restored_payload.accounts[0].descriptors[0].descriptor,
        TEST_DESCRIPTOR
    );
}

#[test]
fn test_full_workflow() {
    // Build a complete payload using PayloadBuilder
    let payload = PayloadBuilder::new(NetworkType::Testnet)
        .genesis_hash([0x00; 32])
        .add_account(0, vec![TEST_DESCRIPTOR.to_string()])
        .add_transaction([0xaa; 32], None, Some(2500000))
        .add_utxo([0xbb; 32], 1, 50000, vec![0x00, 0x14, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc])
        .metadata(WalletMetadata {
            base: BaseMetadata {
                software: Some("Floresta".to_string()),
                ..Default::default()
            },
            ..Default::default()
        })
        .build();

    // Validate
    validate_payload(&payload).unwrap();

    // Encrypt
    let password = "test123";
    let envelope = EncryptedEnvelope::create(&payload, password, Argon2Params::light()).unwrap();
    let bytes = envelope.to_bytes();

    // Decrypt and import
    let restored_envelope = EncryptedEnvelope::from_bytes(&bytes).unwrap();
    let restored_payload = restored_envelope.decrypt(password).unwrap();

    // Use importer
    let importer = WalletImporter::new(restored_payload);
    let result = importer.dry_run().unwrap();

    assert_eq!(result.descriptors_imported, 1);
    assert_eq!(result.transactions_imported, 1);
    assert_eq!(result.utxos_imported, 1);
}
