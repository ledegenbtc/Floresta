//! # Test Vectors
//!
//! Test vectors for validating compliance with the BIP specification.
//! These will be updated as the BIP is finalized with official test vectors.

use floresta_backup::*;

/// Minimum valid payload: version 1, mainnet, one account with one descriptor
#[test]
fn test_minimal_valid_payload() {
    let mut payload = WalletPayload::new(NetworkType::Mainnet);
    payload.accounts.push(Account {
        index: None,
        descriptors: vec![Descriptor {
            descriptor: "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)".to_string(),
            checksum: None,
            addresses: None,
            metadata: None,
        }],
        metadata: None,
    });

    // Should validate successfully
    validate_payload(&payload).unwrap();

    // Should serialize and deserialize
    let bytes = serialize(&payload).unwrap();
    let restored = deserialize(&bytes).unwrap();

    assert_eq!(restored.version, 1);
    assert_eq!(restored.network, NetworkType::Mainnet);
}

/// Test that network type values match BIP spec
#[test]
fn test_network_type_values() {
    assert_eq!(NetworkType::Mainnet as u8, 0);
    assert_eq!(NetworkType::Testnet as u8, 1);
    assert_eq!(NetworkType::Signet as u8, 2);
    assert_eq!(NetworkType::Regtest as u8, 3);
}

/// Test CBOR key numbering
#[test]
fn test_cbor_keys() {
    // Create a payload and serialize
    let mut payload = WalletPayload::new(NetworkType::Testnet);
    payload.accounts.push(Account {
        index: Some(0),
        descriptors: vec![Descriptor {
            descriptor: "wpkh(tpubD...)".to_string(),
            checksum: None,
            addresses: None,
            metadata: None,
        }],
        metadata: None,
    });

    let bytes = serialize(&payload).unwrap();

    // The CBOR should contain the correct key numbers
    // Key 0 = version, Key 1 = network, Key 10 = accounts
    // This is a basic check that serialization is working
    assert!(!bytes.is_empty());

    // Deserialize and verify
    let restored = deserialize(&bytes).unwrap();
    assert_eq!(restored.version, 1);
    assert_eq!(restored.network, NetworkType::Testnet);
}

/// Test descriptor types that should be valid
#[test]
fn test_valid_descriptor_types() {
    let valid_descriptors = [
        "pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
        "pkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
        "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
        "sh(wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))",
        "wsh(pk(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5))",
        "tr(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
        "multi(2,key1,key2)",
        "sortedmulti(2,key1,key2)",
        "combo(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)",
        "addr(bc1qtest)",
        "raw(76a914...88ac)",
    ];

    for desc in valid_descriptors {
        let mut payload = WalletPayload::new(NetworkType::Mainnet);
        payload.accounts.push(Account {
            index: None,
            descriptors: vec![Descriptor {
                descriptor: desc.to_string(),
                checksum: None,
                addresses: None,
                metadata: None,
            }],
            metadata: None,
        });

        let result = validate_payload(&payload);
        assert!(result.is_ok(), "Descriptor should be valid: {}", desc);
    }
}

/// Test that invalid descriptor prefixes are rejected
#[test]
fn test_invalid_descriptor_prefix() {
    let invalid_descriptors = [
        "invalid(key)",
        "unknown(key)",
        "xpub...",
        "key",
    ];

    for desc in invalid_descriptors {
        let mut payload = WalletPayload::new(NetworkType::Mainnet);
        payload.accounts.push(Account {
            index: None,
            descriptors: vec![Descriptor {
                descriptor: desc.to_string(),
                checksum: None,
                addresses: None,
                metadata: None,
            }],
            metadata: None,
        });

        let result = validate_payload(&payload);
        assert!(result.is_err(), "Descriptor should be invalid: {}", desc);
    }
}

/// Test version validation
#[test]
fn test_version_validation() {
    // Version 0 is invalid
    let mut payload = WalletPayload::new(NetworkType::Mainnet);
    payload.version = 0;
    payload.accounts.push(Account {
        index: None,
        descriptors: vec![Descriptor {
            descriptor: "pkh(key)".to_string(),
            checksum: None,
            addresses: None,
            metadata: None,
        }],
        metadata: None,
    });
    assert!(matches!(
        validate_payload(&payload),
        Err(BackupError::UnsupportedVersion(0, 1))
    ));

    // Version 1 is valid
    payload.version = 1;
    assert!(validate_payload(&payload).is_ok());

    // Future versions are invalid for current implementation
    payload.version = 2;
    assert!(matches!(
        validate_payload(&payload),
        Err(BackupError::UnsupportedVersion(2, 1))
    ));
}

/// Test empty payload validation
#[test]
fn test_empty_accounts_validation() {
    let payload = WalletPayload::new(NetworkType::Mainnet);
    assert!(matches!(
        validate_payload(&payload),
        Err(BackupError::EmptyAccounts)
    ));
}

/// Test strict validation for non-mainnet
#[test]
fn test_strict_genesis_hash_requirement() {
    let mut payload = WalletPayload::new(NetworkType::Testnet);
    payload.accounts.push(Account {
        index: None,
        descriptors: vec![Descriptor {
            descriptor: "pkh(key)".to_string(),
            checksum: None,
            addresses: None,
            metadata: None,
        }],
        metadata: None,
    });

    // Normal validation should pass
    assert!(validate_payload(&payload).is_ok());

    // Strict validation should fail without genesis hash
    assert!(validate_payload_strict(&payload).is_err());

    // With genesis hash, strict validation should pass
    payload.genesis_hash = Some([0x00; 32]);
    assert!(validate_payload_strict(&payload).is_ok());
}

/// Test envelope magic bytes
#[test]
fn test_envelope_magic() {
    let mut payload = WalletPayload::new(NetworkType::Mainnet);
    payload.accounts.push(Account {
        index: None,
        descriptors: vec![Descriptor {
            descriptor: "pkh(key)".to_string(),
            checksum: None,
            addresses: None,
            metadata: None,
        }],
        metadata: None,
    });

    let envelope = EncryptedEnvelope::create(&payload, "test", Argon2Params::light()).unwrap();
    let bytes = envelope.to_bytes();

    // Magic should be "BEWP"
    assert_eq!(&bytes[0..4], b"BEWP");

    // Version should be 1
    assert_eq!(bytes[4], 1);
}

/// Test that different passwords produce different ciphertexts
#[test]
fn test_password_independence() {
    let mut payload = WalletPayload::new(NetworkType::Mainnet);
    payload.accounts.push(Account {
        index: None,
        descriptors: vec![Descriptor {
            descriptor: "pkh(key)".to_string(),
            checksum: None,
            addresses: None,
            metadata: None,
        }],
        metadata: None,
    });

    let env1 = EncryptedEnvelope::create(&payload, "password1", Argon2Params::light()).unwrap();
    let env2 = EncryptedEnvelope::create(&payload, "password2", Argon2Params::light()).unwrap();

    // Different passwords should produce different ciphertexts
    assert_ne!(env1.encrypted.ciphertext, env2.encrypted.ciphertext);

    // Each should decrypt with its own password
    let bytes1 = env1.to_bytes();
    let bytes2 = env2.to_bytes();

    let restored1 = EncryptedEnvelope::from_bytes(&bytes1).unwrap();
    let restored2 = EncryptedEnvelope::from_bytes(&bytes2).unwrap();

    assert!(restored1.decrypt("password1").is_ok());
    assert!(restored1.decrypt("password2").is_err());
    assert!(restored2.decrypt("password2").is_ok());
    assert!(restored2.decrypt("password1").is_err());
}
