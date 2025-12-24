//! # CBOR Serialization
//!
//! This module provides CBOR serialization and deserialization for wallet payloads.
//!
//! ## Encoding Requirements
//!
//! All CBOR encoding must follow RFC 8949 §4.2.1 for deterministic/canonical encoding:
//! - No indefinite-length arrays or maps
//! - No floating point numbers
//! - Map keys sorted in ascending order
//! - Minimal integer encoding
//!
//! ## Usage
//!
//! ```rust,ignore
//! use floresta_backup::{WalletPayload, NetworkType};
//! use floresta_backup::cbor;
//!
//! let payload = WalletPayload::new(NetworkType::Mainnet);
//! let bytes = cbor::serialize(&payload)?;
//! let restored: WalletPayload = cbor::deserialize(&bytes)?;
//! ```

use crate::error::{BackupError, Result};
use crate::WalletPayload;

/// Serialize a wallet payload to canonical CBOR bytes.
///
/// The output follows RFC 8949 §4.2.1 deterministic encoding requirements.
pub fn serialize(payload: &WalletPayload) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    ciborium::into_writer(payload, &mut buffer)
        .map_err(|e| BackupError::CborSerialize(e.to_string()))?;
    Ok(buffer)
}

/// Deserialize a wallet payload from CBOR bytes.
///
/// Validates that the payload version is supported.
pub fn deserialize(bytes: &[u8]) -> Result<WalletPayload> {
    let payload: WalletPayload = ciborium::from_reader(bytes)
        .map_err(|e| BackupError::CborDeserialize(e.to_string()))?;

    // Validate version
    if payload.version > WalletPayload::CURRENT_VERSION {
        return Err(BackupError::UnsupportedVersion(
            payload.version,
            WalletPayload::CURRENT_VERSION,
        ));
    }

    Ok(payload)
}

/// Serialize any serializable type to CBOR bytes.
///
/// This is a generic helper for serializing individual components.
pub fn serialize_value<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    ciborium::into_writer(value, &mut buffer)
        .map_err(|e| BackupError::CborSerialize(e.to_string()))?;
    Ok(buffer)
}

/// Deserialize any deserializable type from CBOR bytes.
pub fn deserialize_value<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes).map_err(|e| BackupError::CborDeserialize(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Account, Descriptor, NetworkType};

    #[test]
    fn test_roundtrip_empty_payload() {
        let payload = WalletPayload::new(NetworkType::Testnet);
        let bytes = serialize(&payload).unwrap();
        let restored = deserialize(&bytes).unwrap();

        assert_eq!(restored.version, payload.version);
        assert_eq!(restored.network, payload.network);
    }

    #[test]
    fn test_roundtrip_with_account() {
        let mut payload = WalletPayload::new(NetworkType::Mainnet);
        payload.accounts.push(Account {
            index: Some(0),
            descriptors: vec![Descriptor {
                descriptor: "wpkh([deadbeef/84h/0h/0h]xpub.../0/*)".to_string(),
                checksum: Some("abcd1234".to_string()),
                addresses: None,
                metadata: None,
            }],
            metadata: None,
        });

        let bytes = serialize(&payload).unwrap();
        let restored = deserialize(&bytes).unwrap();

        assert_eq!(restored.accounts.len(), 1);
        assert_eq!(restored.accounts[0].index, Some(0));
        assert_eq!(restored.accounts[0].descriptors.len(), 1);
    }

    #[test]
    fn test_unsupported_version() {
        let mut payload = WalletPayload::new(NetworkType::Mainnet);
        payload.version = 255; // Future unsupported version

        let bytes = serialize(&payload).unwrap();
        let result = deserialize(&bytes);

        assert!(matches!(result, Err(BackupError::UnsupportedVersion(255, 1))));
    }
}
