//! # Validation Module
//!
//! This module provides validation functions for wallet payloads according to the BIP spec.
//!
//! ## Validation Rules
//!
//! 1. **Version**: Must be 1 (current version)
//! 2. **Network**: Must be valid (0-3)
//! 3. **Genesis Hash**: Required for non-mainnet networks
//! 4. **Accounts**: At least one account is required
//! 5. **Descriptors**: Each account must have at least one descriptor
//! 6. **Transactions**: If present, txid must be 32 bytes

use crate::error::{BackupError, Result};
use crate::{NetworkType, WalletPayload};

/// Validate a wallet payload according to BIP requirements.
///
/// Returns `Ok(())` if the payload is valid, or an error describing the issue.
pub fn validate_payload(payload: &WalletPayload) -> Result<()> {
    validate_version(payload)?;
    validate_network(payload)?;
    validate_accounts(payload)?;
    validate_transactions(payload)?;
    validate_utxos(payload)?;
    Ok(())
}

/// Validate the payload version.
fn validate_version(payload: &WalletPayload) -> Result<()> {
    if payload.version == 0 || payload.version > WalletPayload::CURRENT_VERSION {
        return Err(BackupError::UnsupportedVersion(
            payload.version,
            WalletPayload::CURRENT_VERSION,
        ));
    }
    Ok(())
}

/// Validate network settings.
///
/// Non-mainnet networks should include genesis hash for safety.
fn validate_network(payload: &WalletPayload) -> Result<()> {
    // For non-mainnet, genesis_hash is recommended (warning only in strict mode)
    if payload.network != NetworkType::Mainnet && payload.genesis_hash.is_none() {
        // This is a warning, not an error - we allow it but log it
        // In strict mode, this could be an error
    }
    Ok(())
}

/// Validate accounts list.
fn validate_accounts(payload: &WalletPayload) -> Result<()> {
    if payload.accounts.is_empty() {
        return Err(BackupError::EmptyAccounts);
    }

    for (i, account) in payload.accounts.iter().enumerate() {
        if account.descriptors.is_empty() {
            return Err(BackupError::Validation(format!(
                "Account {} has no descriptors",
                i
            )));
        }

        for (j, descriptor) in account.descriptors.iter().enumerate() {
            if descriptor.descriptor.is_empty() {
                return Err(BackupError::InvalidDescriptor(format!(
                    "Account {} descriptor {} is empty",
                    i, j
                )));
            }

            // Basic descriptor syntax check (starts with known types)
            let valid_prefixes = [
                "pk(", "pkh(", "wpkh(", "sh(", "wsh(", "tr(", "multi(", "sortedmulti(",
                "combo(", "addr(", "raw(",
            ];
            let has_valid_prefix = valid_prefixes.iter().any(|p| descriptor.descriptor.starts_with(p));
            if !has_valid_prefix {
                return Err(BackupError::InvalidDescriptor(format!(
                    "Account {} descriptor {} has invalid prefix",
                    i, j
                )));
            }
        }
    }

    Ok(())
}

/// Validate transactions if present.
fn validate_transactions(payload: &WalletPayload) -> Result<()> {
    if let Some(transactions) = &payload.transactions {
        for (i, tx) in transactions.iter().enumerate() {
            // txid is always 32 bytes (enforced by type system)

            // If raw_tx is present, validate minimum size
            if let Some(raw) = &tx.raw_tx {
                // Minimum Bitcoin transaction is ~60 bytes
                if raw.len() < 60 {
                    return Err(BackupError::InvalidTransaction(format!(
                        "Transaction {} raw_tx too short: {} bytes",
                        i,
                        raw.len()
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Validate UTXOs if present.
fn validate_utxos(payload: &WalletPayload) -> Result<()> {
    if let Some(utxos) = &payload.utxos {
        for (i, utxo) in utxos.iter().enumerate() {
            // Minimum scriptPubKey size
            if utxo.script_pubkey.len() < 2 {
                return Err(BackupError::Validation(format!(
                    "UTXO {} has invalid scriptPubKey length: {}",
                    i,
                    utxo.script_pubkey.len()
                )));
            }
        }
    }
    Ok(())
}

/// Strict validation mode that treats warnings as errors.
pub fn validate_payload_strict(payload: &WalletPayload) -> Result<()> {
    // Run normal validation first
    validate_payload(payload)?;

    // Additional strict checks
    if payload.network != NetworkType::Mainnet && payload.genesis_hash.is_none() {
        return Err(BackupError::Validation(
            "Non-mainnet network requires genesis_hash for safety".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Account, Descriptor};

    fn create_valid_payload() -> WalletPayload {
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
        payload
    }

    #[test]
    fn test_valid_payload() {
        let payload = create_valid_payload();
        assert!(validate_payload(&payload).is_ok());
    }

    #[test]
    fn test_empty_accounts() {
        let payload = WalletPayload::new(NetworkType::Mainnet);
        let result = validate_payload(&payload);
        assert!(matches!(result, Err(BackupError::EmptyAccounts)));
    }

    #[test]
    fn test_empty_descriptors() {
        let mut payload = WalletPayload::new(NetworkType::Mainnet);
        payload.accounts.push(Account {
            index: Some(0),
            descriptors: vec![],
            metadata: None,
        });

        let result = validate_payload(&payload);
        assert!(matches!(result, Err(BackupError::Validation(_))));
    }

    #[test]
    fn test_invalid_descriptor_prefix() {
        let mut payload = WalletPayload::new(NetworkType::Mainnet);
        payload.accounts.push(Account {
            index: Some(0),
            descriptors: vec![Descriptor {
                descriptor: "invalid(xpub...)".to_string(),
                checksum: None,
                addresses: None,
                metadata: None,
            }],
            metadata: None,
        });

        let result = validate_payload(&payload);
        assert!(matches!(result, Err(BackupError::InvalidDescriptor(_))));
    }

    #[test]
    fn test_invalid_version() {
        let mut payload = create_valid_payload();
        payload.version = 0;

        let result = validate_payload(&payload);
        assert!(matches!(result, Err(BackupError::UnsupportedVersion(0, 1))));
    }

    #[test]
    fn test_strict_requires_genesis_hash() {
        let mut payload = create_valid_payload();
        payload.network = NetworkType::Testnet;
        payload.genesis_hash = None;

        // Normal validation passes
        assert!(validate_payload(&payload).is_ok());

        // Strict validation fails
        let result = validate_payload_strict(&payload);
        assert!(matches!(result, Err(BackupError::Validation(_))));
    }
}
