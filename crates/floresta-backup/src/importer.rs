//! # Wallet Data Importer
//!
//! This module imports data from a backup into the Floresta wallet.
//!
//! ## Responsibilities
//!
//! - Restore descriptors to the watch-only wallet
//! - Restore transaction history with confirmation data
//! - Enable rescan-free restoration using stored block heights
//! - Validate network compatibility before import
//!
//! ## Rescan-Free Restoration
//!
//! The key feature of this backup format is the ability to restore
//! without rescanning the blockchain. This is achieved by storing:
//!
//! 1. Block height for each confirmed transaction
//! 2. UTXO set snapshot (advisory)
//! 3. Derivation indices (to avoid recomputing addresses)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use floresta_backup::importer::WalletImporter;
//! use floresta_backup::envelope::EncryptedEnvelope;
//!
//! let envelope = EncryptedEnvelope::from_bytes(&backup_data)?;
//! let payload = envelope.decrypt("password")?;
//!
//! let importer = WalletImporter::new(payload);
//! importer.import_to_wallet(&mut address_cache)?;
//! ```

use crate::error::{BackupError, Result};
use crate::validation::validate_payload;
use crate::{NetworkType, WalletPayload};

/// Options for wallet import.
#[derive(Debug, Clone)]
pub struct ImportOptions {
    /// Skip network validation (dangerous!)
    pub skip_network_check: bool,
    /// Import transactions even if heights are missing
    pub allow_incomplete_transactions: bool,
    /// Verify UTXO set against current blockchain
    pub verify_utxos: bool,
    /// Expected network (for validation)
    pub expected_network: Option<NetworkType>,
}

impl Default for ImportOptions {
    fn default() -> Self {
        Self {
            skip_network_check: false,
            allow_incomplete_transactions: true,
            verify_utxos: false,
            expected_network: None,
        }
    }
}

/// Result of a wallet import operation.
#[derive(Debug)]
pub struct ImportResult {
    /// Number of descriptors imported
    pub descriptors_imported: usize,
    /// Number of transactions imported
    pub transactions_imported: usize,
    /// Number of UTXOs imported
    pub utxos_imported: usize,
    /// Warnings encountered during import
    pub warnings: Vec<String>,
}

/// Importer for wallet backups.
///
/// This struct will be expanded to integrate with floresta-watch-only
/// in Phase 4 of the implementation.
pub struct WalletImporter {
    payload: WalletPayload,
    options: ImportOptions,
}

impl WalletImporter {
    /// Create a new wallet importer.
    pub fn new(payload: WalletPayload) -> Self {
        Self {
            payload,
            options: ImportOptions::default(),
        }
    }

    /// Set import options.
    pub fn with_options(mut self, options: ImportOptions) -> Self {
        self.options = options;
        self
    }

    /// Validate the payload before import.
    pub fn validate(&self) -> Result<()> {
        // Run standard validation
        validate_payload(&self.payload)?;

        // Check network if expected
        if let Some(expected) = self.options.expected_network {
            if !self.options.skip_network_check && self.payload.network != expected {
                return Err(BackupError::NetworkMismatch(self.payload.network, expected));
            }
        }

        Ok(())
    }

    /// Get all descriptors from the payload.
    ///
    /// Returns a flat list of all descriptors across all accounts.
    pub fn get_descriptors(&self) -> Vec<&str> {
        self.payload
            .accounts
            .iter()
            .flat_map(|acc| acc.descriptors.iter().map(|d| d.descriptor.as_str()))
            .collect()
    }

    /// Get transaction data with block heights for rescan-free import.
    ///
    /// Returns tuples of (txid, block_height) for confirmed transactions.
    pub fn get_confirmed_transactions(&self) -> Vec<([u8; 32], u32)> {
        self.payload
            .transactions
            .as_ref()
            .map(|txs| {
                txs.iter()
                    .filter_map(|tx| {
                        tx.metadata
                            .as_ref()
                            .and_then(|m| m.block_height)
                            .map(|h| (tx.txid, h))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get raw transaction bytes for transactions that include them.
    pub fn get_raw_transactions(&self) -> Vec<([u8; 32], &[u8])> {
        self.payload
            .transactions
            .as_ref()
            .map(|txs| {
                txs.iter()
                    .filter_map(|tx| tx.raw_tx.as_ref().map(|raw| (tx.txid, raw.as_slice())))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get UTXO set snapshot.
    pub fn get_utxos(&self) -> Vec<&crate::Utxo> {
        self.payload
            .utxos
            .as_ref()
            .map(|utxos| utxos.iter().collect())
            .unwrap_or_default()
    }

    /// Get the network type from the payload.
    pub fn network(&self) -> NetworkType {
        self.payload.network
    }

    /// Get wallet metadata if present.
    pub fn metadata(&self) -> Option<&crate::WalletMetadata> {
        self.payload.metadata.as_ref()
    }

    /// Consume the importer and return the payload.
    pub fn into_payload(self) -> WalletPayload {
        self.payload
    }

    /// Perform a mock import and return statistics.
    ///
    /// This is a placeholder that will be replaced with actual wallet
    /// integration in Phase 4.
    pub fn dry_run(&self) -> Result<ImportResult> {
        self.validate()?;

        let mut result = ImportResult {
            descriptors_imported: 0,
            transactions_imported: 0,
            utxos_imported: 0,
            warnings: Vec::new(),
        };

        // Count descriptors
        for account in &self.payload.accounts {
            result.descriptors_imported += account.descriptors.len();
        }

        // Count transactions
        if let Some(txs) = &self.payload.transactions {
            for tx in txs {
                if tx.metadata.as_ref().and_then(|m| m.block_height).is_some() {
                    result.transactions_imported += 1;
                } else {
                    result.warnings.push(format!(
                        "Transaction {:?} has no block height",
                        hex::encode(&tx.txid[..8])
                    ));
                }
            }
        }

        // Count UTXOs
        if let Some(utxos) = &self.payload.utxos {
            result.utxos_imported = utxos.len();
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Account, Descriptor, Transaction, TransactionMetadata};

    fn create_test_payload() -> WalletPayload {
        let mut payload = WalletPayload::new(NetworkType::Testnet);
        payload.accounts.push(Account {
            index: Some(0),
            descriptors: vec![
                Descriptor {
                    descriptor: "wpkh([deadbeef/84h/0h/0h]xpub.../0/*)".to_string(),
                    checksum: None,
                    addresses: None,
                    metadata: None,
                },
                Descriptor {
                    descriptor: "wpkh([deadbeef/84h/0h/0h]xpub.../1/*)".to_string(),
                    checksum: None,
                    addresses: None,
                    metadata: None,
                },
            ],
            metadata: None,
        });
        payload.transactions = Some(vec![
            Transaction {
                txid: [1u8; 32],
                raw_tx: None,
                metadata: Some(TransactionMetadata {
                    block_height: Some(800000),
                    ..Default::default()
                }),
            },
            Transaction {
                txid: [2u8; 32],
                raw_tx: Some(vec![0u8; 100]),
                metadata: None,
            },
        ]);
        payload
    }

    #[test]
    fn test_get_descriptors() {
        let payload = create_test_payload();
        let importer = WalletImporter::new(payload);
        let descriptors = importer.get_descriptors();

        assert_eq!(descriptors.len(), 2);
        assert!(descriptors[0].contains("wpkh"));
    }

    #[test]
    fn test_get_confirmed_transactions() {
        let payload = create_test_payload();
        let importer = WalletImporter::new(payload);
        let confirmed = importer.get_confirmed_transactions();

        assert_eq!(confirmed.len(), 1);
        assert_eq!(confirmed[0].1, 800000);
    }

    #[test]
    fn test_get_raw_transactions() {
        let payload = create_test_payload();
        let importer = WalletImporter::new(payload);
        let raw_txs = importer.get_raw_transactions();

        assert_eq!(raw_txs.len(), 1);
        assert_eq!(raw_txs[0].1.len(), 100);
    }

    #[test]
    fn test_network_mismatch() {
        let payload = create_test_payload(); // Testnet
        let importer = WalletImporter::new(payload).with_options(ImportOptions {
            expected_network: Some(NetworkType::Mainnet),
            ..Default::default()
        });

        let result = importer.validate();
        assert!(matches!(result, Err(BackupError::NetworkMismatch(_, _))));
    }

    #[test]
    fn test_dry_run() {
        let payload = create_test_payload();
        let importer = WalletImporter::new(payload);
        let result = importer.dry_run().unwrap();

        assert_eq!(result.descriptors_imported, 2);
        assert_eq!(result.transactions_imported, 1);
        assert_eq!(result.warnings.len(), 1); // One tx without height
    }
}
