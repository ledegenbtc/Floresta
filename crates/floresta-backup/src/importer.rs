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
//! let result = importer.import_to_wallet(&wallet)?;
//! ```

use bitcoin::consensus::deserialize as consensus_deserialize;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use floresta_common::get_spk_hash;
use floresta_watch_only::merkle::MerkleProof;
use floresta_watch_only::AddressCacheDatabase;

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
    /// This allows you to preview what will be imported without
    /// actually modifying the wallet.
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

    /// Import the backup data into a wallet.
    ///
    /// This method restores descriptors and transactions to the wallet,
    /// enabling rescan-free restoration by using stored block heights.
    ///
    /// # Arguments
    ///
    /// * `wallet` - Reference to the AddressCache to import data into
    ///
    /// # Returns
    ///
    /// An `ImportResult` containing statistics about what was imported.
    pub fn import_to_wallet<D>(
        &self,
        wallet: &floresta_watch_only::AddressCache<D>,
    ) -> Result<ImportResult>
    where
        D: AddressCacheDatabase,
    {
        // Validate payload first
        self.validate()?;

        let mut result = ImportResult {
            descriptors_imported: 0,
            transactions_imported: 0,
            utxos_imported: 0,
            warnings: Vec::new(),
        };

        // Import descriptors
        for account in &self.payload.accounts {
            for descriptor in &account.descriptors {
                // Check if descriptor is already cached
                match wallet.is_cached(&descriptor.descriptor) {
                    Ok(true) => {
                        result.warnings.push(format!(
                            "Descriptor already cached: {}...",
                            &descriptor.descriptor[..descriptor.descriptor.len().min(40)]
                        ));
                    }
                    Ok(false) => {
                        wallet
                            .push_descriptor(&descriptor.descriptor)
                            .map_err(|e| {
                                BackupError::WalletImport(format!(
                                    "Failed to push descriptor: {e}"
                                ))
                            })?;
                        result.descriptors_imported += 1;
                    }
                    Err(e) => {
                        result.warnings.push(format!(
                            "Failed to check if descriptor is cached: {e}"
                        ));
                    }
                }
            }
        }

        // Derive addresses after importing descriptors
        if result.descriptors_imported > 0 {
            wallet.derive_addresses().map_err(|e| {
                BackupError::WalletImport(format!("Failed to derive addresses: {e}"))
            })?;
        }

        // Import transactions with their confirmation data
        if let Some(txs) = &self.payload.transactions {
            for tx in txs {
                match self.import_transaction(wallet, tx) {
                    Ok(()) => {
                        result.transactions_imported += 1;
                    }
                    Err(e) => {
                        if self.options.allow_incomplete_transactions {
                            result.warnings.push(format!(
                                "Failed to import transaction {}: {}",
                                hex::encode(&tx.txid[..8]),
                                e
                            ));
                        } else {
                            return Err(e);
                        }
                    }
                }
            }
        }

        // Update cache height based on metadata
        if let Some(metadata) = &self.payload.metadata {
            if let Some(birth_height) = metadata.base.birth_height {
                wallet.bump_height(birth_height);
            }
        }

        Ok(result)
    }

    /// Import a single transaction into the wallet.
    fn import_transaction<D>(
        &self,
        wallet: &floresta_watch_only::AddressCache<D>,
        tx: &crate::Transaction,
    ) -> Result<()>
    where
        D: AddressCacheDatabase,
    {
        // We need the raw transaction to import
        let raw_tx = tx.raw_tx.as_ref().ok_or_else(|| {
            BackupError::WalletImport("Transaction missing raw_tx data".to_string())
        })?;

        // Deserialize the transaction
        let bitcoin_tx: bitcoin::Transaction = consensus_deserialize(raw_tx)
            .map_err(|e| BackupError::WalletImport(format!("Failed to deserialize tx: {e}")))?;

        // Get block height (0 for unconfirmed)
        let height = tx
            .metadata
            .as_ref()
            .and_then(|m| m.block_height)
            .unwrap_or(0);

        // Get position in block (0 if not specified)
        let position = tx
            .metadata
            .as_ref()
            .and_then(|m| m.position_in_block)
            .unwrap_or(0);

        // Deserialize merkle proof if present
        let merkle_proof = if let Some(proof_bytes) = tx
            .metadata
            .as_ref()
            .and_then(|m| m.merkle_proof.as_ref())
        {
            consensus_deserialize::<MerkleProof>(proof_bytes).unwrap_or_default()
        } else {
            MerkleProof::default()
        };

        // Find outputs that belong to us (we need to cache for each output)
        for (vout, output) in bitcoin_tx.output.iter().enumerate() {
            let script_hash = get_spk_hash(&output.script_pubkey);

            // Check if this address is being tracked
            if wallet.is_address_cached(&script_hash) {
                wallet.cache_transaction(
                    &bitcoin_tx,
                    height,
                    output.value.to_sat(),
                    merkle_proof.clone(),
                    position,
                    vout,
                    false, // is_spend = false for received outputs
                    script_hash,
                );
            }
        }

        // Also check inputs for spent outputs
        for (vin, input) in bitcoin_tx.input.iter().enumerate() {
            // Get the previous transaction output if available in the wallet
            if let Some(prev_txout) = wallet.get_utxo(&input.previous_output) {
                let script_hash = get_spk_hash(&prev_txout.script_pubkey);

                if wallet.is_address_cached(&script_hash) {
                    wallet.cache_transaction(
                        &bitcoin_tx,
                        height,
                        prev_txout.value.to_sat(),
                        merkle_proof.clone(),
                        position,
                        vin,
                        true, // is_spend = true for spent inputs
                        script_hash,
                    );
                }
            }
        }

        Ok(())
    }

    /// Get derivation index from account metadata if present.
    pub fn get_derivation_index(&self) -> Option<u32> {
        self.payload
            .accounts
            .first()
            .and_then(|acc| acc.metadata.as_ref())
            .and_then(|meta| meta.next_external_index)
    }

    /// Get all raw transactions from the payload.
    ///
    /// Returns tuples of (txid_bytes, bitcoin::Transaction) for transactions
    /// that include raw bytes.
    pub fn get_bitcoin_transactions(&self) -> Result<Vec<(Txid, bitcoin::Transaction)>> {
        let mut transactions = Vec::new();

        if let Some(txs) = &self.payload.transactions {
            for tx in txs {
                if let Some(raw_tx) = &tx.raw_tx {
                    let bitcoin_tx: bitcoin::Transaction = consensus_deserialize(raw_tx)
                        .map_err(|e| {
                            BackupError::WalletImport(format!("Failed to deserialize tx: {e}"))
                        })?;

                    let txid = Txid::from_byte_array(tx.txid);
                    transactions.push((txid, bitcoin_tx));
                }
            }
        }

        Ok(transactions)
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
