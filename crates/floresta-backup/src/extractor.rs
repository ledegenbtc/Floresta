//! # Wallet Data Extractor
//!
//! This module extracts data from the Floresta wallet for backup purposes.
//!
//! ## Responsibilities
//!
//! - Extract descriptors from the watch-only wallet
//! - Extract transaction history with confirmation heights
//! - Extract UTXO set with metadata
//! - Gather wallet metadata (gap limits, derivation indices, etc.)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use floresta_backup::extractor::WalletExtractor;
//! use floresta_watch_only::AddressCache;
//!
//! let extractor = WalletExtractor::new(NetworkType::Mainnet);
//! let payload = extractor.extract_from_wallet(&address_cache)?;
//! ```

use bitcoin::consensus::serialize as consensus_serialize;
use bitcoin::hashes::Hash as _;
use floresta_common::get_spk_hash;
use floresta_watch_only::AddressCacheDatabase;

use crate::error::{BackupError, Result};
use crate::{
    Account, AccountMetadata, BaseMetadata, Descriptor, DescriptorMetadata, NetworkType,
    Transaction, TransactionMetadata, Utxo, UtxoMetadata, WalletMetadata, WalletPayload,
};

/// Options for wallet extraction.
#[derive(Debug, Clone, Default)]
pub struct ExtractOptions {
    /// Include transaction history in the backup
    pub include_transactions: bool,
    /// Include raw transaction bytes (increases backup size)
    pub include_raw_transactions: bool,
    /// Include UTXO set snapshot
    pub include_utxos: bool,
    /// Include derived addresses
    pub include_addresses: bool,
    /// Maximum number of transactions to include (None = all)
    pub max_transactions: Option<usize>,
}

impl ExtractOptions {
    /// Create options for a minimal backup (descriptors only)
    pub fn minimal() -> Self {
        Self::default()
    }

    /// Create options for a full backup with everything
    pub fn full() -> Self {
        Self {
            include_transactions: true,
            include_raw_transactions: true,
            include_utxos: true,
            include_addresses: true,
            max_transactions: None,
        }
    }

    /// Create options for a compact backup (transactions without raw bytes)
    pub fn compact() -> Self {
        Self {
            include_transactions: true,
            include_raw_transactions: false,
            include_utxos: true,
            include_addresses: false,
            max_transactions: None,
        }
    }
}

/// Extractor for wallet data.
///
/// This struct extracts data from the Floresta wallet (AddressCache)
/// for backup purposes, including descriptors, transactions, and UTXOs.
pub struct WalletExtractor {
    network: NetworkType,
    options: ExtractOptions,
}

impl WalletExtractor {
    /// Create a new wallet extractor.
    pub fn new(network: NetworkType) -> Self {
        Self {
            network,
            options: ExtractOptions::default(),
        }
    }

    /// Set extraction options.
    pub fn with_options(mut self, options: ExtractOptions) -> Self {
        self.options = options;
        self
    }

    /// Extract wallet data from an AddressCache into a WalletPayload.
    ///
    /// This method extracts descriptors, transactions, and UTXOs from the
    /// Floresta wallet, including confirmation heights for rescan-free restore.
    ///
    /// # Arguments
    ///
    /// * `wallet` - Reference to the AddressCache to extract data from
    ///
    /// # Returns
    ///
    /// A `WalletPayload` containing all extracted wallet data.
    pub fn extract_from_wallet<D>(
        &self,
        wallet: &floresta_watch_only::AddressCache<D>,
    ) -> Result<WalletPayload>
    where
        D: AddressCacheDatabase,
    {
        let mut payload = WalletPayload::new(self.network);

        // Extract descriptors
        let descriptors = wallet
            .get_descriptors()
            .map_err(|e| BackupError::WalletExtraction(format!("Failed to get descriptors: {e}")))?;

        if descriptors.is_empty() {
            return Err(BackupError::WalletExtraction(
                "No descriptors in wallet".to_string(),
            ));
        }

        // Get wallet stats for metadata
        let stats = wallet
            .get_stats()
            .map_err(|e| BackupError::WalletExtraction(format!("Failed to get stats: {e}")))?;

        // Create account from descriptors
        let account = Account {
            index: Some(0),
            descriptors: descriptors
                .iter()
                .map(|d| Descriptor {
                    descriptor: d.clone(),
                    checksum: extract_checksum(d),
                    addresses: None,
                    metadata: Some(DescriptorMetadata {
                        watch_only: Some(true),
                        ..Default::default()
                    }),
                })
                .collect(),
            metadata: Some(AccountMetadata {
                next_external_index: Some(stats.derivation_index),
                ..Default::default()
            }),
        };

        payload.accounts.push(account);

        // Extract transactions if requested
        if self.options.include_transactions {
            let transactions = self.extract_transactions_from_wallet(wallet)?;
            if !transactions.is_empty() {
                payload.transactions = Some(transactions);
            }
        }

        // Extract UTXOs if requested
        if self.options.include_utxos {
            let utxos = self.extract_utxos_from_wallet(wallet)?;
            if !utxos.is_empty() {
                payload.utxos = Some(utxos);
            }
        }

        // Set wallet metadata
        payload.metadata = Some(WalletMetadata {
            base: BaseMetadata {
                software: Some("Floresta".to_string()),
                birth_height: Some(stats.cache_height),
                ..Default::default()
            },
            ..Default::default()
        });

        Ok(payload)
    }

    /// Extract wallet data into a WalletPayload from a list of descriptors.
    ///
    /// This is a simpler method for when you only have descriptors without
    /// a full wallet instance.
    pub fn extract_from_descriptors(&self, descriptors: &[String]) -> Result<WalletPayload> {
        if descriptors.is_empty() {
            return Err(BackupError::WalletExtraction(
                "No descriptors provided".to_string(),
            ));
        }

        let mut payload = WalletPayload::new(self.network);

        // Create account from descriptors
        let account = Account {
            index: Some(0),
            descriptors: descriptors
                .iter()
                .map(|d| Descriptor {
                    descriptor: d.clone(),
                    checksum: extract_checksum(d),
                    addresses: None,
                    metadata: Some(DescriptorMetadata::default()),
                })
                .collect(),
            metadata: None,
        };

        payload.accounts.push(account);
        payload.metadata = Some(WalletMetadata {
            base: BaseMetadata {
                software: Some("Floresta".to_string()),
                ..Default::default()
            },
            ..Default::default()
        });

        Ok(payload)
    }

    /// Extract transactions from the wallet.
    ///
    /// Includes block heights and merkle proofs for rescan-free restoration.
    fn extract_transactions_from_wallet<D>(
        &self,
        wallet: &floresta_watch_only::AddressCache<D>,
    ) -> Result<Vec<Transaction>>
    where
        D: AddressCacheDatabase,
    {
        let mut transactions = Vec::new();
        let addresses = wallet.get_cached_addresses();

        // Collect unique transactions from all addresses
        let mut seen_txids = std::collections::HashSet::new();

        for script in addresses {
            let script_hash = get_spk_hash(&script);

            if let Some(history) = wallet.get_address_history(&script_hash) {
                for cached_tx in history {
                    // Skip if we've already processed this transaction
                    if !seen_txids.insert(cached_tx.hash) {
                        continue;
                    }

                    // Apply max_transactions limit
                    if let Some(max) = self.options.max_transactions {
                        if transactions.len() >= max {
                            break;
                        }
                    }

                    // Convert txid to bytes (little-endian as stored internally)
                    let txid_bytes: [u8; 32] = *cached_tx.hash.as_byte_array();

                    // Get raw transaction bytes if requested
                    let raw_tx = if self.options.include_raw_transactions {
                        Some(consensus_serialize(&cached_tx.tx))
                    } else {
                        None
                    };

                    // Serialize merkle proof if present
                    let merkle_proof = cached_tx
                        .merkle_block
                        .as_ref()
                        .map(|mb| consensus_serialize(mb));

                    // Create transaction with metadata
                    let tx = Transaction {
                        txid: txid_bytes,
                        raw_tx,
                        metadata: Some(TransactionMetadata {
                            block_height: if cached_tx.height > 0 {
                                Some(cached_tx.height)
                            } else {
                                None
                            },
                            position_in_block: if cached_tx.height > 0 {
                                Some(cached_tx.position)
                            } else {
                                None
                            },
                            merkle_proof,
                            ..Default::default()
                        }),
                    };

                    transactions.push(tx);
                }
            }
        }

        Ok(transactions)
    }

    /// Extract UTXOs from the wallet.
    fn extract_utxos_from_wallet<D>(
        &self,
        wallet: &floresta_watch_only::AddressCache<D>,
    ) -> Result<Vec<Utxo>>
    where
        D: AddressCacheDatabase,
    {
        let mut utxos = Vec::new();
        let addresses = wallet.get_cached_addresses();

        for script in addresses {
            let script_hash = get_spk_hash(&script);

            if let Some(address_utxos) = wallet.get_address_utxos(&script_hash) {
                for (tx_out, outpoint) in address_utxos {
                    let txid_bytes: [u8; 32] = *outpoint.txid.as_byte_array();

                    let utxo = Utxo {
                        txid: txid_bytes,
                        vout: outpoint.vout,
                        amount: tx_out.value.to_sat(),
                        script_pubkey: tx_out.script_pubkey.to_bytes(),
                        address: None, // Could derive address from script if needed
                        metadata: Some(UtxoMetadata {
                            spendable: Some(true),
                            ..Default::default()
                        }),
                    };

                    utxos.push(utxo);
                }
            }
        }

        Ok(utxos)
    }
}

/// Extract checksum from a descriptor string if present.
fn extract_checksum(descriptor: &str) -> Option<String> {
    if let Some(hash_pos) = descriptor.rfind('#') {
        let checksum = &descriptor[hash_pos + 1..];
        if checksum.len() == 8 {
            return Some(checksum.to_string());
        }
    }
    None
}

/// Builder for creating WalletPayload from raw components.
///
/// Useful for testing and manual payload construction.
pub struct PayloadBuilder {
    payload: WalletPayload,
}

impl PayloadBuilder {
    /// Create a new payload builder.
    pub fn new(network: NetworkType) -> Self {
        Self {
            payload: WalletPayload::new(network),
        }
    }

    /// Set the genesis hash.
    pub fn genesis_hash(mut self, hash: [u8; 32]) -> Self {
        self.payload.genesis_hash = Some(hash);
        self
    }

    /// Add an account with descriptors.
    pub fn add_account(mut self, index: u32, descriptors: Vec<String>) -> Self {
        self.payload.accounts.push(Account {
            index: Some(index),
            descriptors: descriptors
                .into_iter()
                .map(|d| Descriptor {
                    descriptor: d,
                    checksum: None,
                    addresses: None,
                    metadata: None,
                })
                .collect(),
            metadata: None,
        });
        self
    }

    /// Add a transaction.
    pub fn add_transaction(
        mut self,
        txid: [u8; 32],
        raw_tx: Option<Vec<u8>>,
        block_height: Option<u32>,
    ) -> Self {
        let transactions = self.payload.transactions.get_or_insert_with(Vec::new);
        transactions.push(Transaction {
            txid,
            raw_tx,
            metadata: Some(TransactionMetadata {
                block_height,
                ..Default::default()
            }),
        });
        self
    }

    /// Add a UTXO.
    pub fn add_utxo(
        mut self,
        txid: [u8; 32],
        vout: u32,
        amount: u64,
        script_pubkey: Vec<u8>,
    ) -> Self {
        let utxos = self.payload.utxos.get_or_insert_with(Vec::new);
        utxos.push(Utxo {
            txid,
            vout,
            amount,
            script_pubkey,
            address: None,
            metadata: Some(UtxoMetadata::default()),
        });
        self
    }

    /// Set wallet metadata.
    pub fn metadata(mut self, metadata: WalletMetadata) -> Self {
        self.payload.metadata = Some(metadata);
        self
    }

    /// Build the final payload.
    pub fn build(self) -> WalletPayload {
        self.payload
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_checksum() {
        assert_eq!(
            extract_checksum("wpkh(...)#abcd1234"),
            Some("abcd1234".to_string())
        );
        assert_eq!(extract_checksum("wpkh(...)"), None);
        assert_eq!(extract_checksum("wpkh(...)#abc"), None); // Too short
    }

    #[test]
    fn test_extract_from_descriptors() {
        let extractor = WalletExtractor::new(NetworkType::Testnet);
        let descriptors = vec![
            "wpkh([deadbeef/84h/0h/0h]xpub.../0/*)#abcd1234".to_string(),
        ];

        let payload = extractor.extract_from_descriptors(&descriptors).unwrap();

        assert_eq!(payload.network, NetworkType::Testnet);
        assert_eq!(payload.accounts.len(), 1);
        assert_eq!(payload.accounts[0].descriptors.len(), 1);
        assert_eq!(
            payload.accounts[0].descriptors[0].checksum,
            Some("abcd1234".to_string())
        );
    }

    #[test]
    fn test_payload_builder() {
        let payload = PayloadBuilder::new(NetworkType::Mainnet)
            .add_account(0, vec!["wpkh(xpub.../0/*)".to_string()])
            .add_transaction([0u8; 32], None, Some(800000))
            .add_utxo([1u8; 32], 0, 100000, vec![0x00, 0x14])
            .build();

        assert_eq!(payload.accounts.len(), 1);
        assert_eq!(payload.transactions.as_ref().unwrap().len(), 1);
        assert_eq!(payload.utxos.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn test_extract_empty_descriptors() {
        let extractor = WalletExtractor::new(NetworkType::Mainnet);
        let result = extractor.extract_from_descriptors(&[]);

        assert!(matches!(result, Err(BackupError::WalletExtraction(_))));
    }
}
