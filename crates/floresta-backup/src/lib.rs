//! # Floresta Backup
//!
//! Implementation of the Bitcoin Encrypted Wallet Payload standard (BIP-BEWP)
//! for the Floresta Bitcoin node.
//!
//! This crate provides functionality to:
//! - Export wallet descriptors and transaction history to a compact, encrypted backup
//! - Import backups and restore wallets without expensive blockchain rescans
//!
//! ## Features
//!
//! - **CBOR Serialization**: Compact binary format using RFC 8949 canonical encoding
//! - **Strong Encryption**: Argon2id key derivation + AES-256-GCM encryption
//! - **Rescan-Free Restore**: Stores confirmation heights for instant restoration
//! - **BIP Compatibility**: Follows the standard for cross-wallet interoperability
//!
//! ## Example
//!
//! ```rust,ignore
//! use floresta_backup::{export_wallet_backup, restore_wallet_backup, NetworkType};
//! use floresta_watch_only::AddressCache;
//!
//! // Export wallet to encrypted backup
//! let backup = export_wallet_backup(&wallet, NetworkType::Mainnet, "my_password")?;
//!
//! // Later, restore from backup
//! let result = restore_wallet_backup(&new_wallet, &backup, "my_password")?;
//! println!("Restored {} descriptors and {} transactions",
//!          result.descriptors_imported, result.transactions_imported);
//! ```

pub mod cbor;
pub mod crypto;
pub mod envelope;
pub mod error;
pub mod extractor;
pub mod importer;
pub mod types;
pub mod validation;

// Re-export main types
pub use types::*;

// Re-export error types
pub use error::{BackupError, Result};

// Re-export main functionality
pub use cbor::{deserialize, serialize};
pub use crypto::Argon2Params;
pub use envelope::EncryptedEnvelope;
pub use extractor::{ExtractOptions, PayloadBuilder, WalletExtractor};
pub use importer::{ImportOptions, ImportResult, WalletImporter};
pub use validation::{validate_payload, validate_payload_strict};

use floresta_watch_only::AddressCacheDatabase;

// ============================================================================
// HIGH-LEVEL API
// ============================================================================

/// Export a wallet to an encrypted backup.
///
/// This is the main high-level function for creating wallet backups.
/// It extracts all wallet data (descriptors, transactions, UTXOs) and
/// encrypts it using the provided password.
///
/// # Arguments
///
/// * `wallet` - Reference to the AddressCache wallet to backup
/// * `network` - The Bitcoin network (Mainnet, Testnet, Signet, Regtest)
/// * `password` - Password for encrypting the backup
///
/// # Returns
///
/// Encrypted backup as a byte vector that can be written to a file.
///
/// # Example
///
/// ```rust,ignore
/// let backup = export_wallet_backup(&wallet, NetworkType::Mainnet, "secure_password")?;
/// std::fs::write("wallet.backup", &backup)?;
/// ```
pub fn export_wallet_backup<D>(
    wallet: &floresta_watch_only::AddressCache<D>,
    network: NetworkType,
    password: &str,
) -> Result<Vec<u8>>
where
    D: AddressCacheDatabase,
{
    export_wallet_backup_with_options(wallet, network, password, ExtractOptions::full())
}

/// Export a wallet to an encrypted backup with custom options.
///
/// Like `export_wallet_backup` but allows customizing what data to include.
///
/// # Arguments
///
/// * `wallet` - Reference to the AddressCache wallet to backup
/// * `network` - The Bitcoin network
/// * `password` - Password for encrypting the backup
/// * `options` - Options controlling what data to include in the backup
///
/// # Example
///
/// ```rust,ignore
/// // Create a minimal backup (descriptors only, no transactions)
/// let options = ExtractOptions::minimal();
/// let backup = export_wallet_backup_with_options(
///     &wallet, NetworkType::Mainnet, "password", options
/// )?;
/// ```
pub fn export_wallet_backup_with_options<D>(
    wallet: &floresta_watch_only::AddressCache<D>,
    network: NetworkType,
    password: &str,
    options: ExtractOptions,
) -> Result<Vec<u8>>
where
    D: AddressCacheDatabase,
{
    // Extract wallet data
    let extractor = WalletExtractor::new(network).with_options(options);
    let payload = extractor.extract_from_wallet(wallet)?;

    // Validate the payload
    validate_payload(&payload)?;

    // Encrypt and create envelope (serialization is handled internally)
    let envelope = EncryptedEnvelope::create(&payload, password, Argon2Params::default())?;

    Ok(envelope.to_bytes())
}

/// Restore a wallet from an encrypted backup.
///
/// This is the main high-level function for restoring wallet backups.
/// It decrypts the backup, validates the data, and imports descriptors
/// and transactions into the wallet.
///
/// # Arguments
///
/// * `wallet` - Reference to the AddressCache wallet to restore into
/// * `backup_data` - The encrypted backup data
/// * `password` - Password for decrypting the backup
///
/// # Returns
///
/// An `ImportResult` with statistics about what was restored.
///
/// # Example
///
/// ```rust,ignore
/// let backup = std::fs::read("wallet.backup")?;
/// let result = restore_wallet_backup(&wallet, &backup, "secure_password")?;
/// println!("Restored {} transactions", result.transactions_imported);
/// ```
pub fn restore_wallet_backup<D>(
    wallet: &floresta_watch_only::AddressCache<D>,
    backup_data: &[u8],
    password: &str,
) -> Result<ImportResult>
where
    D: AddressCacheDatabase,
{
    restore_wallet_backup_with_options(wallet, backup_data, password, ImportOptions::default())
}

/// Restore a wallet from an encrypted backup with custom options.
///
/// Like `restore_wallet_backup` but allows customizing the import behavior.
///
/// # Arguments
///
/// * `wallet` - Reference to the AddressCache wallet to restore into
/// * `backup_data` - The encrypted backup data
/// * `password` - Password for decrypting the backup
/// * `options` - Options controlling import behavior
///
/// # Example
///
/// ```rust,ignore
/// let options = ImportOptions {
///     expected_network: Some(NetworkType::Testnet),
///     ..Default::default()
/// };
/// let result = restore_wallet_backup_with_options(
///     &wallet, &backup, "password", options
/// )?;
/// ```
pub fn restore_wallet_backup_with_options<D>(
    wallet: &floresta_watch_only::AddressCache<D>,
    backup_data: &[u8],
    password: &str,
    options: ImportOptions,
) -> Result<ImportResult>
where
    D: AddressCacheDatabase,
{
    // Parse the encrypted envelope
    let envelope = EncryptedEnvelope::from_bytes(backup_data)?;

    // Decrypt (deserialization is handled internally)
    let payload = envelope.decrypt(password)?;

    // Import to wallet
    let importer = WalletImporter::new(payload).with_options(options);
    importer.import_to_wallet(wallet)
}

/// Preview what would be imported from a backup without modifying the wallet.
///
/// Useful for showing the user what a backup contains before actually
/// restoring it.
///
/// # Arguments
///
/// * `backup_data` - The encrypted backup data
/// * `password` - Password for decrypting the backup
///
/// # Returns
///
/// An `ImportResult` with statistics about what would be imported.
pub fn preview_backup(backup_data: &[u8], password: &str) -> Result<ImportResult> {
    // Parse and decrypt (deserialization is handled internally)
    let envelope = EncryptedEnvelope::from_bytes(backup_data)?;
    let payload = envelope.decrypt(password)?;

    // Do a dry run
    let importer = WalletImporter::new(payload);
    importer.dry_run()
}

/// Get the network type from an encrypted backup.
///
/// Useful for verifying a backup is for the expected network before
/// attempting to restore it.
///
/// # Arguments
///
/// * `backup_data` - The encrypted backup data
/// * `password` - Password for decrypting the backup
///
/// # Returns
///
/// The `NetworkType` the backup was created for.
pub fn get_backup_network(backup_data: &[u8], password: &str) -> Result<NetworkType> {
    let envelope = EncryptedEnvelope::from_bytes(backup_data)?;
    let payload = envelope.decrypt(password)?;
    Ok(payload.network)
}
