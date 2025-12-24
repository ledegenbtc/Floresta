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
//! use floresta_backup::{WalletPayload, NetworkType};
//!
//! // Create a new payload
//! let mut payload = WalletPayload::new(NetworkType::Mainnet);
//!
//! // Add accounts, transactions, etc.
//! // ...
//!
//! // Export to encrypted backup
//! let backup = payload.export_encrypted("my_password")?;
//!
//! // Import from backup
//! let restored = WalletPayload::import_encrypted(&backup, "my_password")?;
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
