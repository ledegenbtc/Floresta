//! # Error Types
//!
//! This module defines error types for the floresta-backup crate.

use thiserror::Error;

/// Errors that can occur during backup operations.
#[derive(Debug, Error)]
pub enum BackupError {
    /// CBOR serialization error
    #[error("CBOR serialization error: {0}")]
    CborSerialize(String),

    /// CBOR deserialization error
    #[error("CBOR deserialization error: {0}")]
    CborDeserialize(String),

    /// Invalid payload version
    #[error("Unsupported payload version: {0}, expected {1}")]
    UnsupportedVersion(u8, u8),

    /// Encryption error
    #[error("Encryption error: {0}")]
    Encryption(String),

    /// Decryption error
    #[error("Decryption error: {0}")]
    Decryption(String),

    /// Invalid password
    #[error("Invalid password or corrupted data")]
    InvalidPassword,

    /// Key derivation error
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),

    /// Validation error
    #[error("Validation error: {0}")]
    Validation(String),

    /// Network mismatch
    #[error("Network mismatch: backup is for {0:?}, wallet is {1:?}")]
    NetworkMismatch(crate::NetworkType, crate::NetworkType),

    /// Empty accounts list
    #[error("Wallet payload must have at least one account")]
    EmptyAccounts,

    /// Invalid descriptor
    #[error("Invalid descriptor: {0}")]
    InvalidDescriptor(String),

    /// Invalid transaction
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Wallet extraction error
    #[error("Wallet extraction error: {0}")]
    WalletExtraction(String),

    /// Wallet import error
    #[error("Wallet import error: {0}")]
    WalletImport(String),
}

/// Result type alias for backup operations.
pub type Result<T> = std::result::Result<T, BackupError>;
