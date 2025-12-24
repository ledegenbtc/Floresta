//! # Encrypted Envelope
//!
//! This module provides the encrypted envelope wrapper for wallet backups.
//!
//! The envelope contains all the metadata needed to decrypt the payload:
//! - Magic bytes for format identification
//! - Version information
//! - Encryption parameters (salt, nonce, Argon2 params)
//! - Encrypted CBOR payload
//!
//! ## Binary Format
//!
//! ```text
//! +-------------------+
//! | Magic (4 bytes)   |  "BEWP" - Bitcoin Encrypted Wallet Payload
//! +-------------------+
//! | Version (1 byte)  |  Currently 1
//! +-------------------+
//! | Flags (1 byte)    |  Reserved for future use
//! +-------------------+
//! | Salt (16 bytes)   |  Argon2id salt
//! +-------------------+
//! | Nonce (12 bytes)  |  AES-GCM nonce
//! +-------------------+
//! | Argon2 params     |  Memory (4B) + Iterations (4B) + Parallelism (4B)
//! | (12 bytes)        |
//! +-------------------+
//! | Ciphertext length |  4 bytes, big-endian
//! +-------------------+
//! | Ciphertext        |  Variable length (CBOR + auth tag)
//! +-------------------+
//! ```

use crate::crypto::{self, Argon2Params, EncryptedData, NONCE_SIZE, SALT_SIZE};
use crate::error::{BackupError, Result};
use crate::{cbor, WalletPayload};

/// Magic bytes identifying the encrypted envelope format
pub const MAGIC: &[u8; 4] = b"BEWP";

/// Current envelope version
pub const ENVELOPE_VERSION: u8 = 1;

/// Header size without ciphertext (magic + version + flags + salt + nonce + argon2 params + length)
pub const HEADER_SIZE: usize = 4 + 1 + 1 + SALT_SIZE + NONCE_SIZE + 12 + 4;

/// Flags for the envelope (reserved for future use)
#[derive(Debug, Clone, Copy, Default)]
pub struct EnvelopeFlags(u8);

impl EnvelopeFlags {
    /// No flags set
    pub const NONE: Self = Self(0);
}

/// An encrypted wallet backup envelope.
#[derive(Debug, Clone)]
pub struct EncryptedEnvelope {
    /// Envelope version
    pub version: u8,
    /// Envelope flags
    pub flags: EnvelopeFlags,
    /// Encrypted data with parameters
    pub encrypted: EncryptedData,
}

impl EncryptedEnvelope {
    /// Create a new encrypted envelope from a wallet payload.
    ///
    /// Serializes the payload to CBOR and encrypts it using the provided password.
    pub fn create(
        payload: &WalletPayload,
        password: &str,
        params: Argon2Params,
    ) -> Result<Self> {
        // Serialize payload to CBOR
        let cbor_data = cbor::serialize(payload)?;

        // Encrypt the CBOR data
        let encrypted = crypto::encrypt(&cbor_data, password, params)?;

        Ok(Self {
            version: ENVELOPE_VERSION,
            flags: EnvelopeFlags::NONE,
            encrypted,
        })
    }

    /// Decrypt the envelope and return the wallet payload.
    pub fn decrypt(&self, password: &str) -> Result<WalletPayload> {
        // Decrypt the ciphertext
        let cbor_data = crypto::decrypt(&self.encrypted.ciphertext, password, &self.encrypted)?;

        // Deserialize CBOR to payload
        cbor::deserialize(&cbor_data)
    }

    /// Serialize the envelope to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HEADER_SIZE + self.encrypted.ciphertext.len());

        // Magic
        bytes.extend_from_slice(MAGIC);

        // Version
        bytes.push(self.version);

        // Flags
        bytes.push(self.flags.0);

        // Salt
        bytes.extend_from_slice(&self.encrypted.salt);

        // Nonce
        bytes.extend_from_slice(&self.encrypted.nonce);

        // Argon2 params (3x u32 big-endian)
        bytes.extend_from_slice(&self.encrypted.params.memory_kib.to_be_bytes());
        bytes.extend_from_slice(&self.encrypted.params.iterations.to_be_bytes());
        bytes.extend_from_slice(&self.encrypted.params.parallelism.to_be_bytes());

        // Ciphertext length
        let len = self.encrypted.ciphertext.len() as u32;
        bytes.extend_from_slice(&len.to_be_bytes());

        // Ciphertext
        bytes.extend_from_slice(&self.encrypted.ciphertext);

        bytes
    }

    /// Parse an envelope from bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            return Err(BackupError::Validation(format!(
                "Envelope too short: {} bytes, minimum {}",
                bytes.len(),
                HEADER_SIZE
            )));
        }

        // Check magic
        if &bytes[0..4] != MAGIC {
            return Err(BackupError::Validation(
                "Invalid magic bytes, not a BEWP file".to_string(),
            ));
        }

        // Version
        let version = bytes[4];
        if version > ENVELOPE_VERSION {
            return Err(BackupError::UnsupportedVersion(version, ENVELOPE_VERSION));
        }

        // Flags
        let flags = EnvelopeFlags(bytes[5]);

        // Salt
        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(&bytes[6..6 + SALT_SIZE]);

        // Nonce
        let mut nonce = [0u8; NONCE_SIZE];
        let nonce_start = 6 + SALT_SIZE;
        nonce.copy_from_slice(&bytes[nonce_start..nonce_start + NONCE_SIZE]);

        // Argon2 params
        let params_start = nonce_start + NONCE_SIZE;
        let memory_kib = u32::from_be_bytes([
            bytes[params_start],
            bytes[params_start + 1],
            bytes[params_start + 2],
            bytes[params_start + 3],
        ]);
        let iterations = u32::from_be_bytes([
            bytes[params_start + 4],
            bytes[params_start + 5],
            bytes[params_start + 6],
            bytes[params_start + 7],
        ]);
        let parallelism = u32::from_be_bytes([
            bytes[params_start + 8],
            bytes[params_start + 9],
            bytes[params_start + 10],
            bytes[params_start + 11],
        ]);

        // Ciphertext length
        let len_start = params_start + 12;
        let ciphertext_len = u32::from_be_bytes([
            bytes[len_start],
            bytes[len_start + 1],
            bytes[len_start + 2],
            bytes[len_start + 3],
        ]) as usize;

        // Ciphertext
        let ciphertext_start = len_start + 4;
        if bytes.len() < ciphertext_start + ciphertext_len {
            return Err(BackupError::Validation(format!(
                "Envelope truncated: expected {} bytes of ciphertext, got {}",
                ciphertext_len,
                bytes.len() - ciphertext_start
            )));
        }
        let ciphertext = bytes[ciphertext_start..ciphertext_start + ciphertext_len].to_vec();

        Ok(Self {
            version,
            flags,
            encrypted: EncryptedData {
                salt,
                nonce,
                ciphertext,
                params: Argon2Params {
                    memory_kib,
                    iterations,
                    parallelism,
                },
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Account, Descriptor, NetworkType};

    fn create_test_payload() -> WalletPayload {
        let mut payload = WalletPayload::new(NetworkType::Testnet);
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
    fn test_envelope_roundtrip() {
        let payload = create_test_payload();
        let password = "test_password";

        // Create envelope
        let envelope = EncryptedEnvelope::create(&payload, password, Argon2Params::light()).unwrap();

        // Serialize and deserialize
        let bytes = envelope.to_bytes();
        let restored_envelope = EncryptedEnvelope::from_bytes(&bytes).unwrap();

        // Decrypt
        let restored_payload = restored_envelope.decrypt(password).unwrap();

        assert_eq!(restored_payload.version, payload.version);
        assert_eq!(restored_payload.network, payload.network);
        assert_eq!(restored_payload.accounts.len(), payload.accounts.len());
    }

    #[test]
    fn test_invalid_magic() {
        let mut bytes = vec![0u8; HEADER_SIZE + 16];
        bytes[0..4].copy_from_slice(b"XXXX");

        let result = EncryptedEnvelope::from_bytes(&bytes);
        assert!(matches!(result, Err(BackupError::Validation(_))));
    }

    #[test]
    fn test_truncated_envelope() {
        let result = EncryptedEnvelope::from_bytes(&[0u8; 10]);
        assert!(matches!(result, Err(BackupError::Validation(_))));
    }

    #[test]
    fn test_wrong_password() {
        let payload = create_test_payload();
        let envelope = EncryptedEnvelope::create(&payload, "correct", Argon2Params::light()).unwrap();
        let bytes = envelope.to_bytes();

        let restored = EncryptedEnvelope::from_bytes(&bytes).unwrap();
        let result = restored.decrypt("wrong");

        assert!(matches!(result, Err(BackupError::InvalidPassword)));
    }
}
