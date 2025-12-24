//! # Cryptography Module
//!
//! This module provides encryption and key derivation for wallet backups.
//!
//! ## Security Parameters
//!
//! - **KDF**: Argon2id with parameters suitable for sensitive data
//!   - Memory: 64 MiB (configurable)
//!   - Iterations: 3 (configurable)
//!   - Parallelism: 4 threads
//! - **Encryption**: AES-256-GCM (authenticated encryption)
//! - **Salt**: 16 bytes random
//! - **Nonce**: 12 bytes random (standard for AES-GCM)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use floresta_backup::crypto::{encrypt, decrypt, Argon2Params};
//!
//! let plaintext = b"secret data";
//! let password = "my_password";
//!
//! // Encrypt with default parameters
//! let encrypted = encrypt(plaintext, password, Argon2Params::default())?;
//!
//! // Decrypt
//! let decrypted = decrypt(&encrypted.ciphertext, password, &encrypted)?;
//! assert_eq!(decrypted, plaintext);
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Version};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{BackupError, Result};

/// Size of the encryption key in bytes (256 bits for AES-256)
pub const KEY_SIZE: usize = 32;

/// Size of the salt for Argon2id
pub const SALT_SIZE: usize = 16;

/// Size of the nonce for AES-GCM
pub const NONCE_SIZE: usize = 12;

/// Size of the authentication tag for AES-GCM
pub const TAG_SIZE: usize = 16;

/// Argon2id parameters for key derivation.
///
/// Default values provide a reasonable balance between security and performance.
/// For highly sensitive backups, consider increasing memory and iterations.
#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    /// Memory cost in KiB (default: 65536 = 64 MiB)
    pub memory_kib: u32,
    /// Number of iterations (default: 3)
    pub iterations: u32,
    /// Parallelism degree (default: 4)
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kib: 65536, // 64 MiB
            iterations: 3,
            parallelism: 4,
        }
    }
}

impl Argon2Params {
    /// Create light parameters suitable for resource-constrained devices.
    pub fn light() -> Self {
        Self {
            memory_kib: 16384, // 16 MiB
            iterations: 2,
            parallelism: 2,
        }
    }

    /// Create strong parameters for maximum security.
    pub fn strong() -> Self {
        Self {
            memory_kib: 262144, // 256 MiB
            iterations: 5,
            parallelism: 4,
        }
    }
}

/// Encrypted data along with the parameters needed for decryption.
#[derive(Debug, Clone)]
pub struct EncryptedData {
    /// Salt used for key derivation
    pub salt: [u8; SALT_SIZE],
    /// Nonce used for AES-GCM encryption
    pub nonce: [u8; NONCE_SIZE],
    /// Ciphertext with authentication tag appended
    pub ciphertext: Vec<u8>,
    /// Argon2 parameters used for key derivation
    pub params: Argon2Params,
}

/// Derived encryption key with secure cleanup.
#[derive(Zeroize, ZeroizeOnDrop)]
struct DerivedKey([u8; KEY_SIZE]);

/// Derive an encryption key from a password using Argon2id.
fn derive_key(password: &str, salt: &[u8; SALT_SIZE], params: &Argon2Params) -> Result<DerivedKey> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        Version::V0x13,
        argon2::Params::new(params.memory_kib, params.iterations, params.parallelism, Some(KEY_SIZE))
            .map_err(|e| BackupError::KeyDerivation(e.to_string()))?,
    );

    let mut key = [0u8; KEY_SIZE];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| BackupError::KeyDerivation(e.to_string()))?;

    Ok(DerivedKey(key))
}

/// Encrypt plaintext data using a password.
///
/// Uses Argon2id for key derivation and AES-256-GCM for encryption.
/// Returns the encrypted data along with all parameters needed for decryption.
pub fn encrypt(plaintext: &[u8], password: &str, params: Argon2Params) -> Result<EncryptedData> {
    // Generate random salt and nonce
    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    // Derive encryption key
    let key = derive_key(password, &salt, &params)?;

    // Encrypt with AES-256-GCM
    let cipher =
        Aes256Gcm::new_from_slice(&key.0).map_err(|e| BackupError::Encryption(e.to_string()))?;
    let nonce_obj = Nonce::from_slice(&nonce);
    let ciphertext = cipher
        .encrypt(nonce_obj, plaintext)
        .map_err(|e| BackupError::Encryption(e.to_string()))?;

    Ok(EncryptedData {
        salt,
        nonce,
        ciphertext,
        params,
    })
}

/// Decrypt ciphertext using a password and the original encryption parameters.
///
/// Returns an error if the password is wrong or the data is corrupted.
pub fn decrypt(ciphertext: &[u8], password: &str, data: &EncryptedData) -> Result<Vec<u8>> {
    // Derive the same key using stored parameters
    let key = derive_key(password, &data.salt, &data.params)?;

    // Decrypt with AES-256-GCM
    let cipher =
        Aes256Gcm::new_from_slice(&key.0).map_err(|e| BackupError::Decryption(e.to_string()))?;
    let nonce = Nonce::from_slice(&data.nonce);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| BackupError::InvalidPassword)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let plaintext = b"Hello, Bitcoin!";
        let password = "test_password_123";

        let encrypted = encrypt(plaintext, password, Argon2Params::light()).unwrap();
        let decrypted = decrypt(&encrypted.ciphertext, password, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_password() {
        let plaintext = b"secret data";
        let password = "correct_password";

        let encrypted = encrypt(plaintext, password, Argon2Params::light()).unwrap();
        let result = decrypt(&encrypted.ciphertext, "wrong_password", &encrypted);

        assert!(matches!(result, Err(BackupError::InvalidPassword)));
    }

    #[test]
    fn test_different_salts_produce_different_ciphertext() {
        let plaintext = b"same data";
        let password = "same_password";

        let encrypted1 = encrypt(plaintext, password, Argon2Params::light()).unwrap();
        let encrypted2 = encrypt(plaintext, password, Argon2Params::light()).unwrap();

        // Ciphertexts should be different due to random salt/nonce
        assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
        assert_ne!(encrypted1.salt, encrypted2.salt);
        assert_ne!(encrypted1.nonce, encrypted2.nonce);
    }

    #[test]
    fn test_empty_plaintext() {
        let plaintext = b"";
        let password = "password";

        let encrypted = encrypt(plaintext, password, Argon2Params::light()).unwrap();
        let decrypted = decrypt(&encrypted.ciphertext, password, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
