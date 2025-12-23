//! # Wallet Payload Types
//!
//! This module defines the data structures for the Bitcoin Encrypted Wallet Payload
//! standard (BIP-BEWP). The structures follow the CDDL schema defined in the BIP
//! and use integer keys for CBOR serialization efficiency.
//!
//! ## Key Ranges
//!
//! | Range     | Purpose                    | Behavior                      |
//! |-----------|----------------------------|-------------------------------|
//! | 0-99      | Core wallet fields         | WARN if unknown, continue     |
//! | 100-999   | Metadata fields            | Safe to ignore if unknown     |
//! | ≥1000     | Vendor-specific (Floresta) | Non-interoperable, safe ignore|
//!
//! ## Encoding Requirements
//!
//! - CBOR must be canonical/deterministic (RFC 8949 §4.2.1)
//! - No indefinite-length arrays/maps
//! - No floating point numbers
//! - Map keys must be sorted by integer value

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

// ============================================================================
// NETWORK TYPE
// ============================================================================

/// Bitcoin network identifier.
///
/// Matches the BIP specification:
/// - 0 = Mainnet
/// - 1 = Testnet
/// - 2 = Signet
/// - 3 = Regtest
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum NetworkType {
    /// Bitcoin mainnet
    Mainnet = 0,
    /// Bitcoin testnet3/testnet4
    Testnet = 1,
    /// Bitcoin signet
    Signet = 2,
    /// Bitcoin regtest (local testing)
    Regtest = 3,
}

impl Default for NetworkType {
    fn default() -> Self {
        Self::Mainnet
    }
}

// ============================================================================
// ROOT MATERIAL (Key 3)
// ============================================================================

/// Root secret material for HD wallet derivation.
///
/// Only ONE of these variants should be present. They are mutually exclusive
/// because they represent different forms of the same underlying entropy:
///
/// ## Mnemonic vs Seed vs Entropy
///
/// ```text
/// Entropy (128-256 bits)
///     ↓ BIP39 encoding
/// Mnemonic (12-24 words) + optional Passphrase
///     ↓ PBKDF2-HMAC-SHA512 (2048 rounds)
/// Seed (512 bits / 64 bytes)
///     ↓ HMAC-SHA512 with key "Bitcoin seed"
/// Master Private Key + Chain Code
/// ```
///
/// - **Entropy**: Raw random bytes (smallest, but needs BIP39 wordlist to recover)
/// - **Mnemonic**: Human-readable words (portable, standard, includes checksum)
/// - **Seed**: Derived from mnemonic+passphrase (largest, passphrase already applied)
///
/// For interoperability, **Mnemonic** is preferred as it's the most portable format.
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(untagged)]
pub enum RootMaterial {
    /// BIP39 mnemonic words (12, 15, 18, 21, or 24 words)
    ///
    /// This is the most interoperable format. The optional passphrase
    /// (sometimes called "25th word") adds extra protection.
    Mnemonic(MnemonicRoot),

    /// Raw 512-bit seed derived from mnemonic + passphrase.
    ///
    /// Use this when the passphrase has already been applied and you
    /// want to store the derived seed directly. Cannot recover the
    /// original mnemonic from this.
    Seed(SeedRoot),

    /// Raw entropy bytes (16, 20, 24, 28, or 32 bytes).
    ///
    /// The most compact form, but requires the BIP39 wordlist to
    /// convert back to mnemonic. Rarely used in practice.
    Entropy(EntropyRoot),
}

/// BIP39 mnemonic with optional passphrase.
///
/// CDDL: `mnemonic-root = { 10 => mnemonic-type, ? 11 => passphrase-type }`
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MnemonicRoot {
    /// BIP39 mnemonic words (12, 15, 18, 21, or 24 words)
    ///
    /// CBOR key: 10
    #[serde(rename = "10")]
    pub words: Vec<String>,

    /// Optional BIP39 passphrase (the "25th word")
    ///
    /// CBOR key: 11
    #[serde(rename = "11", skip_serializing_if = "Option::is_none")]
    pub passphrase: Option<String>,
}

/// Pre-derived 512-bit seed.
///
/// CDDL: `seed-root = { 12 => seed-type }`
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SeedRoot {
    /// 64-byte seed derived from mnemonic + passphrase
    ///
    /// CBOR key: 12
    #[serde(rename = "12", with = "serde_bytes_array")]
    pub seed: [u8; 64],
}

/// Raw entropy bytes.
///
/// CDDL: `entropy-root = { 13 => entropy-type }`
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EntropyRoot {
    /// Raw entropy (16, 20, 24, 28, or 32 bytes)
    ///
    /// CBOR key: 13
    #[serde(rename = "13", with = "serde_bytes")]
    pub entropy: Vec<u8>,
}

// ============================================================================
// WALLET PAYLOAD (Root Structure)
// ============================================================================

/// The root wallet payload structure.
///
/// This is the main container that holds all wallet data for backup/restore.
///
/// CDDL:
/// ```cddl
/// wallet-payload = {
///   0 => 1..255,           ; version
///   1 => network-type,     ; network
///   ? 2 => bstr .size 32,  ; genesis_hash
///   ? 3 => root,           ; root material
///   10 => [+ account],     ; accounts
///   ? 20 => [+ transaction],
///   ? 30 => [+ utxo],
///   ? 100 => wallet-metadata,
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletPayload {
    /// Payload format version (currently 1)
    ///
    /// CBOR key: 0
    #[serde(rename = "0")]
    pub version: u8,

    /// Bitcoin network this wallet belongs to
    ///
    /// CBOR key: 1
    #[serde(rename = "1")]
    pub network: NetworkType,

    /// Genesis block hash (required for non-mainnet)
    ///
    /// Prevents accidentally restoring a testnet wallet on mainnet.
    ///
    /// CBOR key: 2
    #[serde(rename = "2", skip_serializing_if = "Option::is_none")]
    pub genesis_hash: Option<[u8; 32]>,

    /// Root secret material (mnemonic/seed/entropy)
    ///
    /// Optional because watch-only wallets don't have private keys.
    ///
    /// CBOR key: 3
    #[serde(rename = "3", skip_serializing_if = "Option::is_none")]
    pub root: Option<RootMaterial>,

    /// List of accounts with their descriptors
    ///
    /// At least one account is required.
    ///
    /// CBOR key: 10
    #[serde(rename = "10")]
    pub accounts: Vec<Account>,

    /// Transaction history
    ///
    /// CBOR key: 20
    #[serde(rename = "20", skip_serializing_if = "Option::is_none")]
    pub transactions: Option<Vec<Transaction>>,

    /// UTXO set snapshot (advisory only)
    ///
    /// The blockchain is authoritative; these are hints for faster restore.
    ///
    /// CBOR key: 30
    #[serde(rename = "30", skip_serializing_if = "Option::is_none")]
    pub utxos: Option<Vec<Utxo>>,

    /// Wallet-level metadata (labels, timestamps, software info)
    ///
    /// CBOR key: 100
    #[serde(rename = "100", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<WalletMetadata>,
}

impl WalletPayload {
    /// Current version of the payload format
    pub const CURRENT_VERSION: u8 = 1;

    /// Create a new empty wallet payload
    pub fn new(network: NetworkType) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            network,
            genesis_hash: None,
            root: None,
            accounts: Vec::new(),
            transactions: None,
            utxos: None,
            metadata: None,
        }
    }
}

// ============================================================================
// ACCOUNT (Key 10)
// ============================================================================

/// A wallet account containing one or more descriptors.
///
/// Accounts typically correspond to BIP44/84/86 account indices.
///
/// CDDL:
/// ```cddl
/// account = {
///   ? 1 => uint32,          ; account index
///   10 => [+ descriptor],   ; descriptors
///   ? 100 => account-metadata
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// BIP44/84/86 account index (e.g., 0 for first account)
    ///
    /// CBOR key: 1
    #[serde(rename = "1", skip_serializing_if = "Option::is_none")]
    pub index: Option<u32>,

    /// Output descriptors for this account
    ///
    /// Typically includes receive and change descriptors.
    ///
    /// CBOR key: 10
    #[serde(rename = "10")]
    pub descriptors: Vec<Descriptor>,

    /// Account-level metadata
    ///
    /// CBOR key: 100
    #[serde(rename = "100", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<AccountMetadata>,
}

// ============================================================================
// DESCRIPTOR (Key 10 within Account)
// ============================================================================

/// A BIP380 output script descriptor.
///
/// Descriptors are strings that describe how to derive addresses and scripts.
/// Examples:
/// - `wpkh([fingerprint/84'/0'/0']xpub.../0/*)` - Native SegWit
/// - `tr([fingerprint/86'/0'/0']xpub.../0/*)` - Taproot
/// - `pkh(xpub.../*)` - Legacy P2PKH
///
/// CDDL:
/// ```cddl
/// descriptor = {
///   1 => tstr,              ; descriptor string
///   ? 2 => checksum,        ; 8-char bech32 checksum
///   ? 10 => [+ address],    ; derived addresses
///   ? 100 => descriptor-metadata
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Descriptor {
    /// The descriptor string (BIP380 format)
    ///
    /// CBOR key: 1
    #[serde(rename = "1")]
    pub descriptor: String,

    /// 8-character bech32 checksum
    ///
    /// Can be used to validate the descriptor string.
    ///
    /// CBOR key: 2
    #[serde(rename = "2", skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,

    /// Pre-derived addresses (optional cache)
    ///
    /// CBOR key: 10
    #[serde(rename = "10", skip_serializing_if = "Option::is_none")]
    pub addresses: Option<Vec<Address>>,

    /// Descriptor-level metadata
    ///
    /// CBOR key: 100
    #[serde(rename = "100", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<DescriptorMetadata>,
}

// ============================================================================
// ADDRESS (Key 10 within Descriptor)
// ============================================================================

/// A derived Bitcoin address.
///
/// CDDL:
/// ```cddl
/// address = {
///   1 => address-type,      ; the address string
///   ? 100 => address-metadata
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    /// The address string (e.g., "bc1q...")
    ///
    /// CBOR key: 1
    #[serde(rename = "1")]
    pub address: String,

    /// Address-level metadata
    ///
    /// CBOR key: 100
    #[serde(rename = "100", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<AddressMetadata>,
}

// ============================================================================
// TRANSACTION (Key 20)
// ============================================================================

/// A transaction record.
///
/// Stores transaction ID and optionally the raw transaction bytes.
/// The metadata field is crucial for Floresta as it stores the block height
/// where the transaction was confirmed, enabling restore without rescan.
///
/// CDDL:
/// ```cddl
/// transaction = {
///   1 => txid-type,              ; 32-byte txid
///   ? 2 => bstr .size 2..4000000, ; raw tx bytes
///   ? 100 => transaction-metadata
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction ID (32 bytes, little-endian as stored internally)
    ///
    /// CBOR key: 1
    #[serde(rename = "1", with = "serde_bytes_array")]
    pub txid: [u8; 32],

    /// Raw transaction bytes (optional)
    ///
    /// If present, hash(raw_tx) must equal txid.
    ///
    /// CBOR key: 2
    #[serde(rename = "2", skip_serializing_if = "Option::is_none", with = "serde_bytes_opt")]
    pub raw_tx: Option<Vec<u8>>,

    /// Transaction metadata (block height, fee, flags)
    ///
    /// CBOR key: 100
    #[serde(rename = "100", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<TransactionMetadata>,
}

// ============================================================================
// UTXO (Key 30)
// ============================================================================

/// An unspent transaction output.
///
/// UTXOs are advisory only - the blockchain is the authoritative source.
/// They serve as hints for faster wallet restoration.
///
/// CDDL:
/// ```cddl
/// utxo = {
///   1 => txid-type,         ; previous txid
///   2 => uint32,            ; output index
///   3 => uint64,            ; amount in satoshis
///   4 => bstr .size 10..,   ; scriptPubKey
///   ? 5 => address-type,    ; address string
///   ? 100 => utxo-metadata
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Utxo {
    /// Transaction ID containing this output
    ///
    /// CBOR key: 1
    #[serde(rename = "1", with = "serde_bytes_array")]
    pub txid: [u8; 32],

    /// Output index within the transaction
    ///
    /// CBOR key: 2
    #[serde(rename = "2")]
    pub vout: u32,

    /// Amount in satoshis
    ///
    /// CBOR key: 3
    #[serde(rename = "3")]
    pub amount: u64,

    /// The scriptPubKey (locking script)
    ///
    /// CBOR key: 4
    #[serde(rename = "4", with = "serde_bytes")]
    pub script_pubkey: Vec<u8>,

    /// Human-readable address (optional)
    ///
    /// CBOR key: 5
    #[serde(rename = "5", skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    /// UTXO metadata
    ///
    /// CBOR key: 100
    #[serde(rename = "100", skip_serializing_if = "Option::is_none")]
    pub metadata: Option<UtxoMetadata>,
}

// ============================================================================
// METADATA STRUCTURES (Keys 100+)
// ============================================================================

/// Role type for descriptors and addresses.
///
/// - 0 = External (receive addresses)
/// - 1 = Internal (change addresses)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RoleType {
    /// External chain (receive addresses, BIP44 /0/*)
    External = 0,
    /// Internal chain (change addresses, BIP44 /1/*)
    Internal = 1,
}

/// Base metadata fields shared across all metadata types.
///
/// CDDL keys 100-199 are reserved for base metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BaseMetadata {
    /// User-friendly label (BIP329 compatible)
    ///
    /// CBOR key: 100
    #[serde(rename = "100", skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Block height when first used
    ///
    /// CBOR key: 101
    #[serde(rename = "101", skip_serializing_if = "Option::is_none")]
    pub birth_height: Option<u32>,

    /// Timestamp when first used (CBOR tag 1)
    ///
    /// CBOR key: 102
    #[serde(rename = "102", skip_serializing_if = "Option::is_none")]
    pub birth_time: Option<u64>,

    /// Last update timestamp
    ///
    /// CBOR key: 103
    #[serde(rename = "103", skip_serializing_if = "Option::is_none")]
    pub updated_time: Option<u64>,

    /// Software that created this backup
    ///
    /// CBOR key: 104
    #[serde(rename = "104", skip_serializing_if = "Option::is_none")]
    pub software: Option<String>,

    /// Device info (e.g., hardware wallet)
    ///
    /// CBOR key: 105
    #[serde(rename = "105", skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
}

/// Wallet-level metadata.
///
/// Extends base metadata with wallet-specific fields (keys 200-299).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WalletMetadata {
    /// Base metadata fields
    #[serde(flatten)]
    pub base: BaseMetadata,

    /// Master key fingerprint (4 bytes)
    ///
    /// CBOR key: 200
    #[serde(rename = "200", skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<[u8; 4]>,

    /// Default account index
    ///
    /// CBOR key: 201
    #[serde(rename = "201", skip_serializing_if = "Option::is_none")]
    pub default_account: Option<u32>,

    /// Wallet name
    ///
    /// CBOR key: 202
    #[serde(rename = "202", skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    // ========================================================================
    // FLORESTA-SPECIFIC FIELDS (Keys ≥1000)
    // ========================================================================

    /// Utreexo accumulator roots at time of backup
    ///
    /// Vendor key: 1000
    #[serde(rename = "1000", skip_serializing_if = "Option::is_none")]
    pub utreexo_roots: Option<Vec<[u8; 32]>>,

    /// Number of leaves in the Utreexo accumulator
    ///
    /// Vendor key: 1001
    #[serde(rename = "1001", skip_serializing_if = "Option::is_none")]
    pub utreexo_num_leaves: Option<u64>,
}

/// Account-level metadata.
///
/// Extends base metadata with account-specific fields (keys 300-399).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountMetadata {
    /// Base metadata fields
    #[serde(flatten)]
    pub base: BaseMetadata,

    /// Gap limit for address derivation
    ///
    /// CBOR key: 300
    #[serde(rename = "300", skip_serializing_if = "Option::is_none")]
    pub gap_limit: Option<u32>,

    /// Next external (receive) index to derive
    ///
    /// CBOR key: 301
    #[serde(rename = "301", skip_serializing_if = "Option::is_none")]
    pub next_external_index: Option<u32>,

    /// Next internal (change) index to derive
    ///
    /// CBOR key: 302
    #[serde(rename = "302", skip_serializing_if = "Option::is_none")]
    pub next_internal_index: Option<u32>,
}

/// Descriptor-level metadata.
///
/// Extends base metadata with descriptor-specific fields (keys 400-499).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DescriptorMetadata {
    /// Base metadata fields
    #[serde(flatten)]
    pub base: BaseMetadata,

    /// Role: 0 = receive (external), 1 = change (internal)
    ///
    /// CBOR key: 400
    #[serde(rename = "400", skip_serializing_if = "Option::is_none")]
    pub role: Option<RoleType>,

    /// Next index to derive for this descriptor
    ///
    /// CBOR key: 401
    #[serde(rename = "401", skip_serializing_if = "Option::is_none")]
    pub next_index: Option<u32>,

    /// Gap limit for this descriptor
    ///
    /// CBOR key: 402
    #[serde(rename = "402", skip_serializing_if = "Option::is_none")]
    pub gap_limit: Option<u32>,

    /// Whether this is a watch-only descriptor (no private keys)
    ///
    /// CBOR key: 403
    #[serde(rename = "403", skip_serializing_if = "Option::is_none")]
    pub watch_only: Option<bool>,
}

/// Transaction-level metadata.
///
/// Extends base metadata with transaction-specific fields (keys 500-599).
/// This is crucial for Floresta's rescan-free restoration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransactionMetadata {
    /// Base metadata fields
    #[serde(flatten)]
    pub base: BaseMetadata,

    /// Block height where transaction was confirmed
    ///
    /// CRITICAL for Floresta: enables restore without rescan!
    ///
    /// CBOR key: 500
    #[serde(rename = "500", skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u32>,

    /// Transaction fee in satoshis
    ///
    /// CBOR key: 501
    #[serde(rename = "501", skip_serializing_if = "Option::is_none")]
    pub fee: Option<u64>,

    /// Whether this transaction signals RBF
    ///
    /// CBOR key: 502
    #[serde(rename = "502", skip_serializing_if = "Option::is_none")]
    pub is_rbf: Option<bool>,

    /// Whether this is a CPFP parent transaction
    ///
    /// CBOR key: 503
    #[serde(rename = "503", skip_serializing_if = "Option::is_none")]
    pub is_cpfp_parent: Option<bool>,

    /// Whether this is a CPFP child transaction
    ///
    /// CBOR key: 504
    #[serde(rename = "504", skip_serializing_if = "Option::is_none")]
    pub is_cpfp_child: Option<bool>,

    // ========================================================================
    // FLORESTA-SPECIFIC FIELDS (Keys ≥1000)
    // ========================================================================

    /// Block hash where transaction was confirmed
    ///
    /// Vendor key: 1000
    #[serde(rename = "1000", skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<[u8; 32]>,

    /// Merkle proof for SPV verification
    ///
    /// Vendor key: 1001
    #[serde(rename = "1001", skip_serializing_if = "Option::is_none", with = "serde_bytes_opt")]
    pub merkle_proof: Option<Vec<u8>>,

    /// Transaction position in the block
    ///
    /// Vendor key: 1002
    #[serde(rename = "1002", skip_serializing_if = "Option::is_none")]
    pub position_in_block: Option<u32>,
}

/// UTXO-level metadata.
///
/// Extends base metadata with UTXO-specific fields (keys 600-699).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UtxoMetadata {
    /// Base metadata fields
    #[serde(flatten)]
    pub base: BaseMetadata,

    /// Whether this UTXO is spendable (confirmed)
    ///
    /// CBOR key: 600
    #[serde(rename = "600", skip_serializing_if = "Option::is_none")]
    pub spendable: Option<bool>,

    /// Whether this UTXO is frozen (user-locked)
    ///
    /// CBOR key: 601
    #[serde(rename = "601", skip_serializing_if = "Option::is_none")]
    pub frozen: Option<bool>,

    /// Whether this UTXO is from a coinbase transaction
    ///
    /// CBOR key: 602
    #[serde(rename = "602", skip_serializing_if = "Option::is_none")]
    pub is_coinbase: Option<bool>,

    /// Derivation index that generated this address
    ///
    /// CBOR key: 603
    #[serde(rename = "603", skip_serializing_if = "Option::is_none")]
    pub derivation_index: Option<u32>,

    /// Role type (external/internal)
    ///
    /// CBOR key: 604
    #[serde(rename = "604", skip_serializing_if = "Option::is_none")]
    pub role: Option<RoleType>,
}

/// Address-level metadata.
///
/// Extends base metadata with address-specific fields (keys 700-799).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AddressMetadata {
    /// Base metadata fields
    #[serde(flatten)]
    pub base: BaseMetadata,

    /// Derivation index for this address
    ///
    /// CBOR key: 700
    #[serde(rename = "700", skip_serializing_if = "Option::is_none")]
    pub derivation_index: Option<u32>,

    /// Role type (external/internal)
    ///
    /// CBOR key: 701
    #[serde(rename = "701", skip_serializing_if = "Option::is_none")]
    pub role: Option<RoleType>,

    /// Whether this address has been used
    ///
    /// CBOR key: 702
    #[serde(rename = "702", skip_serializing_if = "Option::is_none")]
    pub is_used: Option<bool>,

    /// Number of times this address was used
    ///
    /// CBOR key: 703
    #[serde(rename = "703", skip_serializing_if = "Option::is_none")]
    pub use_count: Option<u32>,
}

// ============================================================================
// SERDE HELPERS
// ============================================================================

/// Helper module for serializing fixed-size byte arrays with CBOR.
mod serde_bytes_array {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: Vec<u8> = serde_bytes::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom(format!("expected {} bytes", N)))
    }
}

/// Helper module for serializing optional byte vectors.
mod serde_bytes_opt {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_bytes::{ByteBuf, Bytes};

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => Bytes::new(b).serialize(serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<ByteBuf>::deserialize(deserializer).map(|opt| opt.map(|bb| bb.into_vec()))
    }
}


// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_type_values() {
        assert_eq!(NetworkType::Mainnet as u8, 0);
        assert_eq!(NetworkType::Testnet as u8, 1);
        assert_eq!(NetworkType::Signet as u8, 2);
        assert_eq!(NetworkType::Regtest as u8, 3);
    }

    #[test]
    fn test_role_type_values() {
        assert_eq!(RoleType::External as u8, 0);
        assert_eq!(RoleType::Internal as u8, 1);
    }

    #[test]
    fn test_wallet_payload_default_version() {
        let payload = WalletPayload::new(NetworkType::Mainnet);
        assert_eq!(payload.version, 1);
        assert_eq!(payload.network, NetworkType::Mainnet);
        assert!(payload.accounts.is_empty());
    }
}
