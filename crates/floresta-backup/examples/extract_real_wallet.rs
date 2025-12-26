//! Extract data from a real Floresta wallet
//!
//! Run with:
//! ```
//! cargo run -p floresta-backup --example extract_real_wallet
//! ```

use floresta_backup::{ExtractOptions, NetworkType, WalletExtractor};
use floresta_watch_only::kv_database::KvDatabase;
use floresta_watch_only::AddressCache;

fn main() {
    // Default signet wallet path
    let home = std::env::var("HOME").expect("HOME not set");
    let wallet_path = format!("{}/.floresta/signet", home);

    println!("Loading wallet from: {}", wallet_path);

    // Load the KvDatabase
    let database = match KvDatabase::new(wallet_path.clone()) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Failed to open wallet database: {}", e);
            eprintln!("Make sure florestad is not running or the path is correct");
            return;
        }
    };

    // Create AddressCache from database
    let wallet = AddressCache::new(database);

    // Get wallet stats
    match wallet.get_stats() {
        Ok(stats) => {
            println!("\n========== WALLET STATS ==========\n");
            println!("  Balance: {} sats ({:.8} BTC)", stats.balance, stats.balance as f64 / 100_000_000.0);
            println!("  Addresses: {}", stats.address_count);
            println!("  Transactions: {}", stats.transaction_count);
            println!("  UTXOs: {}", stats.utxo_count);
            println!("  Cache Height: {}", stats.cache_height);
            println!("  Derivation Index: {}", stats.derivation_index);
        }
        Err(e) => {
            eprintln!("Failed to get stats: {}", e);
        }
    }

    // Get descriptors
    match wallet.get_descriptors() {
        Ok(descriptors) => {
            println!("\n========== DESCRIPTORS ==========\n");
            if descriptors.is_empty() {
                println!("  (no descriptors found)");
            } else {
                for (i, desc) in descriptors.iter().enumerate() {
                    let truncated = if desc.len() > 80 {
                        format!("{}...", &desc[..80])
                    } else {
                        desc.clone()
                    };
                    println!("  [{}] {}", i, truncated);
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to get descriptors: {}", e);
        }
    }

    // Extract full wallet data
    let extractor = WalletExtractor::new(NetworkType::Signet)
        .with_options(ExtractOptions::full());

    match extractor.extract_from_wallet(&wallet) {
        Ok(payload) => {
            println!("\n========== EXTRACTED PAYLOAD ==========\n");

            // Transactions
            println!("TRANSACTIONS:");
            if let Some(txs) = &payload.transactions {
                if txs.is_empty() {
                    println!("  (none)");
                } else {
                    for tx in txs.iter().take(10) {
                        let txid_hex = hex::encode(&tx.txid);
                        let height = tx.metadata.as_ref().and_then(|m| m.block_height).unwrap_or(0);
                        println!("  {}...{} @ block {}", &txid_hex[..8], &txid_hex[56..], height);
                    }
                    if txs.len() > 10 {
                        println!("  ... and {} more", txs.len() - 10);
                    }
                }
            } else {
                println!("  (none)");
            }

            // UTXOs
            println!("\nUTXOS:");
            if let Some(utxos) = &payload.utxos {
                if utxos.is_empty() {
                    println!("  (none)");
                } else {
                    let mut total: u64 = 0;
                    for utxo in utxos.iter().take(10) {
                        let txid_hex = hex::encode(&utxo.txid);
                        println!("  {}...{}:{} = {} sats",
                            &txid_hex[..8], &txid_hex[56..], utxo.vout, utxo.amount);
                        total += utxo.amount;
                    }
                    if utxos.len() > 10 {
                        for utxo in utxos.iter().skip(10) {
                            total += utxo.amount;
                        }
                        println!("  ... and {} more", utxos.len() - 10);
                    }
                    println!("\n  TOTAL: {} sats ({:.8} BTC)", total, total as f64 / 100_000_000.0);
                }
            } else {
                println!("  (none)");
            }
        }
        Err(e) => {
            eprintln!("Failed to extract wallet: {}", e);
            eprintln!("This might happen if the wallet has no descriptors configured.");
        }
    }

    println!("\n====================================\n");
}
