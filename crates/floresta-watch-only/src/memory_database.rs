//! An in-memory database to store addresses data. Being in-memory means this database is
//! volatile, and all data is lost after the database is dropped or the process is terminated.
//! It's not meant to use in production, but for the integrated testing framework
//!
//! For actual databases that can be used for production code, see [KvDatabase](crate::kv_database::KvDatabase).
use bitcoin::hashes::sha256;
use bitcoin::Txid;
use floresta_common::prelude::sync::RwLock;
use floresta_common::prelude::*;

use super::AddressCacheDatabase;
use super::CachedAddress;
use super::CachedTransaction;
use super::Stats;
#[derive(Debug, Default)]
struct Inner {
    addresses: HashMap<sha256::Hash, CachedAddress>,
    transactions: HashMap<Txid, CachedTransaction>,
    stats: Stats,
    height: u32,
    descriptors: Vec<String>,
}

#[derive(Debug)]
pub enum MemoryDatabaseError {
    PoisonedLock,
}
#[derive(Debug, Default)]
pub struct MemoryDatabase {
    inner: RwLock<Inner>,
}

type Result<T> = floresta_common::prelude::Result<T, MemoryDatabaseError>;

impl MemoryDatabase {
    fn get_inner(&self) -> Result<sync::RwLockReadGuard<'_, Inner>> {
        self.inner
            .read()
            .map_err(|_| MemoryDatabaseError::PoisonedLock)
    }
    fn get_inner_mut(&self) -> Result<sync::RwLockWriteGuard<'_, Inner>> {
        self.inner
            .write()
            .map_err(|_| MemoryDatabaseError::PoisonedLock)
    }
    pub fn new() -> MemoryDatabase {
        MemoryDatabase {
            inner: Default::default(),
        }
    }
}
impl AddressCacheDatabase for MemoryDatabase {
    type Error = MemoryDatabaseError;
    fn save(&self, address: &CachedAddress) {
        self.get_inner_mut()
            .map(|mut inner| {
                inner
                    .addresses
                    .insert(address.script_hash, address.to_owned())
            })
            .unwrap();
    }

    fn load(&self) -> Result<Vec<CachedAddress>> {
        Ok(self.get_inner()?.addresses.values().cloned().collect())
    }

    fn get_stats(&self) -> Result<super::Stats> {
        Ok(self.get_inner()?.stats.to_owned())
    }

    fn save_stats(&self, stats: &super::Stats) -> Result<()> {
        self.get_inner_mut().map(|mut inner| {
            inner.stats.clone_from(stats);
        })?;
        Ok(())
    }

    fn update(&self, address: &super::CachedAddress) {
        self.get_inner_mut()
            .map(|mut inner| {
                inner
                    .addresses
                    .entry(address.script_hash)
                    .and_modify(|addr| addr.clone_from(address));
            })
            .unwrap();
    }

    fn get_cache_height(&self) -> Result<u32> {
        Ok(self.get_inner()?.height)
    }

    fn set_cache_height(&self, height: u32) -> Result<()> {
        self.get_inner_mut()?.height = height;
        Ok(())
    }

    fn desc_save(&self, descriptor: &str) -> Result<()> {
        self.get_inner_mut().map(|mut inner| {
            inner.descriptors.push(descriptor.into());
        })
    }

    fn descs_get(&self) -> Result<Vec<String>> {
        Ok(self.get_inner()?.descriptors.to_owned())
    }

    fn desc_remove(&self, descriptor: &str) -> Result<bool> {
        let mut inner = self.get_inner_mut()?;
        let original_len = inner.descriptors.len();
        inner.descriptors.retain(|d| d != descriptor);
        Ok(inner.descriptors.len() != original_len)
    }

    fn get_transaction(&self, txid: &bitcoin::Txid) -> Result<super::CachedTransaction> {
        if let Some(tx) = self.get_inner()?.transactions.get(txid) {
            return Ok(tx.clone());
        }
        Err(MemoryDatabaseError::PoisonedLock)
    }

    fn save_transaction(&self, tx: &super::CachedTransaction) -> Result<()> {
        self.get_inner_mut()?
            .transactions
            .insert(tx.hash, tx.to_owned());
        Ok(())
    }

    fn list_transactions(&self) -> Result<Vec<Txid>> {
        Ok(self.get_inner()?.transactions.keys().copied().collect())
    }
}

#[cfg(test)]
mod test {
    use super::MemoryDatabase;
    use crate::AddressCacheDatabase;

    #[test]
    fn test_desc_remove() {
        let db = MemoryDatabase::new();
        let desc1 = "wpkh([00000000/84h/1h/0h]tpubDCvLwbJPseNux9EtPbrbA2tgDayzptK4HNkky14Cw6msjHuqyZCE18UDfuP2s7iXCbRLFMKnPKeLoK3hnffEzZPQc6jXRpAi6QEHo8vAqZy/0/*)#fyfc5f6k";
        let desc2 = "wpkh([00000000/84h/1h/0h]tpubDCvLwbJPseNux9EtPbrbA2tgDayzptK4HNkky14Cw6msjHuqyZCE18UDfuP2s7iXCbRLFMKnPKeLoK3hnffEzZPQc6jXRpAi6QEHo8vAqZy/1/*)#qv8xvmxa";

        // Initially empty
        assert!(db.descs_get().unwrap().is_empty());

        // Add two descriptors
        db.desc_save(desc1).unwrap();
        db.desc_save(desc2).unwrap();
        assert_eq!(db.descs_get().unwrap().len(), 2);

        // Remove first descriptor - should return true
        assert!(db.desc_remove(desc1).unwrap());
        let descs = db.descs_get().unwrap();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0], desc2);

        // Try to remove non-existent descriptor - should return false
        assert!(!db.desc_remove(desc1).unwrap());
        assert_eq!(db.descs_get().unwrap().len(), 1);

        // Remove second descriptor
        assert!(db.desc_remove(desc2).unwrap());
        assert!(db.descs_get().unwrap().is_empty());

        // Try to remove from empty list - should return false
        assert!(!db.desc_remove(desc1).unwrap());
    }

    #[test]
    fn test_desc_operations() {
        let db = MemoryDatabase::new();
        let desc = "wsh(sortedmulti(1,[54ff5a12/48h/1h/0h/2h]tpubDDw6pwZA3hYxcSN32q7a5ynsKmWr4BbkBNHydHPKkM4BZwUfiK7tQ26h7USm8kA1E2FvCy7f7Er7QXKF8RNptATywydARtzgrxuPDwyYv4x/<0;1>/*,[bcf969c0/48h/1h/0h/2h]tpubDEFdgZdCPgQBTNtGj4h6AehK79Jm4LH54JrYBJjAtHMLEAth7LuY87awx9ZMiCURFzFWhxToRJK6xp39aqeJWrG5nuW3eBnXeMJcvDeDxfp/<0;1>/*))#fuw35j0q";

        // Save and get descriptor
        db.desc_save(desc).unwrap();
        let descs = db.descs_get().unwrap();
        assert_eq!(descs.len(), 1);
        assert_eq!(descs[0], desc);

        // Remove and verify
        assert!(db.desc_remove(desc).unwrap());
        assert!(db.descs_get().unwrap().is_empty());
    }
}
