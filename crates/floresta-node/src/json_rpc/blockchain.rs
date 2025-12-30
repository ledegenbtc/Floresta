use bitcoin::block::Header;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::consensus::Encodable;
use bitcoin::constants::genesis_block;
use bitcoin::Address;
use bitcoin::Block;
use bitcoin::BlockHash;
use bitcoin::MerkleBlock;
use bitcoin::OutPoint;
use bitcoin::Script;
use bitcoin::ScriptBuf;
use bitcoin::Txid;
use corepc_types::v29::GetTxOut;
use corepc_types::ScriptPubkey;
use miniscript::descriptor::checksum;
use serde_json::json;
use serde_json::Value;
use tracing::debug;

use super::res::GetBlockResVerbose;
use super::res::GetBlockchainInfoRes;
use super::res::GetTxOutProof;
use super::res::JsonRpcError;
use super::server::RpcChain;
use super::server::RpcImpl;
use crate::json_rpc::res::RescanConfidence;

impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    async fn get_block_inner(&self, hash: BlockHash) -> Result<Block, JsonRpcError> {
        let is_genesis = self.chain.get_block_hash(0).unwrap().eq(&hash);

        if is_genesis {
            return Ok(genesis_block(self.network));
        }

        self.node
            .get_block(hash)
            .await
            .map_err(|e| JsonRpcError::Node(e.to_string()))
            .and_then(|block| block.ok_or(JsonRpcError::BlockNotFound))
    }

    /// Return the block that contains the given Txid
    pub fn get_block_by_txid(&self, txid: &Txid) -> Result<Block, JsonRpcError> {
        let height = self
            .wallet
            .get_height(txid)
            .ok_or(JsonRpcError::TxNotFound)?;
        let blockhash = self.chain.get_block_hash(height).unwrap();
        self.chain
            .get_block(&blockhash)
            .map_err(|_| JsonRpcError::BlockNotFound)
    }

    pub fn get_rescan_interval(
        &self,
        use_timestamp: bool,
        start: Option<u32>,
        stop: Option<u32>,
        confidence: Option<RescanConfidence>,
    ) -> Result<(u32, u32), JsonRpcError> {
        let start = start.unwrap_or(0u32);
        let stop = stop.unwrap_or(0u32);

        if use_timestamp {
            let confidence = confidence.unwrap_or(RescanConfidence::Medium);
            // `get_block_height_by_timestamp` already does the time validity checks.

            let start_height = self.get_block_height_by_timestamp(start, &confidence)?;

            let stop_height = self.get_block_height_by_timestamp(stop, &RescanConfidence::Exact)?;

            return Ok((start_height, stop_height));
        }

        let (tip, _) = self
            .chain
            .get_best_block()
            .map_err(|_| JsonRpcError::Chain)?;

        if stop > tip {
            return Err(JsonRpcError::InvalidRescanVal);
        }

        Ok((start, stop))
    }

    /// Retrieves the height of the block that was mined in the given timestamp.
    ///
    /// `timestamp` has an alias, 0 will directly refer to the network's genesis timestamp.
    pub fn get_block_height_by_timestamp(
        &self,
        timestamp: u32,
        confidence: &RescanConfidence,
    ) -> Result<u32, JsonRpcError> {
        /// Simple helper to avoid code reuse.
        fn get_block_time<BlockChain: RpcChain>(
            provider: &RpcImpl<BlockChain>,
            at: u32,
        ) -> Result<u32, JsonRpcError> {
            let hash = provider.get_block_hash(at)?;
            let block = provider.get_block_header(hash)?;
            Ok(block.time)
        }

        let genesis_timestamp = genesis_block(self.network).header.time;

        if timestamp == 0 || timestamp == genesis_timestamp {
            return Ok(0);
        };

        let (tip_height, _) = self
            .chain
            .get_best_block()
            .map_err(|_| JsonRpcError::BlockNotFound)?;

        let tip_time = get_block_time(self, tip_height)?;

        if timestamp < genesis_timestamp || timestamp > tip_time {
            return Err(JsonRpcError::InvalidTimestamp);
        }

        let adjusted_target = timestamp.saturating_sub(confidence.as_secs());

        let mut high = tip_height;
        let mut low = 0;
        let max_iters = tip_height.ilog2() + 1;
        for _ in 0..max_iters {
            let cut = (high + low) / 2;

            let block_timestamp = get_block_time(self, cut)?;

            if block_timestamp == adjusted_target {
                debug!("found a precise block; returning {cut}");
                return Ok(cut);
            }

            if high - low <= 2 {
                debug!("didn't find a precise block; returning {low}");
                return Ok(low);
            }

            if block_timestamp > adjusted_target {
                high = cut;
            } else {
                low = cut;
            }
        }

        // This is pretty much unreachable.
        Err(JsonRpcError::BlockNotFound)
    }
}

// blockchain rpcs
impl<Blockchain: RpcChain> RpcImpl<Blockchain> {
    // dumputxoutset

    // getbestblockhash
    pub(super) fn get_best_block_hash(&self) -> Result<BlockHash, JsonRpcError> {
        Ok(self.chain.get_best_block().unwrap().1)
    }

    // getblock
    pub(super) async fn get_block(
        &self,
        hash: BlockHash,
    ) -> Result<GetBlockResVerbose, JsonRpcError> {
        let block = self.get_block_inner(hash).await?;
        let tip = self.chain.get_height().map_err(|_| JsonRpcError::Chain)?;
        let height = self
            .chain
            .get_block_height(&hash)
            .map_err(|_| JsonRpcError::Chain)?
            .unwrap();

        let median_time_past = if height > 11 {
            let mut last_block_times: Vec<_> = ((height - 11)..height)
                .map(|h| {
                    self.chain
                        .get_block_header(&self.chain.get_block_hash(h).unwrap())
                        .unwrap()
                        .time
                })
                .collect();
            last_block_times.sort();
            last_block_times[5]
        } else {
            block.header.time
        };

        let block = GetBlockResVerbose {
            bits: serialize_hex(&block.header.bits),
            chainwork: block.header.work().to_string(),
            confirmations: (tip - height) + 1,
            difficulty: block.header.difficulty(self.chain.get_params()),
            hash: block.header.block_hash().to_string(),
            height,
            merkleroot: block.header.merkle_root.to_string(),
            nonce: block.header.nonce,
            previousblockhash: block.header.prev_blockhash.to_string(),
            size: block.total_size(),
            time: block.header.time,
            tx: block
                .txdata
                .iter()
                .map(|tx| tx.compute_txid().to_string())
                .collect(),
            version: block.header.version.to_consensus(),
            version_hex: serialize_hex(&block.header.version),
            weight: block.weight().to_wu() as usize,
            mediantime: median_time_past,
            n_tx: block.txdata.len(),
            nextblockhash: self
                .chain
                .get_block_hash(height + 1)
                .ok()
                .map(|h| h.to_string()),
            strippedsize: block.total_size(),
        };

        Ok(block)
    }

    pub(super) async fn get_block_serialized(
        &self,
        hash: BlockHash,
    ) -> Result<String, JsonRpcError> {
        let block = self.get_block_inner(hash).await?;
        Ok(serialize_hex(&block))
    }

    // getblockchaininfo
    pub(super) fn get_blockchain_info(&self) -> Result<GetBlockchainInfoRes, JsonRpcError> {
        let (height, hash) = self.chain.get_best_block().unwrap();
        let validated = self.chain.get_validation_index().unwrap();
        let ibd = self.chain.is_in_ibd();
        let latest_header = self.chain.get_block_header(&hash).unwrap();
        let latest_work = latest_header.work();
        let latest_block_time = latest_header.time;
        let leaf_count = self.chain.acc().leaves as u32;
        let root_count = self.chain.acc().roots.len() as u32;
        let root_hashes = self
            .chain
            .acc()
            .roots
            .into_iter()
            .map(|r| r.to_string())
            .collect();

        let validated_blocks = self.chain.get_validation_index().unwrap();

        let validated_percentage = if height != 0 {
            validated_blocks as f32 / height as f32
        } else {
            0.0
        };

        Ok(GetBlockchainInfoRes {
            best_block: hash.to_string(),
            height,
            ibd,
            validated,
            latest_work: latest_work.to_string(),
            latest_block_time,
            leaf_count,
            root_count,
            root_hashes,
            chain: self.network.to_string(),
            difficulty: latest_header.difficulty(self.chain.get_params()) as u64,
            progress: validated_percentage,
        })
    }

    // getblockcount
    pub(super) fn get_block_count(&self) -> Result<u32, JsonRpcError> {
        Ok(self.chain.get_height().unwrap())
    }

    // getblockfilter
    // getblockfrompeer (just call getblock)

    // getblockhash
    pub(super) fn get_block_hash(&self, height: u32) -> Result<BlockHash, JsonRpcError> {
        self.chain
            .get_block_hash(height)
            .map_err(|_| JsonRpcError::BlockNotFound)
    }

    // getblockheader
    pub(super) fn get_block_header(&self, hash: BlockHash) -> Result<Header, JsonRpcError> {
        self.chain
            .get_block_header(&hash)
            .map_err(|_| JsonRpcError::BlockNotFound)
    }

    // getblockstats
    // getchainstates
    // getchaintips
    // getchaintxstats
    // getdeploymentinfo
    // getdifficulty
    // getmempoolancestors
    // getmempooldescendants
    // getmempoolentry
    // getmempoolinfo
    // getrawmempool

    /// Check if the script is anchor type
    fn is_anchor_type(script: &Script) -> bool {
        script.as_bytes().starts_with(&[0x51, 0x02, 0x4e, 0x73])
    }

    /// Returns a label about the scriptPubKey type
    /// (pubkey, pubkeyhash, multisig, nulldata, scripthash, witness_v0_keyhash, witness_v0_scripthash, witness_v1_taproot, anchor, nonstandard)
    fn get_script_type_label(script: &Script) -> &'static str {
        if script.is_p2pk() {
            return "pubkey";
        }

        if script.is_p2pkh() {
            return "pubkeyhash";
        }

        if script.is_multisig() {
            return "multisig";
        }

        if script.is_op_return() {
            return "nulldata";
        }

        if script.is_p2sh() {
            return "scripthash";
        }

        if script.is_p2wpkh() {
            return "witness_v0_keyhash";
        }

        if script.is_p2wsh() {
            return "witness_v0_scripthash";
        }

        if script.is_p2tr() {
            return "witness_v1_taproot";
        }

        if Self::is_anchor_type(script) {
            return "anchor";
        }

        "nonstandard"
    }

    fn get_script_type_descriptor(script: &Script, address: &Option<Address>) -> String {
        let get_addr_str = || {
            address
                .as_ref()
                .expect("address should be Some")
                .to_string()
        };

        if script.is_p2pk() {
            let addr = get_addr_str();
            return format!("pk({addr}");
        }

        if let Some(addr) = address {
            return format!("addr({addr})");
        }

        if script.is_op_return() {
            let hex = script.to_hex_string();
            return format!("raw({hex})");
        }

        if Self::is_anchor_type(script) {
            let addr = get_addr_str();
            return format!("addr({addr})");
        }

        let hex = script.to_hex_string();
        format!("raw({hex})")
    }

    /// Parses the serialized opcodes in a [ScriptBuf] as numbers and it's hashes.
    /// This differs from `ScriptBuf::to_asm_string` in that, `rust-bitcoin` will
    /// show the the human representation of the opcode. It does not omit the number representations of
    /// `OP_PUSHDATA_<N>` and `OP_PUSHBYTE<N>`. This method do the opposite: it not show the human
    /// representation and omit the last opcodes, so it can be compliant with bitcoin-core.
    /// For reference see <https://en.bitcoin.it/wiki/Script#Opcodes>
    fn to_core_asm_string(script: &ScriptBuf) -> Result<String, JsonRpcError> {
        let mut asm = vec![];
        let bytes = script.as_bytes();
        let mut i = 0usize;

        // little reused helper to hex string
        let to_hex_string = |r: &[u8]| r.iter().map(|b| format!("{b:02x}")).collect::<String>();

        while i < bytes.len() {
            let byte = bytes[i];
            i += 1;

            match byte {
                // OP_0
                0x00 => asm.push(format!("{}", 0)),
                // OP_PUSHDATA_<N>: The next N bytes is data to be pushed onto the stack
                0x01..=0x4b => {
                    let pushed_bytes = byte as usize;
                    let hex = to_hex_string(&bytes[i..i + pushed_bytes]);
                    asm.push(hex);
                    i += pushed_bytes;
                }
                // OP_PUSHBYTE1: the next byte contains the number of bytes to be pushed onto the stack.
                0x4c => {
                    let pushed_bytes = bytes[i] as usize;
                    i += 1;
                    let hex = to_hex_string(&bytes[i..i + pushed_bytes]);
                    asm.push(hex);
                    i += pushed_bytes;
                }
                // OP_PUSHBYTE2: the next two bytes contain the number of bytes to be pushed onto the stack in little endian order.
                0x4d => {
                    let pushed_bytes = u16::from_le_bytes([bytes[i], bytes[i + 1]]) as usize;
                    i += 2;
                    let hex = to_hex_string(&bytes[i..i + pushed_bytes]);
                    asm.push(hex);
                    i += pushed_bytes;
                }
                // OP_PUSHBYTE4: the next four bytes contain the number of bytes to be pushed onto the stack in little endian order.
                0x4e => {
                    let pushed_bytes =
                        u32::from_le_bytes([bytes[i], bytes[i + 1], bytes[i + 2], bytes[i + 3]])
                            as usize;
                    i += 4;
                    let hex = to_hex_string(&bytes[i..i + pushed_bytes]);
                    asm.push(hex);
                    i += pushed_bytes;
                }
                // OP_1 to OP_16
                0x51..=0x60 => {
                    // 0x50 is OP_RESERVED
                    let reserved = 0x50;
                    asm.push(format!("{}", byte - reserved));
                }
                // Any other opcode that should  be pushed
                another_one => {
                    asm.push(format!("{another_one:02x}"));
                }
            }
        }

        Ok(asm.join(" "))
    }

    /// gettxout: returns details about an unspent transaction output.
    pub(super) fn get_tx_out(
        &self,
        txid: Txid,
        outpoint: u32,
        _include_mempool: bool,
    ) -> Result<Option<GetTxOut>, JsonRpcError> {
        let res = match (
            self.wallet.get_transaction(&txid),
            self.wallet.get_height(&txid),
            self.wallet.get_utxo(&OutPoint {
                txid,
                vout: outpoint,
            }),
        ) {
            (Some(cached_tx), Some(height), Some(txout)) => {
                let is_coinbase = cached_tx.tx.is_coinbase();
                let Ok((bestblock_height, bestblock_hash)) = self.chain.get_best_block() else {
                    return Err(JsonRpcError::BlockNotFound);
                };

                let script = txout.script_pubkey.as_script();
                let network = self.chain.get_params().network;
                let address = Address::from_script(script, network).ok();

                let base_descriptor = Self::get_script_type_descriptor(script, &address);
                let descriptor: Option<String> = match checksum::desc_checksum(&base_descriptor) {
                    Ok(checksum) => Some(format!("{base_descriptor}#{checksum}")),
                    Err(_) => None,
                };

                let asm = Self::to_core_asm_string(&txout.script_pubkey)?;
                let script_pubkey = ScriptPubkey {
                    asm,
                    hex: txout.script_pubkey.to_hex_string(),
                    descriptor,
                    address: address.as_ref().map(ToString::to_string),
                    type_: Self::get_script_type_label(script).to_string(),
                    // Deprecated in Bitcoin Core v22, require flags in Bitcoin Core.
                    // Set to None as not required for consensus.
                    addresses: None,
                    required_signatures: None,
                };

                Some(GetTxOut {
                    best_block: bestblock_hash.to_string(),
                    confirmations: bestblock_height - height + 1,
                    value: txout.value.to_btc(),
                    script_pubkey,
                    coinbase: is_coinbase,
                })
            }
            _ => None,
        };
        Ok(res)
    }

    /// Computes the necessary information for the RPC `gettxoutproof [txids] blockhash (optional)`
    ///
    /// This function has two paths, when blockhash is inserted and when isn't.
    ///
    /// Specifying the blockhash will make this function go after the block and search
    /// for the transactions inside it, building a merkle proof from the block with its
    /// indexes. Not specifying will redirect it to search for the merkle proof on our
    /// watch-only wallet which may not have the transaction cached.
    ///
    /// Not finding one of the specified transactions will raise [`JsonRpcError::TxNotFound`].
    pub(super) async fn get_txout_proof(
        &self,
        tx_ids: &[Txid],
        blockhash: Option<BlockHash>,
    ) -> Result<GetTxOutProof, JsonRpcError> {
        let block = match blockhash {
            Some(blockhash) => self.get_block_inner(blockhash).await?,
            // Using the first Txid to get the block should be fine since they are expected to all
            // live in the same block, otherwise, theres no way they have a common proof.
            None => self.get_block_by_txid(&tx_ids[0])?,
        };

        // Before building the merkle block we try to remove all txids
        // that aren't present in the block we found, meaning that
        // at least one of the txids doesn't belong to the block which
        // in case needs to make the command fails.
        //
        // this makes the use MerkleBlock::from_block_with_predicate useless.
        let targeted_txids: Vec<Txid> = block
            .txdata
            .iter()
            .filter_map(|tx| {
                let txid = tx.compute_txid();
                if tx_ids.contains(&txid) {
                    Some(txid)
                } else {
                    None
                }
            })
            .collect();

        if targeted_txids.len() != tx_ids.len() {
            return Err(JsonRpcError::TxNotFound);
        };

        let merkle_block = MerkleBlock::from_block_with_predicate(&block, |tx| tx_ids.contains(tx));
        let mut bytes: Vec<u8> = Vec::new();
        merkle_block
            .consensus_encode(&mut bytes)
            .expect("This will raise if a writer error happens");
        Ok(GetTxOutProof(bytes))
    }

    // gettxoutsetinfo
    // gettxspendigprevout
    // importmempool
    // loadtxoutset
    // preciousblock
    // pruneblockchain
    // savemempool
    // scanblocks
    // scantxoutset
    // verifychain
    // verifytxoutproof

    // floresta flavored rpcs. These are not part of the bitcoin rpc spec
    // findtxout
    pub(super) async fn find_tx_out(
        &self,
        txid: Txid,
        vout: u32,
        script: ScriptBuf,
        height: u32,
    ) -> Result<Value, JsonRpcError> {
        if let Some(txout) = self.wallet.get_utxo(&OutPoint { txid, vout }) {
            return Ok(serde_json::to_value(txout).unwrap());
        }

        // if we are on IBD, we don't have any filters to find this txout.
        if self.chain.is_in_ibd() {
            return Err(JsonRpcError::InInitialBlockDownload);
        }

        // can't proceed without block filters
        let Some(cfilters) = self.block_filter_storage.as_ref() else {
            return Err(JsonRpcError::NoBlockFilters);
        };

        self.wallet.cache_address(script.clone());
        let filter_key = script.to_bytes();
        let candidates = cfilters
            .match_any(
                vec![filter_key.as_slice()],
                Some(height),
                None,
                self.chain.clone(),
            )
            .map_err(|e| JsonRpcError::Filters(e.to_string()))?;

        for candidate in candidates {
            let candidate = self.node.get_block(candidate).await;
            let candidate = match candidate {
                Err(e) => {
                    return Err(JsonRpcError::Node(e.to_string()));
                }
                Ok(None) => {
                    return Err(JsonRpcError::Node(format!(
                        "BUG: block {candidate:?} is a match in our filters, but we can't get it?"
                    )));
                }
                Ok(Some(candidate)) => candidate,
            };

            let Ok(Some(height)) = self.chain.get_block_height(&candidate.block_hash()) else {
                return Err(JsonRpcError::BlockNotFound);
            };

            self.wallet.block_process(&candidate, height);
        }

        let val = match self.get_tx_out(txid, vout, false)? {
            Some(gettxout) => json!(gettxout),
            None => json!({}),
        };
        Ok(val)
    }

    // getroots
    pub(super) fn get_roots(&self) -> Result<Vec<String>, JsonRpcError> {
        let hashes = self.chain.get_root_hashes();
        Ok(hashes.iter().map(|h| h.to_string()).collect())
    }

    pub(super) fn list_descriptors(&self) -> Result<Vec<String>, JsonRpcError> {
        let descriptors = self
            .wallet
            .get_descriptors()
            .map_err(|e| JsonRpcError::Wallet(e.to_string()))?;
        Ok(descriptors)
    }

    pub(super) fn remove_descriptor(&self, descriptor: String) -> Result<bool, JsonRpcError> {
        self.wallet
            .remove_descriptor(&descriptor)
            .map_err(|e| JsonRpcError::Wallet(e.to_string()))
    }

    pub(super) fn get_wallet_info(&self) -> Result<WalletInfo, JsonRpcError> {
        let stats = self
            .wallet
            .get_stats()
            .map_err(|e| JsonRpcError::Wallet(e.to_string()))?;

        let descriptors = self
            .wallet
            .get_descriptors()
            .map_err(|e| JsonRpcError::Wallet(e.to_string()))?;

        // Convert satoshis to BTC
        let balance_btc = stats.balance as f64 / 100_000_000.0;

        Ok(WalletInfo {
            walletname: "default".to_string(),
            balance: balance_btc,
            unconfirmed_balance: 0.0, // Floresta doesn't track unconfirmed separately yet
            txcount: stats.transaction_count,
            private_keys_enabled: false, // Always false for watch-only
            descriptors: true,           // Floresta uses descriptors
            utxo_count: stats.utxo_count,
            address_count: stats.address_count,
            descriptor_count: descriptors.len(),
            derivation_index: stats.derivation_index,
        })
    }

    pub(super) fn list_transactions(
        &self,
        count: Option<usize>,
        skip: Option<usize>,
    ) -> Result<Vec<TransactionInfo>, JsonRpcError> {
        let mut transactions = Vec::new();

        // Get current tip height for confirmations calculation
        let tip_height = self.chain.get_height().unwrap_or(0);

        // Get all cached addresses and their histories
        let addresses = self.wallet.get_cached_addresses();
        let mut seen_txids = std::collections::HashSet::new();

        for address in addresses {
            let script_hash = floresta_common::get_spk_hash(&address);
            if let Some(history) = self.wallet.get_address_history(&script_hash) {
                for cached_tx in history {
                    // Avoid duplicates
                    if !seen_txids.insert(cached_tx.hash) {
                        continue;
                    }

                    // Calculate confirmations
                    let confirmations = if cached_tx.height > 0 {
                        (tip_height.saturating_sub(cached_tx.height) + 1) as i32
                    } else {
                        0 // Unconfirmed
                    };

                    // Get block hash and time if confirmed
                    let (blockhash, blocktime) = if cached_tx.height > 0 {
                        let hash = self.chain.get_block_hash(cached_tx.height).ok();
                        let time = hash
                            .and_then(|h| self.chain.get_block_header(&h).ok())
                            .map(|header| header.time);
                        (hash.map(|h| h.to_string()), time)
                    } else {
                        (None, None)
                    };

                    // Calculate amount (positive for receive, negative for send)
                    // For watch-only, we primarily track receives
                    let amount_sats = cached_tx
                        .tx
                        .output
                        .iter()
                        .filter(|out| {
                            let spk_hash = floresta_common::get_spk_hash(&out.script_pubkey);
                            self.wallet.is_address_cached(&spk_hash)
                        })
                        .map(|out| out.value.to_sat())
                        .sum::<u64>();

                    let amount_btc = amount_sats as f64 / 100_000_000.0;

                    // Use block time or current time for unconfirmed
                    let time = blocktime.unwrap_or_else(|| {
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as u32)
                            .unwrap_or(0)
                    });

                    transactions.push(TransactionInfo {
                        txid: cached_tx.hash.to_string(),
                        category: "receive".to_string(), // Watch-only primarily tracks receives
                        amount: amount_btc,
                        confirmations,
                        blockhash,
                        blockheight: if cached_tx.height > 0 {
                            Some(cached_tx.height)
                        } else {
                            None
                        },
                        blocktime,
                        time,
                        timereceived: time,
                    });
                }
            }
        }

        // Sort by confirmations ascending (newest first, then unconfirmed)
        transactions.sort_by(|a, b| a.confirmations.cmp(&b.confirmations));

        // Apply skip and count
        let skip = skip.unwrap_or(0);
        let count = count.unwrap_or(10);

        let result: Vec<TransactionInfo> = transactions
            .into_iter()
            .skip(skip)
            .take(count)
            .collect();

        Ok(result)
    }

    pub(super) fn list_addresses(&self) -> Result<Vec<AddressInfo>, JsonRpcError> {
        let mut addresses = Vec::new();

        let cached_addresses = self.wallet.get_cached_addresses();
        for script in cached_addresses {
            let script_hash = floresta_common::get_spk_hash(&script);
            let balance = self.wallet.get_address_balance(&script_hash).unwrap_or(0);
            let tx_count = self
                .wallet
                .get_address_history(&script_hash)
                .map(|h| h.len())
                .unwrap_or(0);

            // Try to convert script to address string
            let address = bitcoin::Address::from_script(&script, self.chain.get_params())
                .map(|a| a.to_string())
                .ok();

            addresses.push(AddressInfo {
                script_hash: script_hash.to_string(),
                address,
                balance,
                tx_count,
            });
        }

        // Sort by balance descending
        addresses.sort_by(|a, b| b.balance.cmp(&a.balance));

        Ok(addresses)
    }

    pub(super) fn list_unspent(
        &self,
        minconf: Option<u32>,
        maxconf: Option<u32>,
    ) -> Result<Vec<UnspentOutput>, JsonRpcError> {
        let mut utxos = Vec::new();

        let minconf = minconf.unwrap_or(1);
        let maxconf = maxconf.unwrap_or(9999999);

        // Get current tip height for confirmations calculation
        let tip_height = self.chain.get_height().unwrap_or(0);

        // Iterate over all cached addresses and collect their UTXOs
        let cached_addresses = self.wallet.get_cached_addresses();
        for script in cached_addresses {
            let script_hash = floresta_common::get_spk_hash(&script);

            if let Some(address_utxos) = self.wallet.get_address_utxos(&script_hash) {
                for (txout, outpoint) in address_utxos {
                    // Get the height of the transaction
                    let height = self.wallet.get_height(&outpoint.txid).unwrap_or(0);

                    // Calculate confirmations
                    let confirmations = if height > 0 {
                        (tip_height.saturating_sub(height) + 1) as i32
                    } else {
                        0
                    };

                    // Filter by confirmation count
                    if (confirmations as u32) < minconf || (confirmations as u32) > maxconf {
                        continue;
                    }

                    // Convert script to address
                    let address =
                        bitcoin::Address::from_script(&script, self.chain.get_params())
                            .map(|a| a.to_string())
                            .ok();

                    // Amount in BTC
                    let amount = txout.value.to_sat() as f64 / 100_000_000.0;

                    utxos.push(UnspentOutput {
                        txid: outpoint.txid.to_string(),
                        vout: outpoint.vout,
                        address,
                        script_pub_key: txout.script_pubkey.to_hex_string(),
                        amount,
                        confirmations,
                        spendable: false, // Watch-only wallet
                        solvable: true,   // We know the scriptPubKey
                        safe: confirmations >= 1, // Confirmed = safe
                    });
                }
            }
        }

        // Sort by amount descending
        utxos.sort_by(|a, b| b.amount.partial_cmp(&a.amount).unwrap());

        Ok(utxos)
    }
}

/// Information about the watch-only wallet
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WalletInfo {
    /// The wallet name (always "default" for Floresta)
    pub walletname: String,
    /// The total confirmed balance in BTC
    pub balance: f64,
    /// The total unconfirmed balance in BTC
    pub unconfirmed_balance: f64,
    /// The total number of transactions in the wallet
    pub txcount: usize,
    /// Whether private keys are enabled (always false for watch-only)
    pub private_keys_enabled: bool,
    /// Whether the wallet uses descriptors
    pub descriptors: bool,
    // Floresta-specific fields
    /// Number of unspent transaction outputs
    pub utxo_count: usize,
    /// Number of addresses being monitored
    pub address_count: usize,
    /// Number of descriptors loaded
    pub descriptor_count: usize,
    /// Current derivation index
    pub derivation_index: u32,
}

/// Information about a transaction in the wallet
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransactionInfo {
    /// The transaction id
    pub txid: String,
    /// The transaction category (send, receive)
    pub category: String,
    /// The amount in BTC (negative for send)
    pub amount: f64,
    /// The number of confirmations (0 for unconfirmed, -1 for conflicted)
    pub confirmations: i32,
    /// The block hash containing the transaction (if confirmed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockhash: Option<String>,
    /// The block height containing the transaction (if confirmed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockheight: Option<u32>,
    /// The block time (if confirmed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocktime: Option<u32>,
    /// The transaction time
    pub time: u32,
    /// The time received by the wallet
    pub timereceived: u32,
}

/// Information about an address in the watch-only wallet
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AddressInfo {
    /// Script hash (Electrum format - reversed SHA256 of scriptPubKey)
    pub script_hash: String,
    /// Bitcoin address string (if the script is a standard address type)
    pub address: Option<String>,
    /// Current balance in satoshis
    pub balance: u64,
    /// Number of transactions involving this address
    pub tx_count: usize,
}

/// Information about an unspent transaction output (UTXO)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct UnspentOutput {
    /// The transaction id
    pub txid: String,
    /// The output index
    pub vout: u32,
    /// The bitcoin address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The scriptPubKey hex
    #[serde(rename = "scriptPubKey")]
    pub script_pub_key: String,
    /// The output value in BTC
    pub amount: f64,
    /// The number of confirmations
    pub confirmations: i32,
    /// Whether we have the keys to spend this output (always false for watch-only)
    pub spendable: bool,
    /// Whether we know how to spend this output
    pub solvable: bool,
    /// Whether this output is safe to spend
    pub safe: bool,
}
