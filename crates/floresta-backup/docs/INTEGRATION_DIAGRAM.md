# Diagrama de Integração - Floresta Backup

## 1. Arquitetura Atual do Floresta

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              florestad                                   │
│                         (Node Principal)                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────────────┐ │
│  │floresta-chain│   │ floresta-wire│   │     floresta-electrum        │ │
│  │  (Consenso)  │   │    (P2P)     │   │   (Servidor Electrum)        │ │
│  └──────────────┘   └──────────────┘   └──────────────────────────────┘ │
│         │                  │                        │                    │
│         └──────────────────┼────────────────────────┘                    │
│                            │                                             │
│                            ▼                                             │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    floresta-watch-only                            │   │
│  │                   (Watch-Only Wallet)                             │   │
│  ├──────────────────────────────────────────────────────────────────┤   │
│  │                                                                   │   │
│  │  AddressCache<KvDatabase>                                        │   │
│  │  ├── descriptors: Vec<String>                                    │   │
│  │  ├── transactions: HashMap<Txid, CachedTransaction>              │   │
│  │  ├── addresses: HashMap<Hash, CachedAddress>                     │   │
│  │  └── stats: Stats                                                │   │
│  │                                                                   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                            │                                             │
│                            │ Persistência                                │
│                            ▼                                             │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                         sled (KV Store)                           │   │
│  │  Buckets: addresses, transactions, stats                         │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## 2. Integração do floresta-backup

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              florestad                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                    floresta-watch-only                            │   │
│  │                   (Watch-Only Wallet)                             │   │
│  └───────────────────────────┬──────────────────────────────────────┘   │
│                              │                                           │
│                              │ AddressCache<D>                          │
│                              │                                           │
│          ┌───────────────────┼───────────────────┐                      │
│          │                   │                   │                      │
│          ▼                   ▼                   ▼                      │
│  ┌───────────────┐   ┌───────────────┐   ┌───────────────────────────┐ │
│  │  get_descriptors │   │get_transaction│   │   list_transactions     │ │
│  │  → Vec<String>   │   │→CachedTx     │   │   → Vec<Txid>           │ │
│  └───────────────┘   └───────────────┘   └───────────────────────────┘ │
│          │                   │                   │                      │
│          └───────────────────┼───────────────────┘                      │
│                              │                                           │
│                              ▼                                           │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                     floresta-backup                               │   │
│  │                    (NOVO CRATE)                                   │   │
│  ├──────────────────────────────────────────────────────────────────┤   │
│  │                                                                   │   │
│  │  ┌─────────────────────────────────────────────────────────────┐ │   │
│  │  │                    extractor.rs                              │ │   │
│  │  │  extract_from_wallet(cache: &AddressCache) → WalletPayload  │ │   │
│  │  └─────────────────────────────────────────────────────────────┘ │   │
│  │                              │                                    │   │
│  │                              ▼                                    │   │
│  │  ┌─────────────────────────────────────────────────────────────┐ │   │
│  │  │                      cbor.rs                                 │ │   │
│  │  │  serialize(payload: &WalletPayload) → Vec<u8>               │ │   │
│  │  └─────────────────────────────────────────────────────────────┘ │   │
│  │                              │                                    │   │
│  │                              ▼                                    │   │
│  │  ┌─────────────────────────────────────────────────────────────┐ │   │
│  │  │                     crypto.rs                                │ │   │
│  │  │  encrypt(data: &[u8], password: &str) → EncryptedEnvelope   │ │   │
│  │  └─────────────────────────────────────────────────────────────┘ │   │
│  │                              │                                    │   │
│  │                              ▼                                    │   │
│  │                      Backup Criptografado                         │   │
│  │                         (arquivo .bewp)                           │   │
│  │                                                                   │   │
│  └──────────────────────────────────────────────────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

## 3. Fluxo de Exportação

```
┌─────────────────┐
│  AddressCache   │
│  (wallet ativa) │
└────────┬────────┘
         │
         │ 1. get_descriptors()
         ▼
┌─────────────────┐
│ Vec<String>     │  "wpkh([fp/84'/0'/0']xpub.../0/*)"
│ (descriptors)   │  "wpkh([fp/84'/0'/0']xpub.../1/*)"
└────────┬────────┘
         │
         │ 2. list_transactions() + get_transaction()
         ▼
┌─────────────────────────────────────────────────────┐
│ Vec<CachedTransaction>                               │
│ ┌─────────────────────────────────────────────────┐ │
│ │ tx: Transaction (raw bytes)                      │ │
│ │ height: 800000          ← block_height (500)     │ │
│ │ position: 42            ← position_in_block (1002)│
│ │ merkle_block: Some(...)  ← merkle_proof (1001)   │ │
│ │ hash: Txid              ← txid (1)               │ │
│ └─────────────────────────────────────────────────┘ │
└────────┬────────────────────────────────────────────┘
         │
         │ 3. Converter para WalletPayload
         ▼
┌─────────────────────────────────────────────────────┐
│ WalletPayload (types.rs)                            │
│ ┌─────────────────────────────────────────────────┐ │
│ │ version: 1                                       │ │
│ │ network: Mainnet                                 │ │
│ │ accounts: [Account { descriptors: [...] }]       │ │
│ │ transactions: [Transaction { txid, metadata }]   │ │
│ │ metadata: { software: "Floresta 0.x.x" }        │ │
│ └─────────────────────────────────────────────────┘ │
└────────┬────────────────────────────────────────────┘
         │
         │ 4. Serializar CBOR
         ▼
┌─────────────────┐
│   Vec<u8>       │  (CBOR binário, ~50KB para 1000 txs)
│  (cbor data)    │
└────────┬────────┘
         │
         │ 5. Criptografar
         ▼
┌─────────────────────────────────────────────────────┐
│ EncryptedEnvelope                                    │
│ ┌─────────────────────────────────────────────────┐ │
│ │ magic: "BEWP"                                    │ │
│ │ version: 1                                       │ │
│ │ salt: [16 bytes random]                          │ │
│ │ nonce: [12 bytes random]                         │ │
│ │ ciphertext: [encrypted CBOR]                     │ │
│ │ tag: [16 bytes auth]                             │ │
│ └─────────────────────────────────────────────────┘ │
└────────┬────────────────────────────────────────────┘
         │
         │ 6. Salvar arquivo
         ▼
┌─────────────────┐
│  backup.bewp    │
│  (arquivo)      │
└─────────────────┘
```

## 4. Fluxo de Importação (Restore sem Rescan)

```
┌─────────────────┐
│  backup.bewp    │
│  (arquivo)      │
└────────┬────────┘
         │
         │ 1. Ler arquivo
         ▼
┌─────────────────┐
│EncryptedEnvelope│
└────────┬────────┘
         │
         │ 2. Decriptar (senha do usuário)
         ▼
┌─────────────────┐
│   Vec<u8>       │
│  (cbor data)    │
└────────┬────────┘
         │
         │ 3. Deserializar CBOR
         ▼
┌─────────────────────────────────────────────────────┐
│ WalletPayload                                        │
│ ┌─────────────────────────────────────────────────┐ │
│ │ accounts[0].descriptors[0].descriptor           │ │
│ │   → "wpkh([fp/84'/0'/0']xpub.../0/*)"          │ │
│ │                                                  │ │
│ │ transactions[0].metadata.block_height           │ │
│ │   → 800000 (JÁ CONFIRMADA!)                     │ │
│ └─────────────────────────────────────────────────┘ │
└────────┬────────────────────────────────────────────┘
         │
         │ 4. Registrar descriptors
         ▼
┌─────────────────────────────────────────────────────┐
│ AddressCache.push_descriptor(desc)                   │
│ AddressCache.derive_addresses()                      │
└────────┬────────────────────────────────────────────┘
         │
         │ 5. Restaurar transações COM altura
         │    (SEM RESCAN NECESSÁRIO!)
         ▼
┌─────────────────────────────────────────────────────┐
│ for tx in payload.transactions:                      │
│   cache.cache_transaction(                          │
│     tx.raw_tx,                                      │
│     tx.metadata.block_height,  ← altura conhecida   │
│     merkle_proof,              ← prova SPV          │
│     tx.metadata.position,      ← posição no bloco   │
│   )                                                 │
└────────┬────────────────────────────────────────────┘
         │
         │ 6. Definir altura do cache
         ▼
┌─────────────────────────────────────────────────────┐
│ cache.bump_height(payload.metadata.birth_height)    │
│                                                      │
│ Wallet restaurada instantaneamente!                 │
│ Apenas sincroniza blocos NOVOS a partir daqui.      │
└─────────────────────────────────────────────────────┘
```

## 5. Pontos de Integração

### 5.1 Extração (Export)

```rust
// extractor.rs
pub fn extract_from_wallet<D: AddressCacheDatabase>(
    cache: &AddressCache<D>,
    network: NetworkType,
) -> Result<WalletPayload, BackupError> {

    // 1. Extrair descriptors
    let descriptors = cache.get_descriptors()?;

    // 2. Criar accounts (cada descriptor = 1 account simples)
    let accounts = descriptors
        .iter()
        .map(|desc| Account {
            index: None,
            descriptors: vec![Descriptor {
                descriptor: desc.clone(),
                checksum: None,  // TODO: calcular
                addresses: None,
                metadata: None,
            }],
            metadata: None,
        })
        .collect();

    // 3. Extrair transações com metadata
    let txids = cache.database.list_transactions()?;
    let transactions = txids
        .iter()
        .filter_map(|txid| {
            let cached = cache.get_transaction(txid)?;
            Some(Transaction {
                txid: txid.to_byte_array(),
                raw_tx: Some(serialize(&cached.tx)),
                metadata: Some(TransactionMetadata {
                    block_height: Some(cached.height),
                    position_in_block: Some(cached.position),
                    merkle_proof: cached.merkle_block.map(|m| serialize(&m)),
                    ..Default::default()
                }),
            })
        })
        .collect();

    // 4. Stats
    let stats = cache.get_stats()?;

    Ok(WalletPayload {
        version: 1,
        network,
        genesis_hash: None,
        root: None,  // watch-only, sem chaves privadas
        accounts,
        transactions: Some(transactions),
        utxos: None,  // TODO: extrair UTXOs
        metadata: Some(WalletMetadata {
            base: BaseMetadata {
                birth_height: Some(stats.cache_height),
                software: Some("Floresta".to_string()),
                ..Default::default()
            },
            ..Default::default()
        }),
    })
}
```

### 5.2 Importação (Restore)

```rust
// importer.rs
pub fn restore_to_wallet<D: AddressCacheDatabase>(
    payload: WalletPayload,
    cache: &AddressCache<D>,
) -> Result<(), BackupError> {

    // 1. Registrar descriptors
    for account in payload.accounts {
        for desc in account.descriptors {
            cache.push_descriptor(&desc.descriptor)?;
        }
    }

    // 2. Derivar endereços
    cache.derive_addresses()?;

    // 3. Restaurar transações (sem rescan!)
    if let Some(transactions) = payload.transactions {
        for tx in transactions {
            if let (Some(raw_tx), Some(metadata)) = (tx.raw_tx, tx.metadata) {
                let bitcoin_tx: bitcoin::Transaction = deserialize(&raw_tx)?;
                let height = metadata.block_height.unwrap_or(0);
                let position = metadata.position_in_block.unwrap_or(0);

                let merkle_proof = metadata.merkle_proof
                    .map(|p| deserialize(&p))
                    .transpose()?
                    .unwrap_or_default();

                // Cachear com altura conhecida = SEM RESCAN
                cache.cache_transaction(
                    &bitcoin_tx,
                    height,
                    0,  // value calculado internamente
                    merkle_proof,
                    position,
                    0,  // index
                    false,
                    get_spk_hash(&bitcoin_tx.output[0].script_pubkey),
                );
            }
        }
    }

    // 4. Definir altura do cache
    if let Some(metadata) = payload.metadata {
        if let Some(height) = metadata.base.birth_height {
            cache.bump_height(height);
        }
    }

    Ok(())
}
```

## 6. Métodos Necessários em AddressCache

| Método Existente | Usado Para |
|------------------|------------|
| `get_descriptors()` | Extrair descriptors para backup |
| `get_transaction(txid)` | Extrair dados da transação |
| `list_transactions()` (via database) | Listar todas as txs |
| `get_stats()` | Extrair estatísticas |
| `get_cache_height()` | Altura atual do cache |
| `push_descriptor(desc)` | Restaurar descriptor |
| `derive_addresses()` | Derivar endereços após import |
| `cache_transaction(...)` | Restaurar transação com altura |
| `bump_height(height)` | Definir altura após restore |

**Todos os métodos necessários JÁ EXISTEM!** Não precisamos modificar `floresta-watch-only`.

## 7. Dependências entre Crates

```
floresta-backup
    ├── floresta-watch-only (AddressCache, CachedTransaction)
    ├── floresta-common (get_spk_hash, parse_descriptors)
    ├── bitcoin (Transaction, serialize, deserialize)
    ├── ciborium (CBOR)
    ├── argon2 (KDF)
    └── aes-gcm (Encryption)
```

## 8. Arquivos a Criar

```
floresta-backup/src/
├── lib.rs           ✅ Criado
├── types.rs         ✅ Criado
├── cbor.rs          ⏳ Pendente (Dia 5)
├── crypto.rs        ⏳ Pendente (Dia 9-10)
├── envelope.rs      ⏳ Pendente (Dia 11)
├── extractor.rs     ⏳ Pendente (Dia 12-13)
├── importer.rs      ⏳ Pendente (Dia 14-15)
├── validation.rs    ⏳ Pendente (Dia 7-8)
└── error.rs         ⏳ Pendente (Dia 3)
```
