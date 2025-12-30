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

A extração utiliza a API do `WalletExtractor` em `extractor.rs`:

```rust
// Uso da API de exportação
let extractor = WalletExtractor::new(NetworkType::Mainnet);
let payload = extractor.extract_from_wallet(&address_cache)?;
```

**Fluxo interno:**
1. Extrai descriptors via `cache.get_descriptors()`
2. Cria accounts (cada descriptor = 1 account)
3. Extrai transações com block_height e merkle_proof
4. Coleta stats para metadata (birth_height, software)

### 5.2 Importação (Restore)

A importação utiliza a API do `WalletImporter` em `importer.rs`:

```rust
// Uso da API de importação
let importer = WalletImporter::new(payload);
let result = importer.import_to_wallet(&address_cache)?;
println!("Imported {} descriptors, {} transactions",
         result.descriptors_imported, result.transactions_imported);
```

**Fluxo interno:**
1. Registra descriptors via `cache.push_descriptor()`
2. Deriva endereços via `cache.derive_addresses()`
3. Restaura transações com altura conhecida (SEM RESCAN)
4. Define altura do cache via `cache.bump_height()`

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

## 8. Estrutura de Arquivos

```
floresta-backup/src/
├── lib.rs           # Módulo principal, re-exports e API de alto nível
├── types.rs         # Structs do payload (WalletPayload, Account, etc.)
├── cbor.rs          # Serialização/deserialização CBOR
├── crypto.rs        # Argon2id + AES-GCM
├── envelope.rs      # Wrapper criptografado
├── extractor.rs     # Extrai dados da wallet
├── importer.rs      # Restaura wallet de backup
├── validation.rs    # Validações do BIP
└── error.rs         # Tipos de erro
```
