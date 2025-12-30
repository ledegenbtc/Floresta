# Requisitos Técnicos - Floresta Backup (BIP-BEWP)

## 1. Visão Geral

### 1.1 Objetivo

Implementar o padrão **Bitcoin Encrypted Wallet Payload (BIP-BEWP)** no Floresta, permitindo:

1. **Exportar** descriptors e histórico de transações em formato compacto e criptografado
2. **Importar** backups e restaurar a wallet **sem rescan** da blockchain

### 1.2 Problema que Resolve

| Situação Atual | Com BIP-BEWP |
|----------------|--------------|
| Cada wallet tem formato próprio de backup | Formato universal, interoperável |
| Restauração requer rescan completo (horas/dias) | Restauração instantânea com metadados |
| Backups podem ser texto puro (inseguros) | Criptografia obrigatória (Argon2id + AES) |
| Apenas mnemonic, sem histórico | Inclui transações, labels, UTXOs |

---

## 2. O que é CBOR?

### 2.1 Definição

**CBOR** (Concise Binary Object Representation) é um formato de serialização binária definido na [RFC 8949](https://www.rfc-editor.org/rfc/rfc8949.html).

### 2.2 Comparação com outros formatos

```
JSON (texto):     {"name": "Alice", "age": 30}     → 28 bytes
CBOR (binário):   A2 64 6E61 6D65 65 416C 696365 61 6167 65 18 1E → 18 bytes
                  ↑  ↑  └───┘     ↑  └───────┘    ↑ └───┘ ↑  └──┘
                  │  │   "name"   │   "Alice"     │ "age" │   30
                  │  │            │               │       │
                  │  text(4)     text(5)         text(3) uint
                  │
                  map(2 items)
```

### 2.3 Por que CBOR?

| Característica | JSON | Protobuf | CBOR |
|----------------|------|----------|------|
| Tamanho | Grande | Pequeno | Pequeno |
| Schema obrigatório | Não | Sim (.proto) | Não (opcional CDDL) |
| Extensível | Sim | Difícil | Sim |
| Suporte a bytes | Base64 | Nativo | Nativo |
| Determinístico | Não* | Não | Sim (RFC 8949 §4.2) |

*JSON tem ordem de chaves indefinida

### 2.4 Ciborium

**Ciborium** é a crate Rust que usamos para CBOR:

```rust
use ciborium::{from_reader, into_writer};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct Person {
    name: String,
    age: u32,
}

// Serializar
let person = Person { name: "Alice".into(), age: 30 };
let mut bytes = Vec::new();
into_writer(&person, &mut bytes).unwrap();

// Deserializar
let decoded: Person = from_reader(&bytes[..]).unwrap();
```

---

## 3. Seed vs Mnemonic vs Entropy

### 3.1 Fluxo de Derivação BIP39

```
┌─────────────────────────────────────────────────────────────────┐
│                         ENTROPY                                  │
│                    (128-256 bits random)                         │
│                   Ex: 0x8f3a7b2c...                             │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      │ BIP39 Encoding
                      │ (adiciona checksum, mapeia para palavras)
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                        MNEMONIC                                  │
│                    (12-24 palavras)                              │
│    Ex: "abandon abandon abandon ... about"                       │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      │ + Passphrase (opcional, "25th word")
                      │
                      │ PBKDF2-HMAC-SHA512 (2048 rounds)
                      │ salt = "mnemonic" + passphrase
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                          SEED                                    │
│                       (512 bits)                                 │
│              Ex: 0x5eb00bbddcf069084889a8ab9155568165...        │
└─────────────────────┬───────────────────────────────────────────┘
                      │
                      │ HMAC-SHA512 com key = "Bitcoin seed"
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│              MASTER PRIVATE KEY + CHAIN CODE                     │
│                                                                  │
│   m = primeiros 256 bits    chain = últimos 256 bits            │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Qual usar no backup?

| Formato | Tamanho | Portabilidade | Quando usar |
|---------|---------|---------------|-------------|
| **Mnemonic** | ~240 bytes | Alta | Padrão preferido |
| **Seed** | 64 bytes | Média | Quando passphrase já aplicada |
| **Entropy** | 16-32 bytes | Baixa | Compacto, mas precisa wordlist |

**Recomendação**: Usar **Mnemonic** para máxima interoperabilidade.

### 3.3 Implicações para Floresta

O Floresta é **watch-only** por padrão:
- Não armazena chaves privadas
- Apenas guarda **descriptors com xpubs**
- O campo `root` será `None` nos backups

Para wallets com chaves:
- Futuro suporte pode incluir mnemonic criptografado
- Usar `zeroize` para limpar memória após uso

---

## 4. Estrutura de Dados Detalhada

### 4.1 Hierarquia de Chaves CBOR

```
Key 0-99:     Campos core (obrigatórios ou importantes)
Key 100-999:  Metadata (opcionais, padronizados)
Key ≥1000:    Vendor-specific (Floresta)
```

### 4.2 WalletPayload

```
┌─────────────────────────────────────────────────────────┐
│ WalletPayload                                           │
├─────────────────────────────────────────────────────────┤
│ 0: version = 1                                          │
│ 1: network (0=mainnet, 1=testnet, 2=signet, 3=regtest) │
│ 2: genesis_hash [opcional, obrigatório se != mainnet]  │
│ 3: root [opcional - mnemonic/seed/entropy]             │
│                                                         │
│ 10: accounts[] ─────────────────────────────────────┐  │
│                                                      │  │
│ 20: transactions[] [opcional] ───────────────────┐  │  │
│                                                   │  │  │
│ 30: utxos[] [opcional, advisory] ─────────────┐  │  │  │
│                                                │  │  │  │
│ 100: metadata ─────────────────────────────┐   │  │  │  │
│                                             │   │  │  │  │
│   100: label                               │   │  │  │  │
│   101: birth_height                        │   │  │  │  │
│   104: software = "Floresta x.x.x"         │   │  │  │  │
│   1000: utreexo_roots [vendor]             │   │  │  │  │
│   1001: utreexo_num_leaves [vendor]        │   │  │  │  │
└─────────────────────────────────────────────┴───┴──┴──┴──┘
```

### 4.3 Account

```
┌─────────────────────────────────────────────┐
│ Account                                      │
├─────────────────────────────────────────────┤
│ 1: index (BIP44 account number)             │
│                                              │
│ 10: descriptors[] ───────────────────────┐  │
│                                           │  │
│ 100: metadata                             │  │
│   100: label = "Main Account"             │  │
│   300: gap_limit = 20                     │  │
│   301: next_external_index                │  │
│   302: next_internal_index                │  │
└───────────────────────────────────────────┴──┘
```

### 4.4 Descriptor

```
┌──────────────────────────────────────────────────────────────┐
│ Descriptor                                                    │
├──────────────────────────────────────────────────────────────┤
│ 1: descriptor = "wpkh([fp/84'/0'/0']xpub.../0/*)"           │
│ 2: checksum = "abcd1234" (8 chars bech32)                    │
│                                                               │
│ 10: addresses[] [opcional, cache] ────────────────────────┐  │
│                                                            │  │
│ 100: metadata                                              │  │
│   400: role = 0 (receive) ou 1 (change)                    │  │
│   401: next_index                                          │  │
│   403: watch_only = true                                   │  │
└────────────────────────────────────────────────────────────┴──┘
```

### 4.5 Transaction (Crítico para Floresta)

```
┌──────────────────────────────────────────────────────────────┐
│ Transaction                                                   │
├──────────────────────────────────────────────────────────────┤
│ 1: txid (32 bytes)                                           │
│ 2: raw_tx [opcional]                                         │
│                                                               │
│ 100: metadata                                                 │
│   100: label = "Pagamento café"                              │
│   500: block_height = 800000  ← ESSENCIAL PARA NO-RESCAN    │
│   501: fee = 1500                                            │
│                                                               │
│   [FLORESTA VENDOR FIELDS]                                   │
│   1000: block_hash (32 bytes)                                │
│   1001: merkle_proof                                         │
│   1002: position_in_block                                    │
└──────────────────────────────────────────────────────────────┘
```

---

## 5. Fluxo de Criptografia

### 5.1 Argon2id

**Argon2** é o vencedor do Password Hashing Competition (2015). A variante **Argon2id** combina:
- Resistência a ataques side-channel (Argon2i)
- Resistência a ataques GPU/ASIC (Argon2d)

```
Password + Salt (16 bytes random)
         │
         ▼
┌─────────────────────────────────────┐
│           Argon2id                   │
│                                      │
│  Memory: 64 MiB (m=65536)           │
│  Iterations: 3 (t=3)                │
│  Parallelism: 4 (p=4)               │
│  Output: 32 bytes                    │
└─────────────────────────────────────┘
         │
         ▼
    Encryption Key (256 bits)
```

### 5.2 AES-256-GCM

**AES-GCM** (Galois/Counter Mode) provê:
- Confidencialidade (AES-256)
- Integridade (GMAC authentication tag)

```
Encryption Key (32 bytes) + Nonce (12 bytes random)
         │
         ▼
┌─────────────────────────────────────┐
│         AES-256-GCM                  │
│                                      │
│  Input: CBOR payload                │
│  Output: ciphertext + tag (16 bytes)│
└─────────────────────────────────────┘
         │
         ▼
    Encrypted Backup
```

### 5.3 Envelope Final

```
┌────────────────────────────────────────────────────────┐
│                  Encrypted Envelope                     │
├────────────────────────────────────────────────────────┤
│ Magic bytes: "BEWP" (4 bytes)                          │
│ Version: 1 (1 byte)                                    │
│ Salt: 16 bytes (random)                                │
│ Nonce: 12 bytes (random)                               │
│ Ciphertext: variable                                   │
│ Auth Tag: 16 bytes                                     │
└────────────────────────────────────────────────────────┘
```

---

## 6. Decisões de Design

### 6.1 Por que chaves inteiras no CBOR?

```rust
// Ruim: chaves string
{ "version": 1, "network": 0 }  // 27 bytes

// Bom: chaves inteiras
{ 0: 1, 1: 0 }  // 5 bytes
```

Economia de ~80% em tamanho para muitos campos.

### 6.2 Por que campos opcionais com skip_serializing_if?

Evita serializar `null` desnecessariamente:

```rust
#[serde(skip_serializing_if = "Option::is_none")]
pub genesis_hash: Option<[u8; 32]>,
```

### 6.3 Por que zeroize para dados sensíveis?

```rust
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MnemonicRoot {
    pub words: Vec<String>,
    pub passphrase: Option<String>,
}
```

Garante que a memória é zerada quando a struct é dropada.

### 6.4 Por que campos vendor (≥1000)?

Permite extensões específicas do Floresta sem quebrar compatibilidade:
- Outras wallets ignoram campos ≥1000
- Floresta pode guardar dados Utreexo, proofs, etc.

### 6.5 Watch-only por padrão

O Floresta é watch-only, então:
- `root` será `None` na maioria dos backups
- Foco em descriptors com xpubs
- Suporte futuro para wallets com chaves

---

## 7. Requisitos Funcionais

### 7.1 Exportação

| Req | Descrição | Prioridade |
|-----|-----------|------------|
| EXP-1 | Exportar todos os descriptors registrados | Alta |
| EXP-2 | Exportar histórico de transações com block_height | Alta |
| EXP-3 | Exportar UTXOs atuais (advisory) | Média |
| EXP-4 | Incluir labels/metadata se disponíveis | Baixa |
| EXP-5 | Criptografar com senha do usuário | Alta |
| EXP-6 | Incluir dados Utreexo (vendor fields) | Média |

### 7.2 Importação

| Req | Descrição | Prioridade |
|-----|-----------|------------|
| IMP-1 | Decriptar com senha do usuário | Alta |
| IMP-2 | Validar version e network | Alta |
| IMP-3 | Registrar descriptors na wallet | Alta |
| IMP-4 | Restaurar transações SEM rescan | Alta |
| IMP-5 | Verificar genesis_hash se presente | Média |
| IMP-6 | Restaurar labels/metadata | Baixa |

### 7.3 Validação

| Req | Descrição | Prioridade |
|-----|-----------|------------|
| VAL-1 | Rejeitar CBOR com indefinite-length | Alta |
| VAL-2 | Rejeitar floats | Alta |
| VAL-3 | Rejeitar version > suportada | Alta |
| VAL-4 | Verificar txid == hash(raw_tx) se ambos presentes | Média |
| VAL-5 | Validar checksum dos descriptors | Média |

---

## 8. Requisitos Não-Funcionais

### 8.1 Performance

| Métrica | Meta |
|---------|------|
| Tempo de backup (1000 txs) | < 1 segundo |
| Tempo de restore (1000 txs) | < 1 segundo |
| Tamanho do backup (1000 txs) | < 500 KB |
| Memória para criptografia | < 128 MiB |

### 8.2 Segurança

| Requisito | Implementação |
|-----------|---------------|
| Derivação de chave | Argon2id (64 MiB, 3 iter) |
| Criptografia | AES-256-GCM |
| Salt | 16 bytes random (CSPRNG) |
| Nonce | 12 bytes random (CSPRNG) |
| Limpeza de memória | zeroize para dados sensíveis |

### 8.3 Compatibilidade

| Requisito | Status |
|-----------|--------|
| Compatível com outros implementadores BIP-BEWP | Planejado |
| Campos vendor ignorados por outras wallets | Garantido |
| Versionamento para evolução do formato | Suportado |

---

## 9. API

### 9.1 Rust API

```rust
use floresta_backup::{export_wallet_backup, restore_wallet_backup, NetworkType};

// Exportar wallet para backup criptografado
let backup = export_wallet_backup(&wallet, NetworkType::Mainnet, "password")?;
std::fs::write("wallet.backup", &backup)?;

// Restaurar wallet de backup
let backup = std::fs::read("wallet.backup")?;
let result = restore_wallet_backup(&wallet, &backup, "password")?;
println!("Restored {} descriptors", result.descriptors_imported);
```

### 9.2 RPC API

```json
// Exportar
{
  "method": "exportwalletbackup",
  "params": {
    "password": "minha_senha_forte",
    "file": "/path/to/backup.bewp"
  }
}

// Importar
{
  "method": "importwalletbackup",
  "params": {
    "password": "minha_senha_forte",
    "file": "/path/to/backup.bewp"
  }
}
```

### 9.3 CLI

```bash
# Exportar
floresta-cli exportwalletbackup --password "senha" --output backup.bewp

# Importar
floresta-cli importwalletbackup --password "senha" --input backup.bewp
```

---

## 10. Estrutura de Arquivos

```
crates/floresta-backup/
├── Cargo.toml
├── src/
│   ├── lib.rs           # API de alto nível e re-exports
│   ├── types.rs         # Structs do payload (WalletPayload, Account, etc.)
│   ├── cbor.rs          # Serialização/deserialização CBOR
│   ├── crypto.rs        # Argon2id + AES-GCM
│   ├── envelope.rs      # Wrapper criptografado
│   ├── extractor.rs     # Extrai dados da wallet
│   ├── importer.rs      # Restaura wallet de backup
│   ├── validation.rs    # Validações do BIP
│   └── error.rs         # Tipos de erro
├── tests/
│   ├── vectors.rs       # Test vectors do BIP
│   ├── roundtrip.rs     # Testes serialize/deserialize
│   └── integration.rs   # Testes end-to-end
└── docs/
    └── TECHNICAL_REQUIREMENTS.md
```

---

## 11. Dependências

```toml
[dependencies]
ciborium = "0.2"      # CBOR encoding/decoding
argon2 = "0.5"        # Argon2id KDF
aes-gcm = "0.10"      # AES-256-GCM
rand = "0.8"          # CSPRNG para salt/nonce
zeroize = "1.7"       # Limpeza segura de memória
thiserror = "1.0"     # Error handling
serde = "1.0"         # Serialization framework
serde_bytes = "0.11"  # Eficiente para [u8]
bitcoin = "0.32"      # Tipos Bitcoin
```

---

## 12. Riscos e Mitigações

| Risco | Probabilidade | Impacto | Mitigação |
|-------|---------------|---------|-----------|
| BIP muda antes de finalização | Média | Alto | Código modular, fácil adaptar |
| Ciborium não suporta canonical encoding | Baixa | Médio | Testar cedo; alternativa: minicbor |
| Performance em wallets grandes | Baixa | Médio | Streaming se necessário |
| Integração complexa com wallet | Média | Médio | API simples, iterativa |

---

## 13. Status da Implementação

**Módulos implementados:**
- `types.rs` - Estruturas de dados do payload
- `cbor.rs` - Serialização/deserialização CBOR
- `crypto.rs` - Argon2id + AES-GCM
- `envelope.rs` - Envelope criptografado
- `extractor.rs` - Extração de dados da wallet
- `importer.rs` - Importação para wallet
- `validation.rs` - Validações do BIP

**Pendente:**
- RPCs `exportwalletbackup` e `importwalletbackup`
- Comandos CLI correspondentes
- Testes de compatibilidade com outras implementações

---

## Referências

1. [BIP: Standard Encrypted Wallet Payload](https://gist.github.com/KeysSoze/7109a7f0455897b1930f851bde6337e3)
2. [RFC 8949: CBOR](https://www.rfc-editor.org/rfc/rfc8949.html)
3. [BIP39: Mnemonic code](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
4. [BIP380: Output Script Descriptors](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki)
5. [Argon2 RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)
6. [AES-GCM NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
