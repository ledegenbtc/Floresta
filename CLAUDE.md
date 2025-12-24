# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Floresta is a lightweight Bitcoin full node implementation in Rust, powered by Utreexo for efficient UTXO set representation. It consists of:
- **libfloresta**: Modular, reusable Bitcoin node components
- **florestad**: Full node daemon with watch-only wallet and Electrum server

## Current Task: Bitcoin Encrypted Backup Standard

Implement a first working version of the new Bitcoin Encrypted Wallet Payload standard in Floresta, allowing the wallet to produce a compact, encrypted backup of its descriptors and transaction history. This will be used to restore the wallet without the need for an expensive rescan afterwards.

The implementation should follow the scheme described in a new proposed BIP for exporting wallet-related materials. The optional section for application-specific data should be used to store transaction data and where they were confirmed.

### Entregas Principais

1. **Módulo de serialização CBOR** para wallet payload
2. **Módulo de criptografia** (envelope de criptografia com Argon2id)
3. **Integração com a wallet existente** do Floresta
4. **Suporte a dados específicos de aplicação** (transações + confirmações)
5. **Comandos RPC** para exportar/importar backups
6. **Testes e documentação**

### Cronograma

#### FASE 1: Fundamentos e Pesquisa (Dias 1-4)

**Dia 1 — Estudo do BIP e Arquitetura**
- Leitura detalhada do BIP "Standard Encrypted Wallet Payload"
- Análise da estrutura CBOR e CDDL schema
- Documentar decisões de design e estrutura de dados
- **Entrega:** Documento de requisitos técnicos

**Dia 2 — Análise do Código Floresta**
- Explorar estrutura do crate `floresta-wallet`
- Entender como descriptors são armazenados
- Mapear pontos de integração (wallet, transactions, RPC)
- **Entrega:** Diagrama de integração

**Dia 3 — Setup do Ambiente e Dependências**
- Fork e configuração do repositório
- Pesquisar crates Rust: `ciborium` (CBOR), `argon2`
- Criar estrutura inicial do módulo `floresta-backup`
- **Entrega:** Novo crate `floresta-backup` com Cargo.toml configurado

**Dia 4 — Definição de Estruturas de Dados**
- Definir structs Rust para WalletPayload, Account, Descriptor
- Definir structs para Transaction, UTXO, Metadata
- Adicionar derives para Serialize/Deserialize (CBOR)
- **Entrega:** `src/types.rs` com todas as estruturas core

#### FASE 2: Implementação Core CBOR (Dias 5-8)

**Dia 5 — Serialização CBOR Básica**
- Implementar serialização do WalletPayload
- Implementar serialização de Accounts e Descriptors
- Testes unitários de serialização básica
- **Entrega:** Serialização funcional para estruturas principais

**Dia 6 — Serialização de Transações**
- Implementar serialização de Transaction com txid e raw_tx
- Implementar campo de metadata com block height (confirmação)
- Testes com transações reais do testnet
- **Entrega:** Suporte completo a transações no backup

**Dia 7 — Serialização Canônica/Determinística**
- Garantir encoding determinístico (RFC 8949 §4.2.1)
- Implementar ordenação de chaves de mapa
- Validar com test vectors do BIP
- **Entrega:** Serialização canônica validada

**Dia 8 — Deserialização e Validação**
- Implementar deserialização completa
- Implementar validações do BIP (version, checksums)
- Testes de round-trip (serialize → deserialize → compare)
- **Entrega:** Parser completo com validação

#### FASE 3: Criptografia (Dias 9-11)

**Dia 9 — Envelope de Criptografia**
- Implementar derivação de chave com Argon2id
- Definir struct EncryptedEnvelope
- Documentar parâmetros de segurança
- **Entrega:** `src/crypto.rs` com KDF

**Dia 10 — Criptografia Simétrica**
- Implementar criptografia AES-256-GCM ou ChaCha20-Poly1305
- Implementar descriptografia
- Testes de encrypt/decrypt
- **Entrega:** Criptografia funcional

**Dia 11 — Integração CBOR + Crypto**
- Pipeline: Payload → CBOR → Encrypt → Envelope
- Pipeline reverso: Envelope → Decrypt → CBOR → Payload
- Testes end-to-end com senha
- **Entrega:** Fluxo completo de backup criptografado

#### FASE 4: Integração com Floresta Wallet (Dias 12-15)

**Dia 12 — Extração de Dados da Wallet**
- Função para extrair descriptors da wallet existente
- Função para extrair histórico de transações
- Mapear addresses e derivation indices
- **Entrega:** `src/extractor.rs`

**Dia 13 — Dados Específicos de Aplicação**
- Implementar seção de metadata para confirmações (block height, timestamp)
- Armazenar proofs Utreexo (opcional, se aplicável)
- Definir formato para restauração sem rescan
- **Entrega:** Metadata específico do Floresta

**Dia 14 — Função de Exportação**
- Implementar `export_backup(wallet, password) -> Vec<u8>`
- Adicionar opções (incluir/excluir transactions, UTXOs)
- Testes de exportação
- **Entrega:** API de exportação funcional

**Dia 15 — Função de Importação/Restauração**
- Implementar `import_backup(data, password) -> Wallet`
- Restaurar descriptors e re-registrar na wallet
- Restaurar transactions sem rescan (usar metadata)
- **Entrega:** API de importação funcional

#### FASE 5: Interface RPC e CLI (Dias 16-17)

**Dia 16 — Comandos RPC**
- Adicionar RPC `exportwalletbackup`
- Adicionar RPC `importwalletbackup`
- Documentar parâmetros e retornos
- **Entrega:** RPCs funcionais

**Dia 17 — Integração CLI**
- Adicionar comandos em `floresta-cli`
- Suporte a arquivo de saída/entrada
- Testes de integração via CLI
- **Entrega:** Comandos CLI funcionais

#### FASE 6: Testes e Documentação (Dias 18-20)

**Dia 18 — Testes Abrangentes**
- Testes de compatibilidade com test vectors do BIP
- Testes de edge cases (wallet vazia, muitas txs)
- Testes de segurança (senhas fracas, corrupção de dados)
- **Entrega:** Suite de testes completa

**Dia 19 — Documentação**
- Documentação da API (rustdoc)
- README do módulo com exemplos
- Guia de uso para usuários finais
- **Entrega:** Documentação completa

**Dia 20 — Revisão Final e PR**
- Code review interno, linting, formatação
- Atualizar CHANGELOG
- Preparar Pull Request com descrição detalhada
- **Entrega:** PR pronto para review

### Estrutura de Arquivos Proposta

```
crates/
└── floresta-backup/
    ├── Cargo.toml
    ├── src/
    │   ├── lib.rs           # Módulo principal, re-exports
    │   ├── types.rs         # Structs: WalletPayload, Account, etc.
    │   ├── cbor.rs          # Serialização/deserialização CBOR
    │   ├── crypto.rs        # Argon2id + AES-GCM
    │   ├── envelope.rs      # EncryptedEnvelope wrapper
    │   ├── extractor.rs     # Extrai dados da wallet Floresta
    │   ├── importer.rs      # Restaura wallet de backup
    │   ├── validation.rs    # Validações do BIP
    │   └── error.rs         # Tipos de erro
    └── tests/
        ├── vectors.rs       # Test vectors do BIP
        ├── roundtrip.rs     # Testes de ida e volta
        └── integration.rs   # Testes end-to-end
```

### Dependências Rust Sugeridas

```toml
[dependencies]
ciborium = "0.2"          # CBOR encoding/decoding
argon2 = "0.5"            # Argon2id KDF
aes-gcm = "0.10"          # Criptografia simétrica
rand = "0.8"              # Geração de nonce/salt
zeroize = "1.7"           # Limpar memória sensível
thiserror = "1.0"         # Error handling
serde = { version = "1.0", features = ["derive"] }

# Do Floresta existente
floresta-wallet = { path = "../floresta-wallet" }
bitcoin = "0.32"
```

### Métricas de Sucesso

| Critério | Meta |
|----------|------|
| Cobertura de testes | > 80% |
| Compatibilidade com test vectors | 100% |
| Tempo de backup (1000 txs) | < 1s |
| Tamanho do backup (1000 txs) | < 500KB |
| Restauração sem rescan | Funcional |

### Riscos e Mitigações

| Risco | Mitigação |
|-------|-----------|
| BIP ainda em draft, pode mudar | Modularizar código para fácil adaptação |
| Crate CBOR não suporta encoding canônico | Testar `ciborium` antecipadamente; alternativa: `minicbor` |
| Integração complexa com wallet existente | Começar com API simples, iterar |
| Performance em wallets grandes | Streaming de transações se necessário |

### Referências

1. [BIP: Standard Encrypted Wallet Payload](https://gist.github.com/KeysSoze/7109a7f0455897b1930f851bde6337e3)
2. [RFC 8949: CBOR](https://www.rfc-editor.org/rfc/rfc8949.html)
3. [BIP 380: Output Script Descriptors](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki)
4. [Floresta GitHub](https://github.com/vinteumorg/Floresta)
5. [Floresta Docs](https://docs.getfloresta.sh/floresta/)

### Notas Adicionais

- O BIP menciona um "companion BIP" para o envelope de criptografia que ainda não está publicado. A implementação seguirá as práticas recomendadas (Argon2id + AES-GCM).
- O campo de metadata `≥1000` será usado para dados específicos do Floresta (confirmações, Utreexo proofs).
- Priorizar compatibilidade com outras wallets que implementarem o mesmo BIP no futuro.

## Build Commands

Uses `just` command runner. Requires Rust 1.81.0+ (MSRV).

```bash
just build              # Debug build
just build-release      # Release build
just run                # Run florestad (debug)
just run-release        # Run florestad (release)
just install            # Install binaries
```

## Testing

```bash
just test               # All tests (unit + doc + workspace)
just test-unit [name]   # Unit tests with optional filter
just test-features      # Test all feature combinations
just test-functional    # Full functional tests (requires Python 3.12+)
```

Run a single test:
```bash
cargo test test_name
cargo test -p floresta-chain test_name  # Specific crate
```

Functional test subsets:
```bash
just test-functional-run "-t floresta-cli"           # Specific test file
just test-functional-run "-t floresta-cli -k getblock"  # Specific test case
```

## Code Quality

```bash
just fmt                # Format (requires nightly)
just lint               # Full lint (fmt + clippy + doc-check)
just pcc                # Pre-commit check (full suite)
just spell-check        # Typo checking
```

Formatting requires nightly: `cargo +nightly fmt --all`

## Architecture

### Crate Structure

```
crates/
├── floresta/           # Meta-crate exporting all public interfaces
├── floresta-chain/     # Consensus validation, blockchain state, Utreexo accumulator
├── floresta-wire/      # P2P networking (v1 & BIP324 v2), mempool
├── floresta-node/      # Full node orchestration combining all components
├── floresta-electrum/  # Electrum protocol server
├── floresta-watch-only/# Watch-only wallet
├── floresta-compact-filters/  # BIP158 compact block filters
├── floresta-common/    # Shared types (supports no_std)
└── floresta-rpc/       # JSON-RPC interface

bin/
├── florestad/          # Main node daemon
└── floresta-cli/       # CLI tool for node interaction
```

### Component Dependencies

- **floresta-chain** is the core: validates blocks, manages chain state with `ChainState` and `ChainBackend` trait
- **floresta-wire** handles P2P: peer discovery (DNS seeds), block/tx propagation, mempool
- **floresta-node** orchestrates everything: combines chain, wire, electrum, wallet into cohesive node
- **florestad** is the binary: CLI interface, config files, daemon mode (Unix), exposes Electrum/JSON-RPC servers

### Key Traits

- `ChainBackend`: Chain state storage abstraction
- `BlockchainInterface`: Blockchain query interface used across crates

## Commit Convention

Uses Conventional Commits 1.0.0:
```
<type>(<scope>): <description>
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `chore`, `perf`, `style`, `ci`, `bench`, `fuzz`

Scopes: `chain`, `wire`, `node`, `electrum`, `wallet`, `filters`, `rpc`, `cli`, `florestad`, `common`, `consensus`, `mempool`, `deps`, `integration`, `functional`, `unit`

## Feature Flags

Default features: `bitcoinconsensus`, `electrum-server`, `watch-only-wallet`, `flat-chainstore`

Key optional features:
- `json-rpc`: Enable JSON-RPC server
- `zmq-server`: ZeroMQ notifications
- `compact-filters`: BIP158 filters
- `metrics`: Prometheus metrics

## Network Ports

- 50001: Electrum server
- 8332: JSON-RPC
- 8333: P2P (mainnet)

## Test Data

### Default Descriptor for Tests

Use this WSH multisig descriptor (testnet) as default for watch-only wallet tests:

```rust
const TEST_DESCRIPTORS: &[&str] = &[
    "wsh(sortedmulti(1,[54ff5a12/48h/1h/0h/2h]tpubDDw6pwZA3hYxcSN32q7a5ynsKmWr4BbkBNHydHPKkM4BZwUfiK7tQ26h7USm8kA1E2FvCy7f7Er7QXKF8RNptATywydARtzgrxuPDwyYv4x/<0;1>/*,[bcf969c0/48h/1h/0h/2h]tpubDEFdgZdCPgQBTNtGj4h6AehK79Jm4LH54JrYBJjAtHMLEAth7LuY87awx9ZMiCURFzFWhxToRJK6xp39aqeJWrG5nuW3eBnXeMJcvDeDxfp/<0;1>/*))#fuw35j0q"
];
```

**Details:**
- Type: `wsh(sortedmulti(1,...))` - 1-of-2 multisig in native SegWit
- Network: Testnet (`tpub` prefix)
- Derivation: BIP48 (`48h/1h/0h/2h`)
- Multipath: `<0;1>/*` - derives both external (0) and internal/change (1)
- Checksum: `#fuw35j0q`
