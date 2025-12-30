# `listaddresses`

Returns a list of all addresses derived from loaded descriptors in the watch-only wallet.

## Usage

### Synopsis

```
floresta-cli listaddresses
```

### Examples

```bash
floresta-cli --network signet listaddresses
```

## Arguments

None.

## Returns

### Ok Response

```json
[
  {
    "script_hash": "a914b472a266d0bd89c13706a4132ccfb16f7c3b9fcb87",
    "address": "tb1qkge5f5nnq3jy3d8gq4s27kk7etl7hku9wlqazj",
    "balance": 150000,
    "tx_count": 3
  },
  {
    "script_hash": "76a914...",
    "address": "tb1q...",
    "balance": 0,
    "tx_count": 0
  }
]
```

- Array of address objects, sorted by balance (highest first):
  - `script_hash` - (string) The script hash in Electrum format (reversed SHA256 of scriptPubKey)
  - `address` - (string | null) The Bitcoin address string, or null if the script cannot be represented as a standard address
  - `balance` - (u64) Current balance in satoshis
  - `tx_count` - (usize) Number of transactions involving this address

### Error

- Returns wallet error if the database cannot be read.

## Notes

- Returns addresses from all loaded descriptors
- Addresses are sorted by balance in descending order (highest balance first)
- The `script_hash` can be used with Electrum protocol commands
- Addresses with zero balance are still included if they were derived from descriptors
- Use `loaddescriptor` to add new descriptors and derive more addresses
- Related commands: `getwalletinfo`, `listtransactions`, `loaddescriptor`
