# `listtransactions`

Returns a list of all transactions in the watch-only wallet.

## Usage

### Synopsis

```
floresta-cli listtransactions
```

### Examples

```bash
floresta-cli --network signet listtransactions
```

## Arguments

None.

## Returns

### Ok Response

```json
[
  {
    "txid": "6bb0665122c7dcecc6e6c45b6384ee2bdce148aea097896e6f3e9e08070353ea",
    "height": 118511
  },
  {
    "txid": "abc123def456789...",
    "height": 118500
  }
]
```

- Array of transaction objects:
  - `txid` - (string) The transaction ID
  - `height` - (u32) Block height where the transaction was confirmed (0 if unconfirmed)

### Error

- Returns wallet error if the database cannot be read.

## Notes

- Transactions are sorted by height in descending order (newest first)
- Includes transactions from all loaded descriptors
- Duplicate transactions are automatically filtered out
- Use `gettransaction <txid>` to get full transaction details
- Related commands: `getwalletinfo`, `gettransaction`, `loaddescriptor`
