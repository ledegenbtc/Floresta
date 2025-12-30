# `listtransactions`

Returns a list of transactions in the watch-only wallet.

## Usage

### Synopsis

```
floresta-cli listtransactions [count] [skip]
```

### Examples

```bash
# Get the 10 most recent transactions (default)
floresta-cli --network signet listtransactions

# Get 20 most recent transactions
floresta-cli --network signet listtransactions 20

# Get transactions 10-20 (skip first 10, then get 10)
floresta-cli --network signet listtransactions 10 10
```

## Arguments

`count` - (numeric, optional, default=10) The number of transactions to return.

`skip` - (numeric, optional, default=0) The number of transactions to skip.

## Returns

### Ok Response

```json
[
  {
    "txid": "6bb0665122c7dcecc6e6c45b6384ee2bdce148aea097896e6f3e9e08070353ea",
    "category": "receive",
    "amount": 0.00150000,
    "confirmations": 1234,
    "blockhash": "00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054",
    "blockheight": 118511,
    "blocktime": 1703123456,
    "time": 1703123456,
    "timereceived": 1703123456
  }
]
```

- `txid` - (string) The transaction ID
- `category` - (string) Transaction category: "receive" (watch-only tracks receives)
- `amount` - (numeric) The amount in BTC
- `confirmations` - (numeric) Number of confirmations (0 if unconfirmed)
- `blockhash` - (string, optional) The block hash containing this transaction
- `blockheight` - (numeric, optional) The block height containing this transaction
- `blocktime` - (numeric, optional) The block time as Unix timestamp
- `time` - (numeric) The transaction time as Unix timestamp
- `timereceived` - (numeric) The time the transaction was received

### Error

- Returns wallet error if the database cannot be read.

## Notes

- Transactions are sorted by confirmations (most recent first)
- The `category` is always "receive" for watch-only wallets
- Amount is in BTC (not satoshis)
- Use `gettransaction <txid>` to get full transaction details including raw hex
- Related commands: `getwalletinfo`, `gettransaction`, `loaddescriptor`
