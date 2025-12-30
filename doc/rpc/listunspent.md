# `listunspent`

Returns a list of unspent transaction outputs (UTXOs) in the watch-only wallet.

## Usage

### Synopsis

```
floresta-cli listunspent [minconf] [maxconf]
```

### Examples

```bash
# Get all UTXOs with at least 1 confirmation (default)
floresta-cli --network signet listunspent

# Get all UTXOs including unconfirmed (0 confirmations)
floresta-cli --network signet listunspent 0

# Get UTXOs with 6 to 100 confirmations
floresta-cli --network signet listunspent 6 100
```

## Arguments

`minconf` - (numeric, optional, default=1) Minimum number of confirmations.

`maxconf` - (numeric, optional, default=9999999) Maximum number of confirmations.

## Returns

### Ok Response

```json
[
  {
    "txid": "6bb0665122c7dcecc6e6c45b6384ee2bdce148aea097896e6f3e9e08070353ea",
    "vout": 0,
    "address": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
    "scriptPubKey": "0014751e76e8199196d454941c45d1b3a323f1433bd6",
    "amount": 0.00150000,
    "confirmations": 1234,
    "spendable": false,
    "solvable": true,
    "safe": true
  }
]
```

- `txid` - (string) The transaction id
- `vout` - (numeric) The output index
- `address` - (string, optional) The bitcoin address
- `scriptPubKey` - (string) The scriptPubKey hex
- `amount` - (numeric) The output value in BTC
- `confirmations` - (numeric) Number of confirmations
- `spendable` - (boolean) Whether we can spend this output (always false for watch-only)
- `solvable` - (boolean) Whether we know how to spend this output
- `safe` - (boolean) Whether this output is safe to spend (confirmed)

### Error

- Returns wallet error if the database cannot be read.

## Notes

- UTXOs are sorted by amount (largest first)
- `spendable` is always `false` for watch-only wallets
- `safe` is `true` for confirmed outputs (confirmations >= 1)
- Use this command to find outputs available for constructing transactions
- Related commands: `getwalletinfo`, `listtransactions`, `gettxout`
