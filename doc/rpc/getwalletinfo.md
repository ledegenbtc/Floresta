# `getwalletinfo`

Returns information about the watch-only wallet, including balance, transaction count, and descriptor count.

## Usage

### Synopsis

```
floresta-cli getwalletinfo
```

### Examples

```bash
floresta-cli --network signet getwalletinfo
```

## Arguments

None.

## Returns

### Ok Response

```json
{
  "walletname": "default",
  "balance": 0.00999890,
  "unconfirmed_balance": 0.0,
  "txcount": 2,
  "private_keys_enabled": false,
  "descriptors": true,
  "utxo_count": 1,
  "address_count": 100,
  "descriptor_count": 1,
  "derivation_index": 100
}
```

- `walletname` - (string) The wallet name (always "default" for Floresta)
- `balance` - (numeric) Total confirmed balance in BTC
- `unconfirmed_balance` - (numeric) Total unconfirmed balance in BTC
- `txcount` - (numeric) Number of transactions in the wallet
- `private_keys_enabled` - (boolean) Whether private keys are enabled (always false for watch-only)
- `descriptors` - (boolean) Whether the wallet uses descriptors (always true)
- `utxo_count` - (numeric) Number of unspent transaction outputs
- `address_count` - (numeric) Number of addresses being monitored
- `descriptor_count` - (numeric) Number of descriptors loaded
- `derivation_index` - (numeric) Current derivation index

### Error

- Returns wallet error if the database cannot be read.

## Notes

- This command aggregates data from all loaded descriptors
- Balance is returned in BTC (not satoshis)
- `unconfirmed_balance` is currently always 0 (not yet tracked separately)
- Use `listtransactions` to see individual transactions
- Related commands: `loaddescriptor`, `listdescriptors`, `listtransactions`
