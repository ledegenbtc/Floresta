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
  "balance": 999890,
  "tx_count": 2,
  "utxo_count": 1,
  "address_count": 100,
  "descriptor_count": 1,
  "derivation_index": 100
}
```

- `balance` - (u64) Total confirmed balance in satoshis across all descriptors
- `tx_count` - (usize) Number of transactions in the wallet
- `utxo_count` - (usize) Number of unspent transaction outputs
- `address_count` - (usize) Number of addresses being monitored
- `descriptor_count` - (usize) Number of descriptors loaded
- `derivation_index` - (u32) Current derivation index

### Error

- Returns wallet error if the database cannot be read.

## Notes

- This command aggregates data from all loaded descriptors
- Balance includes all confirmed transactions only
- Use `listtransactions` to see individual transactions
- Related commands: `loaddescriptor`, `listdescriptors`, `listtransactions`
