# `removedescriptor`

Removes a descriptor from the watch-only wallet.

## Usage

### Synopsis

```
floresta-cli removedescriptor <descriptor>
```

### Examples

```bash
floresta-cli --network signet removedescriptor "wpkh([00000000/84h/1h/0h]tpubDC.../<0;1>/*)"
```

## Arguments

`descriptor` - (string, required) The exact descriptor string to remove. Must match exactly as it was provided to `loaddescriptor`.

## Returns

### Ok Response

```json
true
```

Returns `true` if the descriptor was found and removed.

```json
false
```

Returns `false` if the descriptor was not found in the wallet.

### Error

- Returns wallet error if the database cannot be accessed.

## Notes

- The descriptor string must match exactly (including checksum if provided)
- Removing a descriptor does NOT delete associated transactions or UTXOs
- The cached addresses derived from this descriptor remain in the database
- To fully remove all data, you would need to reset the wallet database
- Related commands: `loaddescriptor`, `listdescriptors`
