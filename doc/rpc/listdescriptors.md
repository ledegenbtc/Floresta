# `listdescriptors`

Returns a list of all output descriptors currently loaded in the watch-only wallet.

## Usage

### Synopsis

```
floresta-cli listdescriptors
```

### Examples

```bash
floresta-cli --network signet listdescriptors
```

## Arguments

None.

## Returns

### Ok Response

```json
[
  "wpkh([00000000/84h/1h/0h]tpubDC.../<0;1>/*)#checksum",
  "wsh(sortedmulti(1,[...]tpub1.../*,[...]tpub2.../*))#checksum"
]
```

Returns an array of descriptor strings. Empty array `[]` if no descriptors are loaded.

### Error

- Returns wallet error if the database cannot be read.

## Notes

- Returns descriptors in the order they were added
- Each descriptor is returned as the exact string that was provided to `loaddescriptor`
- Related commands: `loaddescriptor`, `removedescriptor`
