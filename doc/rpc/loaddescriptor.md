# `loaddescriptor`

Loads a new output descriptor into the watch-only wallet and triggers a rescan for matching transactions.

## Usage

### Synopsis

```
floresta-cli loaddescriptor <descriptor>
```

### Examples

```bash
# Load a P2WPKH descriptor
floresta-cli --network signet loaddescriptor "wpkh([00000000/84h/1h/0h]tpubDC.../<0;1>/*)"

# Load a multisig descriptor
floresta-cli --network signet loaddescriptor "wsh(sortedmulti(1,[fingerprint/path]tpub1.../*,[fingerprint/path]tpub2.../*))#checksum"
```

## Arguments

`descriptor` - (string, required) The output descriptor to load. Must be a valid Bitcoin output descriptor with optional checksum.

## Returns

### Ok Response

```json
true
```

Returns `true` if the descriptor was successfully loaded and saved.

### Error

- `InvalidDescriptor` - The descriptor is malformed or invalid
- `InInitialBlockDownload` - Cannot rescan during IBD (compact block filters not ready)

## Notes

- Derives 100 addresses from the descriptor by default
- Automatically triggers a rescan using compact block filters
- The descriptor is persisted to the database for future sessions
- Multiple descriptors can be loaded; they are stored in a list
- Use `<0;1>/*` syntax for descriptors with both external (0) and change (1) paths
- Related commands: `listdescriptors`, `removedescriptor`, `rescanblockchain`
