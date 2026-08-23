# ConvertFrom-FotonPrefetch fixtures (synthetic - not client data)

| File | Purpose |
|------|---------|
| `prefetch-scca-v23.bin` | Uncompressed SCCA v23 with Unicode name NOTEPAD.EXE at 0x10 |
| `prefetch-mam.bin` | MAM magic only - parser must not guess a name |
| `prefetch-not.bin` | Random bytes - Unsupported-NotPrefetch |
| `jumplist-destlist-v1.bin` | Synthetic DestList v1 (notepad path, known FILETIME). Not client data |
| `jumplist-not.bin` | Random bytes - Unsupported-NotJumplist |

Amcache tests write a synthetic `regf` hive in TEMP (not client data, no `reg save`).

Custom destinations tests build a wrapper around a COM-created `.lnk`.
