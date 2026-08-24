# Public/Parse

Pure functions over bytes or files already in a package. No live system, no network,
no writes except what the caller asked for.

- `ConvertFrom-FotonPrefetch` - SCCA executable name; MAM is unsupported, not guessed.
- `ConvertFrom-FotonLnk` - ANSI LocalBasePath from LinkInfo when present.
- `ConvertFrom-FotonEvtx` - ElfFile via Get-WinEvent -Path; selected Event IDs only, capped. Not a full log dump.
- `ConvertFrom-FotonJumplist` - automatic DestList v1/2/3/4 (path + FILETIME at offset 100) and custom destinations via Shell Link CLSID. Unknown DestList versions are unsupported, not guessed.
- `ConvertFrom-FotonAmcache` - Win10+ InventoryApplicationFile named values from a copied hive. Key last-write is not execution. Legacy Root\File numeric IDs are unsupported. Does not `reg load`.
- `Invoke-FotonParse` - case folder, ZIP, or one `.pf`/`.lnk`/`.evtx`/jumplist/`Amcache.hve`. Writes `analysis/parsed_records.csv` and `analysis/Foton_Parse.html`. Does not invent names for MAM Prefetch. Does not parse SRUM ESE. Does not write `findings.csv`.
- `Invoke-FotonExternalParse` - optional EZ Tools / Hayabusa / Chainsaw **if already on PATH**. Writes hashed files under `analysis/external/<tool>/`. No download. Native ConvertFrom-Foton* remains the fallback.

Fixtures: `tests/Fixtures/Parse/` (prefetch, DestList). LNK and custom jumplist tests create a shortcut via COM. Amcache tests write a synthetic `regf` hive (not `reg save`).

If the format version is unknown, emit an explicit unsupported-version record. Wrong
timestamps are worse than missing ones.
