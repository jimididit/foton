# Public/Parse

Pure functions over bytes or files already in a package. No live system, no network,
no writes except what the caller asked for.

- `ConvertFrom-FotonPrefetch` - SCCA executable name; MAM is unsupported, not guessed.
- `ConvertFrom-FotonLnk` - ANSI LocalBasePath from LinkInfo when present.

Fixtures: `tests/Fixtures/Parse/` (prefetch). LNK tests create a shortcut via COM.

If the format version is unknown, emit an explicit unsupported-version record. Wrong
timestamps are worse than missing ones.
