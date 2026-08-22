# Public/Parse

Pure functions over bytes or files already in a package. No live system, no network,
no writes except what the caller asked for.

`ConvertFrom-FotonPrefetch` is the first parser (SCCA name; MAM is unsupported, not guessed). Fixture: `tests/Fixtures/Parse/`.


If the format version is unknown, emit an explicit unsupported-version record. Wrong
timestamps are worse than missing ones.
