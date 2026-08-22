# Public/Parse

Pure functions over bytes or files already in a package. No live system, no network,
no writes except what the caller asked for.

`ConvertFrom-FotonPrefetch -Path <file>` returns objects. Every parser needs a fixture
under `tests/Fixtures/` and a Pester test before it counts as done.

If the format version is unknown, emit an explicit unsupported-version record. Wrong
timestamps are worse than missing ones.
