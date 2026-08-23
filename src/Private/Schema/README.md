# Private/Schema

On-disk contracts. Bump the matching version in `Foton.psd1` → `PrivateData.Foton`
when you change:

| Schema | Means |
|--------|--------|
| CollectSchemaVersion | Artifact folder names, task names, column sets |
| BaselineSchemaVersion | Identity keys and compared fields per record type |
| FindingsSchemaVersion | Finding object properties (Tier, Artifact, WhyItMatters, …) |

`Compare-FotonBaseline` must **refuse** incompatible baseline schemas with a clear error.
Silent diffs across schema versions are a defect.

Package unit: a case **folder or ZIP**. Every public command should accept that unit so
Collect on the endpoint and Analyze on the workstation compose without recollecting.

## What schema is not

Schema versions do **not** list every Windows artifact Foton might one day collect.
That inventory (use cases, Collect vs Baseline, ASEP gaps, parse backlog) is
[docs/COVERAGE.md](../../../docs/COVERAGE.md).

| If you… | Bump |
|---------|------|
| Add a Collect CSV with a new task name or columns | CollectSchemaVersion |
| Add or change a baseline RecordType / identity / compared fields | BaselineSchemaVersion (recapture day0) |
| Add a finding property | FindingsSchemaVersion |
| Only document a *planned* provider | Nothing - edit COVERAGE.md |

Collect packages: **1.2.0** (`prefetch_files`, `amcache_hive`, `srum_database` copies under `08_Filesystem/`). Baseline **1.11.0** (KnownDll, ProxyConfig). Older JSON will not compare across baseline schema bumps. You may recapture day0 once after a batch of provider adds.

Empty tables are allowed; empty *because we never mapped the artifact* (Settings
startup vs Startup folder) is a coverage bug, not a schema event, until the
provider exists and the version bumps.
