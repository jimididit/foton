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
What Collect captures today is in [docs/USAGE.md](../../../docs/USAGE.md); the
maintainers keep the planned-coverage inventory separately.

| If you… | Bump |
|---------|------|
| Add a Collect CSV with a new task name or columns | CollectSchemaVersion |
| Add or change a baseline RecordType / identity / compared fields | BaselineSchemaVersion (recapture day0) |
| Add a finding property | FindingsSchemaVersion |
| Only document a *planned* provider | Nothing |

Collect packages: **1.13.0** adds `ServiceDll`, `ServiceDllSource`, and ServiceDll signature/hash/user-writable columns to `services.csv`. **1.12.0** exports loaded hives with `reg save` (SAM/SECURITY recorded as `NotCollectedByDesign`), copy tasks report `Partial`/`Failed`, `collection_coverage.json` gains `IncompleteTasks` and `ExcludedEarlierPackages`, `os_info` gains SMBIOS/BIOS release/EC fields, and `boot_and_firmware` gains `FirmwareDevices`. **1.11.0** adds the `-Deep` tasks (task scripts, PnP, DriverStore, gpresult). **1.10.0** (`SuspiciousHits` / `SuspiciousCmdHits` are now written empty - the columns remain, but the matching moved to Analyze; see below). **1.9.0** added registry hive / LNK / jumplist / task XML / browser DB / host log copies + optional USN + expanded EVTX + prior Prefetch/Amcache/SRUM. Baseline **1.14.0** (WdacApplockerPolicy).

The suspicious-command pattern list is deliberately **not** embedded in the Collect
flatten: inlined as a literal array it is a contiguous list of credential-theft and
LOLBin strings, and Defender AMSI blocks the whole file as
`Trojan:PowerShell/PSAttackTool.A` at load. Collect preserves the raw
`Command` / `Actions` / `CommandLine` values; `Invoke-FotonAnalysis` derives the hits
on the workstation and raises an Info visibility-gap finding when no pattern list is
loaded. Packages at collect schema &lt; 1.10.0 carry endpoint-computed hits, and those
are trusted as-is so old cases keep reproducing.

Empty tables are allowed; empty *because we never mapped the artifact* (Settings
startup vs Startup folder) is a coverage bug, not a schema event, until the
provider exists and the version bumps.
