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
