# Carve proposal (step 6)

Foton Analyze/Parse stay in PowerShell. **Full NTFS unallocated-space carving should not.**

## Why not PowerShell

- NTFS `FILE` records, fixups, attribute lists, and slack need careful little-endian parsing at volume scale. A half-correct parser invents timestamps and parent paths — in DFIR that is worse than “not parsed.”
- Live images are tens to hundreds of GB. PS 5.1 arrays and `Get-Content -Encoding Byte` do not stream well.
- Carved data is **Tier 3** until a path/timestamp from a live or collected artifact corroborates it.

## Proposed approach (when we build it)

1. **Do not** walk `$MFT` or unallocated clusters in `ConvertFrom-Foton*` cmdlets.
2. Prefer a **small C# `Add-Type`** (or a well-known offline tool whose output we ingest) that:
   - Reads a raw image or unallocated blob the analyst already copied
   - Emits **records with offsets only** (byte offset, signature, recovered bytes hash)
   - Does not claim a filename unless the resident name attribute parsed cleanly
3. Foton’s job: `Invoke-FotonCarve` wraps that engine, stores output under `analysis/carve/`, hashes it, and creates **Tier 3** findings that cite the carve file and say what would move them to Tier 2 (matching Prefetch, USN, or a collected executable hash).
4. Signature-only scans (e.g. “bytes look like an MZ at offset X”) can be a later *narrow* PowerShell helper over a **capped** blob, with the same Tier 3 rule.

## Out of scope until that engine exists

- Writing NTFS from Foton
- Using carve output as Collect facts
- Network/download of carving tools at runtime (Analyze stays offline; the engine is local)
