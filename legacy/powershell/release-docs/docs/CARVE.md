# Carve

Signature scanning of a **capped** blob is supported. Full NTFS unallocated-space carving is **not** implemented in PowerShell.

## What `Invoke-FotonCarve` does

Walks a file you already copied (default max 8 MiB). Records **MZ** at any offset and **PE** when `e_lfanew` points at `PE\0\0`. Hits are **Tier 3** (offset + window hash, no filename). Corroborate with Prefetch, LNK, or a collected file hash.

```powershell
Invoke-FotonCarve -Path D:\evidence\unalloc-sample.bin
# optional: -MaxBytes, -MaxHits
```

## Why not NTFS in PowerShell

NTFS `FILE` records, fixups, attribute lists, and slack need careful little-endian parsing at volume scale. A half-correct parser invents timestamps and parent paths-in DFIR that is worse than “not parsed.” Live images are tens to hundreds of GB; Windows PowerShell 5.1 arrays do not stream that well.

## Out of scope

- Walking `$MFT` or unallocated clusters in `ConvertFrom-Foton*`
- Collecting `$MFT` in Foton-Collect (use KAPE/ORC). Optional `-IncludeUsnJournal` copies `$J` only; default is `fsutil usn queryjournal` text
- Writing NTFS from Foton
- Treating carve hits as Collect facts
- Downloading carving tools at runtime (Analyze stays offline)

## Future direction

A small native helper or a well-known offline tool whose output Foton ingests: offsets only; filename only when resident name parsed cleanly. Carve output stays Tier 3 until corroborated.
