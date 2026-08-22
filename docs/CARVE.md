# Carve

**Full NTFS unallocated-space carving is not implemented in PowerShell.** Signature scanning of a **capped** blob is.

## What `Invoke-FotonCarve` does now

Walks a file you already copied (max 8 MiB by default). Records **MZ** at any offset and **PE** when `e_lfanew` points at `PE\0\0`. Hits are **Tier 3** (offset + window hash, no filename). Use Prefetch, LNK, or a collected file hash to corroborate.

## Why not NTFS in PowerShell

- NTFS `FILE` records, fixups, attribute lists, and slack need careful little-endian parsing at volume scale. A half-correct parser invents timestamps and parent paths - in DFIR that is worse than “not parsed.”
- Live images are tens to hundreds of GB. PS 5.1 arrays do not stream well.

## Later (not this release)

A small C# `Add-Type` or a well-known offline tool whose output we ingest: offsets only, filename only if the resident name parsed cleanly. Foton would hash `analysis/carve/` and keep Tier 3 until corroborated.

## Out of scope

- Walking `$MFT` or unallocated clusters in `ConvertFrom-Foton*`
- Writing NTFS from Foton
- Using carve output as Collect facts
- Downloading carving tools at runtime (Analyze stays offline)
