# Carve

Signature scanning of a **capped** blob is supported. Full NTFS unallocated-space carving is **not** implemented.

## What `foton carve` does

Walks a file you already copied (default max 8 MiB). Records **MZ** at any offset and **PE** when `e_lfanew` points at `PE\0\0`. Hits are **Tier 3** (offset + window hash, no filename). Corroborate with Prefetch, LNK, or a collected file hash.

```powershell
.\foton.exe carve D:\evidence\unalloc-sample.bin
# optional: -MaxBytes <n> -MaxHits <n>
```

## Why not NTFS carving

NTFS `FILE` records, fixups, attribute lists, and slack need careful little-endian parsing at volume scale. A half-correct parser invents timestamps and parent paths, and in DFIR that is worse than "not parsed." Use a dedicated tool against a forensic image.

## Out of scope

- Walking `$MFT` or unallocated clusters in `foton parse`
- Collecting `$MFT` in `foton-collect` (use KAPE/ORC). Optional `-IncludeUsnJournal` copies `$J` only; the default is `fsutil usn queryjournal` text
- Writing NTFS from Foton
- Treating carve hits as Collect facts
- Downloading carving tools at runtime (Analyze stays offline)

## Future direction

A well-known offline tool whose output Foton ingests: offsets only, filename only when a resident name parsed cleanly. Carve output stays Tier 3 until corroborated.
