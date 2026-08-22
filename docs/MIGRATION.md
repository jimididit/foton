# Migration plan (v1 WinFoton.ps1 → Foton module)

Approved sequence. **Do not start a later step until the previous one is reviewable.**

`WinFoton.ps1` remains the live collector (do not rename internals). Privilege/coverage behavior in that file is part of the reference for extract.

## Status

| Step | Description | Status |
|------|-------------|--------|
| 0 | Scaffold module, tests, docs, Foton naming | **Done** (this tree) |
| 1 | Extract Core helpers verbatim with `Foton` prefix; prove helper behavior vs `WinFoton.ps1` | **Done** |
| 2 | Split nine collection sections into `Public/Collect/*` | Not started |
| 3 | Patterns + remaining hardening tables as data files | Partial: command/path lists are in `src/Private/Patterns/*.txt` (needed so Core .ps1 is not AMSI-blocked). Hardening checks still in `WinFoton.ps1` |
| 4 | Findings engine → `Public/Analyze`; HTML → `Public/Report`; **load `$script:FotonSession.Data` from package files** so re-report works offline | Not started |
| 5 | `Build-Standalone.ps1` writes `dist/Foton-Collect.ps1`; VM run | Not started |
| 6 | New capabilities: Baseline first, then IOC, then one parser with fixture, then carve **proposal** | Not started |

## Equivalence (step 1–5)

Do not compare two live runs field-for-field (PIDs and connections will differ). Compare **task names, file names, column sets, and finding titles** against a gold v1 package from the same host class.

## After step 4

`Get-FotonPackage` should open a v1 ZIP produced by `WinFoton.ps1` so historical cases still analyze. Folder prefix `WinFoton_*` remains valid input even when new collects use `Foton_*`.
