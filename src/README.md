# src/

Foton source. `Foton.psm1` dotsources **Private** then **Public**.

| Path | What belongs here | Live host? |
|------|-------------------|------------|
| `Private/Core` | Shared helpers (status, hash, registry, HTML escape, package I/O) | Only if called from Collect/Baseline |
| `Private/Patterns` | Data: command/path/RAT lists, hardening checks - not logic | n/a |
| `Private/Schema` | Versioned contracts for packages, baselines, findings | n/a |
| `Public/Collect` | One collection category per file | Yes (endpoint) |
| `Public/Baseline` | Snapshot + diff + one file per provider | Capture: yes. Diff: anywhere |
| `Public/Parse` | Pure parsers over files/bytes | Never |
| `Public/Carve` | Signature carving over supplied blobs | Never |
| `Public/Analyze` | Rules + IOC match over a package | Never |
| `Public/Report` | HTML/CSS/JS rendering from findings + data | Never |

**Adding a feature:** new file in the matching folder, filename = function name, comment-based help, a Pester test. Public commands must be listed in `Foton.psd1` `FunctionsToExport`.

**Do not** add network calls or live registry/WMI reads under Parse, Carve, or Analyze.

Live triage behavior for v1 equivalence still lives in the frozen `WinFoton.ps1` at the repo root until Collect is extracted here and `build/Build-Standalone.ps1` produces `dist/Foton-Collect.ps1`.
