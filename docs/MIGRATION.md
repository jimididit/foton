# Migration (v1 → Foton module)

The extract from a single live-triage script into the modular tree is **complete**. Product work is [COVERAGE.md](COVERAGE.md) and [TODO.md](TODO.md).

Live collect/baseline on an endpoint is `dist/Foton-Collect.ps1` / `dist/Foton-Baseline.ps1`. Analyze/parse/compare on a workstation is `Foton.cmd` / `Import-Module .\Foton.psd1`.

A frozen `WinFoton.ps1` may remain in git as a **historical v1 reference** (helper names, hardening-count tests, old `WinFoton_*` packages). It is **not** the operator collector. Do not rename strings inside it if you keep it. Do not send it to endpoints.

| Step | Description | Status |
|------|-------------|--------|
| 0–4 | Scaffold, Core, Collect files, patterns, Analyze/Report from package | **Done** |
| 5 | Flatten Collect; VM runs | **Done** |
| 6 | Baseline, IOC, parsers, carve proposal | **Done** (ongoing product: schema bumps) |

`Get-FotonPackage` should still open a historical `WinFoton_*` folder/ZIP as well as `Foton_*`.
