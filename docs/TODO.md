# Backlog

Use this file when you return to Foton after a break. Layers and artifact inventory: [COVERAGE.md](COVERAGE.md). How to run: [USAGE.md](USAGE.md).

The v1 → module extract is **done** ([MIGRATION.md](MIGRATION.md)). Endpoint files are the flatten scripts, not a 3k-line collector.

---

## Will implement (next product work)

Ordered. Prefer the next Collect P1 over exotic ASEPs.

1. Close remaining **public-release lab ticks** (below) on a VM: v1 zip + Foton folder, parse copied `.pf`, IOC fixture, carve throw, locked files, standard-user skips.
2. **External tool provisioning** - design agreed, not built: [TOOLS.md](TOOLS.md). Collect is one file for the target user; the workstation side still needs a manual tool download plus a correct `PATH`, and when that is missing compose quietly produces no findings. Scope for the first cut:
   - `Install-FotonTool` + `Foton.cmd tools`, **Hayabusa only**. Separate setup command; compose stays offline and never prompts, it just names the command in its `NotOnPath` row.
   - Foton-owned tool root (`%LOCALAPPDATA%\Foton\tools`) + `tools.json`. Resolution order in `Invoke-FotonExternalParse`: `-ToolPath`, then manifest, then `PATH`. **Do not modify `PATH`** - see TOOLS.md for why.
   - Pinned version + expected SHA-256, refuse on mismatch; offline install from a local archive folder.
   - Add tool **version** and rule-set version to the external parse inventory and the report's External Tool Passes section. Without it, external findings are not reproducible.
   - Tests: faked catalog and a faked archive; no network in tests.

**SRUM:** Collect copies the DB + WAL/SHM. A real ESE parser in PowerShell is unlikely to be correct; prefer “copied, not parsed” until a dedicated approach exists.

---

## Considering (not scheduled)

Propose before building.

- **In-report artifact browser** - navigable CSV/JSON inside `Foton_Report.html`. Offline only; cap rows; escape cells. Decide `file://` vs embed vs local HTTP first. Findings-first HTML already exists.
- **TUI / GUI workstation shell** - wrap Collect/Baseline/open HTML. Does **not** replace one-file IR scripts. No risk score. Prefer TUI before a signed exe. Blocked on public-release bar being mostly green.
- **MAM Prefetch inflate** - Win10+ `.pf` names stay empty until we inflate correctly.
- **NTFS unallocated carve** - not in PowerShell; see [CARVE.md](CARVE.md).
- **Authenticode** for flatten scripts / ExecutionPolicy story. Note that signing does **not** prevent AMSI content scanning: the 1.27.0 Defender block was on script content, not trust.
- **Analyze zip** that does not require cloning the repo.
- **OptionalFeature / Appx** as baseline - noisy on consumer SKUs.
- **Codecs, gadgets, IE BHO** - low ROI.

---

## Public-release bar

Do not treat a GitHub release as ready for first-time DFIR users until most of this is true.

**Usage (operators)**

- [x] One-file collect: `dist/Foton-Collect.ps1`
- [x] One-file baseline: `dist/Foton-Baseline.ps1`
- [x] Workstation wrapper: `Foton.cmd` / USAGE.md
- [x] Desktop default `-OutputPath` on flatten (double-click still blocked by unsigned ExecutionPolicy)
- [ ] Documented Authenticode / ExecutionPolicy story
- [x] Collector loads past AMSI on a Defender-protected host (1.27.0; guarded by `build/Test-FotonAmsiLoad.ps1`, operator guidance in USAGE.md)
- [ ] Verify the collector loads under at least one non-Microsoft endpoint product before release
- [ ] Installer or zip that analyzes a case without cloning the repo
- [ ] Workstation tool setup that does not require a manual download plus a hand-edited `PATH` ([TOOLS.md](TOOLS.md))

**Lab (admin + standard user)**

- [x] Collect → open `Foton_Report.html` from the case folder (`file://`)
- [x] Recapture baseline after schema bumps; Compare day0 vs day1 (schema **1.14.0** requires a new day0)
- [ ] `Get-FotonPackage` on a historical `WinFoton_*` zip **and** a `Foton_*` flatten folder
- [ ] Parse `.pf` / EVTX already in the package (not live Prefetch)
- [ ] IOC txt + csv against `tests/Fixtures`
- [ ] Carve tiny PE; missing-file throws
- [ ] Locked/missing artifacts: manifest, no crash, Info gaps
- [ ] Standard-user: Security / Prefetch skipped, not fatal

**Honesty (keep true)**

- Findings never say compromised / attributed
- Methodology / limitations updated if collect footprint changes
- Baseline provenance caveat in USAGE and HTML

---

## Flattened baseline package

**Status: done.** `New-FotonBaselineReport`, compare HTML, `Build-BaselineStandalone.ps1`.

Operator copies one file, gets `FotonBaseline_<HOST>_<UTC>Z/` with `baseline.json`, hashes, `coverage.json`, `Foton_Baseline.html`. Analyst compares offline. Do not emit compare HTML on the endpoint. Do not mix baseline into a Collect case folder.

---

## In-report artifact browser (consideration)

**Status:** Not started. HTML already has search/nav chrome. A full CSV browser is separate.

Stay offline, cap rows, `ConvertTo-FotonSafeHtml`, no “compromised” charts. Propose `file://` vs embed before a large JS app.
