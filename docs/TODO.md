# Backlog

Use this file when you return to Foton after a break. Strategy and course check: [LANDSCAPE.md](LANDSCAPE.md). Layers and artifact inventory: [COVERAGE.md](COVERAGE.md). How to run: [USAGE.md](USAGE.md). Tool install design: [TOOLS.md](TOOLS.md).

The v1 → module extract is **done** ([MIGRATION.md](MIGRATION.md)). Endpoint files are the flatten scripts, not a 3k-line collector. The landscape *compose* plan through **1.27.0** is largely landed (raw copies, Hayabusa compose + footprint exclusion, AMSI fix). Next work is **finish and convenience**, not a new architecture.

**North star (from LANDSCAPE):** go-to Windows **audit / known-good baseline** tool; competitive IR via compose — not by absorbing KAPE/Hayabusa/Autoruns into PowerShell. Anti-monstrosity: every item below must strengthen baseline/audit, the package for specialists, or compose/analyze convenience.

---

## Will implement (next product work)

Ordered. Prefer finish and compose convenience over exotic ASEPs or new native parsers.

1. ~~Close remaining **public-release lab ticks**~~ — automated in `tests/Unit/Lab.Tests.ps1` (package open, parse `.pf`/EVTX-in-package, IOC, carve, locked/missing, elevation skip). Live Collect → HTML + standard-user Security/Prefetch on a VM still operator smoke if you care before release.
2. ~~**External tool provisioning**~~ — **done in 1.28.0** for Hayabusa: [TOOLS.md](TOOLS.md). Chainsaw / EZ Tools catalog entries still open when those paths are verified.
3. ~~**Analyze consumes compose output**~~ — **done in 1.29.0** for PECmd / EvtxECmd (coverage + user-writable paths + high-attention EventIds; findings cite the tool). Chainsaw ingest still open.
4. ~~**Baseline / audit operator path**~~ — **done in 1.30.0**: USAGE temporal + fleet recipes; `Compare-FotonBaseline` writes `baseline_diff.csv` and cites provider FalsePositives; Analyze lifts High-attention `baseline_diff` rows (not Info software bumps). No new ASEP providers.
5. **Analyze-without-clone zip** + documented Authenticode / ExecutionPolicy story (release bar).

**SRUM:** Collect copies the DB + WAL/SHM. A real ESE parser in PowerShell is unlikely to be correct; prefer “copied, not parsed” until a dedicated approach exists.

---

## Considering (not scheduled)

Propose before building. Most of these are monstrosity risks if done early.

- **In-report artifact browser** — navigable CSV/JSON inside `Foton_Report.html`. Offline only; cap rows; escape cells. Decide `file://` vs embed vs local HTTP first. Findings-first HTML already exists.
- **TUI / GUI workstation shell** — wrap Collect/Baseline/open HTML. Does **not** replace one-file IR scripts. No risk score. Prefer TUI before a signed exe. **Blocked** on public-release bar being mostly green.
- **MAM Prefetch inflate in PowerShell** — wrong default; prefer PECmd via compose once tools install exists. Keep native “unsupported,” never guessed names.
- **NTFS unallocated carve** — not in PowerShell; see [CARVE.md](CARVE.md).
- **ZIP package session** — single extract reused across parse/compose/analyze so chaining a ZIP does not silently drop compose output (USAGE already says extract first; a code fix is optional later).
- **OptionalFeature / Appx** as baseline — noisy on consumer SKUs.
- **Codecs, gadgets, IE BHO** — low ROI; use Autoruns.
- **Chainsaw** verify + ingest — after Hayabusa install path is solid.
- **`$MFT` copy** — charter decision vs KAPE/ORC handoff; do not parse in PS.

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
- [x] Workstation tool setup that does not require a manual download plus a hand-edited `PATH` ([TOOLS.md](TOOLS.md) — Hayabusa via `Install-FotonTool` in 1.28.0; EZ Tools/Chainsaw still PATH)

**Lab (admin + standard user)**

- [x] Collect → open `Foton_Report.html` from the case folder (`file://`)
- [x] Recapture baseline after schema bumps; Compare day0 vs day1 (schema **1.14.0** requires a new day0)
- [x] `Get-FotonPackage` on a historical `WinFoton_*` zip **and** a `Foton_*` flatten folder (`tests/Unit/Lab.Tests.ps1`)
- [x] Parse `.pf` / EVTX already in the package (not live Prefetch) (`Lab.Tests.ps1`; EVTX via wevtutil export into a temp case)
- [x] IOC txt + csv against `tests/Fixtures` (`Lab.Tests.ps1`)
- [x] Carve tiny PE; missing-file throws (`Lab.Tests.ps1`)
- [x] Locked/missing artifacts: CopyError / Missing, no crash (`Lab.Tests.ps1`)
- [x] Elevation skip path: `RequiresElevation` → `SkippedNotElevated` (`Lab.Tests.ps1`; live standard-user Security/Prefetch still optional VM smoke)

**Honesty (keep true)**

- Findings never say compromised / attributed
- Methodology / limitations updated if collect footprint changes
- Baseline provenance caveat in USAGE and HTML
- External-tool hits name the engine; collector footprint is disclosed when excluded

---

## Flattened baseline package

**Status: done.** `New-FotonBaselineReport`, compare HTML, `Build-BaselineStandalone.ps1`.

Operator copies one file, gets `FotonBaseline_<HOST>_<UTC>Z/` with `baseline.json`, hashes, `coverage.json`, `Foton_Baseline.html`. Analyst compares offline. Do not emit compare HTML on the endpoint. Do not mix baseline into a Collect case folder.

This is the wedge for “go-to audit/baseline.” Next baseline work is operator recipes and diff→findings, not a second packaging format.

---

## In-report artifact browser (consideration)

**Status:** Not started. HTML already has search/nav chrome. A full CSV browser is separate.

Stay offline, cap rows, `ConvertTo-FotonSafeHtml`, no “compromised” charts. Propose `file://` vs embed before a large JS app. Do not schedule ahead of the public-release bar.
