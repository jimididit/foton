# Backlog

Use this file when you return to Foton after a break. Layers and artifact inventory: [COVERAGE.md](COVERAGE.md). How to run: [USAGE.md](USAGE.md).

The v1 → module extract is **done** ([MIGRATION.md](MIGRATION.md)). Endpoint files are the flatten scripts, not a 3k-line collector.

---

## Will implement (next product work)

Ordered. Prefer the next Collect P1 over exotic ASEPs.

1. **Jumplist parser** - Collect already inventories LNKs/jumplists; parse copied files offline with fixtures first.
2. **Amcache parser** - Collect copies `Amcache.hve`. Parse only if we can do it correctly (offline hive), otherwise emit unsupported + point at a hive tool. Do not invent timestamps.
3. **Screensaver / SilentProcessExit / netsh helpers / time providers** - Collect P2, lower-volume ASEPs.
4. Close remaining **public-release lab ticks** (below) on a VM: v1 zip + Foton folder, parse copied `.pf`, IOC fixture, carve throw, locked files, standard-user skips.

**SRUM:** Collect copies the DB + WAL/SHM. A real ESE parser in PowerShell is unlikely to be correct; prefer “copied, not parsed” until a dedicated approach exists.

---

## Considering (not scheduled)

Propose before building.

- **In-report artifact browser** - navigable CSV/JSON inside `Foton_Report.html`. Offline only; cap rows; escape cells. Decide `file://` vs embed vs local HTTP first. Findings-first HTML already exists.
- **TUI / GUI workstation shell** - wrap Collect/Baseline/open HTML. Does **not** replace one-file IR scripts. No risk score. Prefer TUI before a signed exe. Blocked on public-release bar being mostly green.
- **MAM Prefetch inflate** - Win10+ `.pf` names stay empty until we inflate correctly.
- **NTFS unallocated carve** - not in PowerShell; see [CARVE.md](CARVE.md).
- **Authenticode** for flatten scripts / ExecutionPolicy story.
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
- [ ] Installer or zip that analyzes a case without cloning the repo

**Lab (admin + standard user)**

- [x] Collect → open `Foton_Report.html` from the case folder (`file://`)
- [x] Recapture baseline after schema bumps; Compare day0 vs day1 (schema **1.12.0**)
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
