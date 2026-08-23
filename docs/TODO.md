# Backlog and later considerations

Items here are **not** the current migration step. Capture them so a later chat or contributor does not lose the intent.

## In-report artifact browser (consideration)

**Status:** Not started. Do after Collect/Analyze/Report compose on a package (migration step 4+), so the UI reads files from the case folder rather than `$script:` cache only.

**Idea:** Extend `WinFoton_Report.html` (later `New-FotonReport`) beyond finding cards and a few summary tables. The examiner should be able to **navigate collected artifacts** - especially CSV/JSON in `01_`–`09_` - inside the same HTML package, in a clean organized UI, without opening Excel for every file.

**Why:** The report is the thing people actually open. Manifest links to raw CSV work, but a dedicated viewer (sortable tables, column filters, category nav, maybe process tree / connection charts) would make triage and audits faster and still stay **offline** (no server, relative links, hashed package).

**Constraints:**

- Stay **offline**. No CDN, no fetching CSVs from the network. Either embed a capped preview or `fetch()` local relative files (file:// vs opening via a tiny local viewer has CORS/`file:` limits - decide explicitly; a single HTML+JS that loads sibling CSVs often needs the report opened from a local http viewer or inlined JSON).
- **Cap rows** in the UI (same idea as `MaxEventsPerLog`). Full files remain the source of truth; the viewer is a convenience.
- Escape all cell text (`ConvertTo-FotonSafeHtml`). Do not execute CSV content as HTML.
- Visualizations (charts, graphs) are optional extras: process parent/child, external connections, finding counts by category. Prefer tables first.
- Findings stay observations. Charts must not imply “compromised.”
- Re-reporting after Analyze should add an `analysis/` or viewer pane without rewriting original collect hashes.

**Suggested shape (when built):** left nav by category / manifest task; main pane is a table for the selected artifact; optional “related findings” that cite that file.

---

When picking this up: propose the `file:` vs embed tradeoff before writing a large JS app.

---



## Public-release bar (usability + testing)

Do not treat a GitHub release as “ready for first-time DFIR users” until most of this is true.

**Usage (non-PowerShell operators)**

- [x] One-file collect: `dist/Foton-Collect.ps1` after `Build-Standalone.ps1`
- [x] Workstation wrapper: `Foton.cmd` / `docs/USAGE.md` (`analyze`, `baseline`, `compare`, `parse`, `ioc`, `carve`)
- [x] One-file baseline: `dist/Foton-Baseline.ps1` → hashed folder/ZIP + HTML snapshot (see “Flattened baseline package”)
- [ ] Signed `Foton-Collect.ps1` or documented Authenticode story (ExecutionPolicy)
- [ ] Installer or zip that does not require cloning the repo to analyze a case
- [ ] Double-click collect that picks an output folder without `-OutputPath` (prompt or Desktop default that is obvious)

**Layers to exercise on a lab VM (admin + standard user)**

- [x] Collect → open `Foton_Report.html` from the case folder (file://)
- [x] Recapture baseline after every `BaselineSchemaVersion` bump; Compare day0 vs day1 (now **1.5.0**)
- [ ] `Get-FotonPackage` on a `WinFoton_*` v1 zip and a `Foton_*` flatten folder
- [ ] Parse `.pf` already copied into `08_Filesystem/prefetch` (not live `%SystemRoot%\Prefetch`)
- [ ] IOC txt + csv against a known fixture package
- [ ] Carve on a tiny PE blob; confirm missing-file throws
- [ ] Locked/missing artifacts: manifest errors, no crash, Info visibility gaps
- [ ] Unreadable Security log / Prefetch as standard user: skipped, not fatal

**Honesty**

- Findings never say compromised / attributed
- Methodology / limitations updated if collect footprint changes
- Baseline provenance caveat in USAGE and report

**Still later**

- In-report CSV browser (this file, above)
- Baseline/Collect gaps in **[docs/COVERAGE.md](COVERAGE.md)** (next: LsaPackage / print monitors; EVTX parser; Amcache/SRUM *parsers*; MAM Prefetch inflate later)
- EVTX / jumplist / Amcache / SRUM parsers (files are now in the collect package)
- Real NTFS carve engine (see `docs/CARVE.md`)

---



## Flattened baseline package (same shipping idea as Collect)

**Status:** Snapshot HTML, flatten, and compare-HTML exist (`New-FotonBaselineReport`, `New-FotonBaselineCompareReport`, `build/Build-BaselineStandalone.ps1`).

**User story:** Someone on a host (or a golden VM) copies **one file**, runs it, and gets a folder they can zip/hash/email to an analyst - without cloning the repo or reading JSON. Optional HTML so *they* can see “what was captured,” not so the tool declares the host clean.

**Ship format**

1. `build/Build-BaselineStandalone.ps1` emits `dist/Foton-Baseline.ps1`.
2. Default output is a **package folder**, not a naked JSON on the Desktop:
  `FotonBaseline_<HOST>_<UTCSTAMP>Z/`
  - `baseline.json` (schema-stamped; compared payload still hashed in the header)
  - `hashes.csv` / `*_PACKAGE_HASH.txt` after optional ZIP (same custody loop as Collect)
  - `coverage.json`: what providers failed / not elevated
  - `Foton_Baseline.html` - **snapshot of this observation**, not a findings dump
3. Operator copies the ZIP + hash file off-host. Analyst runs `Compare-FotonBaseline` (or later `Foton.cmd compare`) on two packages / two JSON paths. Compare stays **offline**.

**HTML snapshot - not too much if it stays dumb**

Worth doing. JSON is the source of truth; HTML is a capped, escaped table per `RecordType` (identity + compared fields), header block (hostname, schema, payload SHA-256, elevated, captured UTC), and the provenance caveat: *picture of this moment, not when or who*. Cap rows per table. No “secure / infected” language. No charts that imply health score.

**HTML compare report - the visual that actually matters**

`Compare-FotonBaseline` (workstation) writes **Added / Removed / Modified** to `Foton_BaselineCompare.html` beside the difference JSON. Do not generate a compare report on the endpoint (no second JSON there).

**Not in this flatten**

- Live Analyze heuristics (LOLBin lists, etc.)
- Re-using `Foton_Report.html` triage cards as if a baseline were a collect
- Writing the baseline into an existing Collect case folder (different schema, different hash set)

**Public-release bar:** one-file baseline is implemented; still exercise on a VM (admin + standard user) before calling it public-ready.

---



## Visualization: GUI executable and/or TUI (consideration)

**Status:** Not started. Capture only - do not build until Collect + Baseline flatten + HTML snapshot exist and the public-release bar is mostly green. A GUI will not fix missing providers or a JSON-only day0.

**Why consider it:** `Foton.cmd` still assumes a repo checkout. End users who will never `Import-Module` still hit walls (ExecutionPolicy, “which file do I run,” opening HTML via `file://`). A single Windows binary or a keyboard TUI could be *one* entry: Collect / Baseline / open last package / compare two baselines.

**Constraints (non-negotiable if we build this)**

- **Offline.** No phone-home, no CDN, no “check for updates” that hits the network from Analyze/Parse/Carve.
- **Does not replace the one-file Collect/Baseline scripts** for RMM/USB. Those stay the IR drop. A GUI is the *workstation* (and maybe a lab golden-image) experience.
- **Findings stay observations.** UI chrome must not grow a “risk score” or red “compromised” banner.
- **PS 5.1 Collect/Baseline** remain the acquisition engines. A WinForms/WPF/WinUI shell that shells out to `Foton-Collect.ps1` / `Foton-Baseline.ps1` is more honest than rewriting acquisition in C#.
- **TUI** (e.g. Spectre.Console, or a PS-only menu) is cheaper than a signed `.exe` and still helps operators who live in a terminal. Prefer a TUI prototype before an installer.
- Signing, SmartScreen, and “is this malware” on a DFIR tool that contains LOLBin strings is a product problem - same as the Authenticode bar above.

**Suggested order if picked up:** (1) TUI menu wrapping existing commands, (2) HTML snapshot/compare, (3) only then a packaged exe that launches those scripts + opens the HTML. Propose stack (WinForms vs WPF vs Avalonia vs “just mshta/WebView on the report”) before writing it.

**Relate to in-report browser:** a GUI that is only a nicer `Foton_Report.html` host (local HTTP to dodge `file://` CORS) may be enough visualization without a full app.