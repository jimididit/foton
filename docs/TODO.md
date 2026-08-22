# Backlog and later considerations

Items here are **not** the current migration step. Capture them so a later chat or contributor does not lose the intent.

## In-report artifact browser (consideration)

**Status:** Not started. Do after Collect/Analyze/Report compose on a package (migration step 4+), so the UI reads files from the case folder rather than `$script:` cache only.

**Idea:** Extend `WinFoton_Report.html` (later `New-FotonReport`) beyond finding cards and a few summary tables. The examiner should be able to **navigate collected artifacts** — especially CSV/JSON in `01_`–`09_` — inside the same HTML package, in a clean organized UI, without opening Excel for every file.

**Why:** The report is the thing people actually open. Manifest links to raw CSV work, but a dedicated viewer (sortable tables, column filters, category nav, maybe process tree / connection charts) would make triage and audits faster and still stay **offline** (no server, relative links, hashed package).

**Constraints:**

- Stay **offline**. No CDN, no fetching CSVs from the network. Either embed a capped preview or `fetch()` local relative files (file:// vs opening via a tiny local viewer has CORS/`file:` limits — decide explicitly; a single HTML+JS that loads sibling CSVs often needs the report opened from a local http viewer or inlined JSON).
- **Cap rows** in the UI (same idea as `MaxEventsPerLog`). Full files remain the source of truth; the viewer is a convenience.
- Escape all cell text (`ConvertTo-FotonSafeHtml`). Do not execute CSV content as HTML.
- Visualizations (charts, graphs) are optional extras: process parent/child, external connections, finding counts by category. Prefer tables first.
- Findings stay observations. Charts must not imply “compromised.”
- Re-reporting after Analyze should add an `analysis/` or viewer pane without rewriting original collect hashes.

**Suggested shape (when built):** left nav by category / manifest task; main pane is a table for the selected artifact; optional “related findings” that cite that file.

---

When picking this up: propose the `file:` vs embed tradeoff before writing a large JS app.
