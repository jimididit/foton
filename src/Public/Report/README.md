# Public/Report

Render HTML from a loaded package + findings (`New-FotonReport`), a baseline
snapshot (`New-FotonBaselineReport`), a baseline compare
(`New-FotonBaselineCompareReport`), or offline parse rows (`New-FotonParseReport`).

All untrusted strings through `ConvertTo-FotonSafeHtml`. CSS/JS in single-quoted
here-strings; closing `'@` at column 0. **No CDN.**

**Required chrome (every HTML report):** sticky filter (`#foton-q`), generated
section jump list (`#foton-toc`), and a Top link. Shared helpers:
`Get-FotonReportNavCss` (a full `<style>` element), `Get-FotonReportNavBarHtml`,
`Get-FotonReportNavScript`, and `Get-FotonReportMarkSvg` (wave-packet brand mark)
(`src/Private/Core/`).
Do not ship a report that is
only a long unfiltered table. Filter client-side; JSON/CSV remains the source
of truth. Caps still apply (`MaxRows`).

The triage report must remain openable from **inside the extracted case folder**.
Default path is `Foton_Report.html` at the case root. Baseline packages use
`Foton_Baseline.html` beside `baseline.json`. Compare HTML defaults to
`Foton_BaselineCompare.html` beside the **difference** JSON (workstation; not
emitted by `Foton-Baseline.ps1`). Parse HTML is `analysis/Foton_Parse.html`
(not `findings.csv`). Re-reporting must not rewrite collect `hashes.csv`.

An in-report CSV browser is planned, not built.
