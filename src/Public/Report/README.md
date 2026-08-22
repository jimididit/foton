# Public/Report

Render HTML from a loaded package + findings (`New-FotonReport`), a baseline
snapshot (`New-FotonBaselineReport`), or a baseline compare
(`New-FotonBaselineCompareReport`).

All untrusted strings through `ConvertTo-FotonSafeHtml`. CSS/JS in single-quoted
here-strings; closing `'@` at column 0.

The triage report must remain openable from **inside the extracted case folder**.
Default path is `Foton_Report.html` at the case root. Baseline packages use
`Foton_Baseline.html` beside `baseline.json`. Compare HTML defaults to
`Foton_BaselineCompare.html` beside the **difference** JSON (workstation; not
emitted by `Foton-Baseline.ps1`). Re-reporting must not rewrite collect `hashes.csv`.

In-report CSV browser: see `docs/TODO.md`.
