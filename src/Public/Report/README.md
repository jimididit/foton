# Public/Report

Render HTML from a loaded package + findings (`New-FotonReport`).

All untrusted strings through `ConvertTo-FotonSafeHtml`. CSS/JS in single-quoted
here-strings; closing `'@` at column 0.

The report must remain openable from **inside the extracted case folder** so relative
artifact links resolve. Default path is `Foton_Report.html` at the case root (does not
overwrite `WinFoton_Report.html`). Re-reporting must not rewrite `00_Collection/hashes.csv`.

In-report CSV browser: see `docs/TODO.md`.
