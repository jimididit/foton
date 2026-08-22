# Public/Report

Render HTML (and later other formats) from a loaded package + findings.

All untrusted strings through `ConvertTo-FotonSafeHtml`. CSS/JS in single-quoted
here-strings; closing `'@` at column 0.

The report must remain openable from **inside the extracted case folder** so relative
artifact links resolve. Re-reporting after Analyze should not rewrite original collect
hashes — put analysis output in a dedicated tree or append-only manifest.
