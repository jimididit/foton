function New-FotonBaselineReport {
    <#
    .SYNOPSIS
        HTML snapshot of one baseline observation (offline). Not a findings report.

    .DESCRIPTION
        Tables per record type from baseline.json (or a FotonBaseline_* folder).
        Caps rows. Escapes every cell. Does not say the host is clean or compromised.
        The JSON file remains the source of truth for Compare-FotonBaseline.

    .PARAMETER Path
        baseline.json or a baseline package folder.

    .PARAMETER OutputPath
        HTML file. Defaults to Foton_Baseline.html beside the JSON.

    .PARAMETER MaxRows
        Max rows per table (default 200).

    .EXAMPLE
        New-FotonBaselineReport -Path D:\Baselines\FotonBaseline_PC1_20260822-120000Z

        Writes Foton_Baseline.html in that folder.

    .OUTPUTS
        Path to the HTML file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string]$OutputPath,
        [int]$MaxRows = 200
    )

    if ($null -eq $script:FotonSession) { Initialize-FotonSession }

    $jsonPath = Get-FotonBaselineJsonPath -Path $Path
    $doc = Get-Content -LiteralPath $jsonPath -Raw -Encoding UTF8 | ConvertFrom-Json
    if (-not $OutputPath) {
        $OutputPath = Join-Path (Split-Path -Parent $jsonPath) 'Foton_Baseline.html'
    }

    $h = $doc.Header
    $hostName = [string]$h.Hostname
    if (-not $hostName) { $hostName = '(unknown host)' }
    $schema = [string]$h.BaselineSchemaVersion
    $tool = [string]$h.ToolVersion
    $captured = [string]$h.CapturedUtc
    $elev = $false
    if ($h.Elevated) { $elev = [bool]$h.Elevated }
    $payload = [string]$h.PayloadSha256
    $note = [string]$h.Note

    $provByType = @{}
    foreach ($p in @($doc.Providers)) {
        $provByType[[string]$p.RecordType] = $p
    }

    $css = @'
<style>
:root{
  --bg:#0b1016; --panel:#121a24; --panel2:#0f1720; --line:#22303f;
  --text:#dfe8f1; --beam:#37d6ff; --beam2:#7cf5c4; --med:#ffb340;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1240px;margin:0 auto;padding:28px 22px 80px}
header.hero{border:1px solid var(--line);border-radius:14px;padding:26px 28px;background:
  radial-gradient(1100px 200px at 12% -40%,rgba(55,214,255,.18),transparent 60%),
  linear-gradient(180deg,#121b26,#0e151e)}
.brand{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.mark{flex:0 0 auto;display:block;color:var(--beam)}
h1{margin:0;font-size:28px;letter-spacing:3px;font-weight:700;color:var(--beam);text-transform:uppercase}
.tagline{color:#93a7bb;font-size:13px;font-style:italic;margin-top:6px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:10px 26px;margin-top:20px}
.meta div{font-size:13px;color:#a9bccf}
.meta b{display:block;color:#6f8399;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.9px;margin-bottom:2px}
.notice{margin-top:18px;border-left:3px solid var(--med);background:rgba(255,179,64,.08);padding:12px 16px;border-radius:0 8px 8px 0;font-size:13px;color:#e8d4b4}
h2{font-size:17px;margin:34px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
h2 small{color:#6f8399;font-weight:400;font-size:12px;margin-left:8px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:16px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:14px 16px}
.card .n{font-size:22px;font-weight:600;color:var(--beam2)}
.card .l{font-size:11px;text-transform:uppercase;letter-spacing:.9px;color:#7f93a8;margin-top:4px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:12.5px}
th{background:var(--panel2);text-align:left;padding:9px 12px;color:#8fa3b8;font-size:11px;text-transform:uppercase;letter-spacing:.8px;border-bottom:1px solid var(--line)}
td{padding:8px 12px;border-bottom:1px solid rgba(34,48,63,.6);vertical-align:top;word-break:break-word}
tr:last-child td{border-bottom:none}
.dim{color:#7f93a8}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);color:#6f8399;font-size:12px}
</style>
'@
    $css = $css + (Get-FotonReportNavCss)

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    $null = $sb.AppendLine('<meta name="viewport" content="width=device-width,initial-scale=1">')
    $null = $sb.AppendLine("<title>Foton Baseline Snapshot - $(ConvertTo-FotonSafeHtml $hostName)</title>")
    $null = $sb.AppendLine($css)
    $null = $sb.AppendLine('</head><body><div class="wrap" id="top">')
    $null = $sb.AppendLine('<header class="hero">')
    $null = $sb.AppendLine('<div class="brand">')
    $null = $sb.AppendLine((Get-FotonReportMarkSvg))
    $null = $sb.AppendLine('<div class="brand-text">')
    $null = $sb.AppendLine('<h1>Foton</h1>')
    $null = $sb.AppendLine('<div class="tagline">Baseline snapshot - one observation of stable configuration. Not a triage report. Not a clean-host certificate.</div>')
    $null = $sb.AppendLine('</div></div>')
    $null = $sb.AppendLine('<div class="meta">')
    $null = $sb.AppendLine("<div><b>Hostname</b>$(ConvertTo-FotonSafeHtml $hostName)</div>")
    $null = $sb.AppendLine("<div><b>Captured (UTC)</b>$(ConvertTo-FotonSafeHtml $captured)</div>")
    $null = $sb.AppendLine("<div><b>Schema</b>$(ConvertTo-FotonSafeHtml $schema)</div>")
    $null = $sb.AppendLine("<div><b>Tool</b>$(ConvertTo-FotonSafeHtml $tool)</div>")
    $priv = 'Standard user - some providers may be thin'
    if ($elev) { $priv = 'Elevated (Administrator)' }
    $null = $sb.AppendLine("<div><b>Privilege</b>$priv</div>")
    $null = $sb.AppendLine("<div><b>Payload SHA-256</b>$(ConvertTo-FotonSafeHtml $payload)</div>")
    $null = $sb.AppendLine('</div>')
    $caveat = $note
    if (-not $caveat) {
        $caveat = 'A baseline taken after an incident is a picture of that state. Diff proves change between two observations, never when or who.'
    }
    $null = $sb.AppendLine("<div class=""notice""><b>Read this first.</b> $(ConvertTo-FotonSafeHtml $caveat) Full tables live in baseline.json. This HTML is a capped preview.</div>")
    $null = $sb.AppendLine('</header>')
    $null = $sb.AppendLine((Get-FotonReportNavBarHtml))

    $null = $sb.AppendLine('<h2 id="sec-counts">Record counts</h2><div class="cards">')
    $typeNames = @($doc.Records.PSObject.Properties.Name | Sort-Object)
    foreach ($type in $typeNames) {
        $n = @($doc.Records.$type).Count
        $sid = Get-FotonReportSectionId -Name $type
        $null = $sb.AppendLine("<a class=""card"" href=""#$sid""><div class=""n"">$n</div><div class=""l"">$(ConvertTo-FotonSafeHtml $type)</div></a>")
    }
    $null = $sb.AppendLine('</div>')

    foreach ($type in $typeNames) {
        $rows = @($doc.Records.$type)
        $meta = $provByType[$type]
        $cols = @()
        if ($meta) {
            foreach ($f in @($meta.IdentityFields)) { if ($cols -notcontains [string]$f) { $cols += [string]$f } }
            foreach ($f in @($meta.ComparedFields)) { if ($cols -notcontains [string]$f) { $cols += [string]$f } }
        }
        if ($cols.Count -eq 0 -and $rows.Count -gt 0) {
            foreach ($pr in $rows[0].PSObject.Properties) { $cols += $pr.Name }
        }
        $shown = $rows.Count
        $extra = ''
        if ($shown -gt $MaxRows) {
            $extra = " (showing $MaxRows of $shown)"
            $rows = @($rows | Select-Object -First $MaxRows)
        }
        $sid = Get-FotonReportSectionId -Name $type
        $null = $sb.AppendLine("<h2 id=""$sid"">$(ConvertTo-FotonSafeHtml $type) <small>$($rows.Count) rows$extra</small></h2>")
        if ($meta -and $meta.FalsePositives) {
            $null = $sb.AppendLine("<p class=""dim"">$(ConvertTo-FotonSafeHtml ([string]$meta.FalsePositives))</p>")
        }
        if ($cols.Count -eq 0 -or $rows.Count -eq 0) {
            $null = $sb.AppendLine('<p class="dim">No rows.</p>')
            continue
        }
        $null = $sb.AppendLine('<table><thead><tr>')
        foreach ($c in $cols) {
            $null = $sb.AppendLine("<th>$(ConvertTo-FotonSafeHtml $c)</th>")
        }
        $null = $sb.AppendLine('</tr></thead><tbody>')
        foreach ($row in $rows) {
            $null = $sb.AppendLine('<tr>')
            foreach ($c in $cols) {
                $null = $sb.AppendLine("<td>$(ConvertTo-FotonSafeHtml ([string]$row.$c))</td>")
            }
            $null = $sb.AppendLine('</tr>')
        }
        $null = $sb.AppendLine('</tbody></table>')
    }

    $null = $sb.AppendLine("<footer>Foton baseline snapshot v$(ConvertTo-FotonSafeHtml $tool) &middot; schema $(ConvertTo-FotonSafeHtml $schema) &middot; $(ConvertTo-FotonSafeHtml $hostName) &middot; compare with Compare-FotonBaseline against baseline.json</footer>")
    $null = $sb.AppendLine('</div>')
    $null = $sb.AppendLine((Get-FotonReportNavScript))
    $null = $sb.AppendLine('</body></html>')

    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($OutputPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding $false))
    Write-FotonStatus "Baseline snapshot report: $OutputPath" 'Good'
    return $OutputPath
}
