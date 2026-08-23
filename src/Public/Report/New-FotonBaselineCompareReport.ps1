function New-FotonBaselineCompareReport {
    <#
    .SYNOPSIS
        HTML report of Added/Removed/Modified rows from two baseline snapshots (offline).

    .DESCRIPTION
        Workstation-only. Does not run on the endpoint flatten unless you copy this
        command. Caps rows. Escapes every cell. Does not say the host is compromised.
        Attention colors follow the same ranking as Compare-FotonBaseline findings.

    .PARAMETER ReferencePath
        Older / golden baseline.json or package folder.

    .PARAMETER DifferencePath
        Newer / candidate baseline.json or package folder.

    .PARAMETER OutputPath
        HTML file. Defaults to Foton_BaselineCompare.html beside the difference JSON.

    .PARAMETER MaxRows
        Max change rows in the table (default 400).

    .PARAMETER Changes
        Precomputed change objects from Compare-FotonBaseline (avoids a second diff).

    .PARAMETER Mode
        Temporal or Fleet. Used with -Changes.

    .EXAMPLE
        New-FotonBaselineCompareReport -ReferencePath D:\day0.json -DifferencePath D:\day1.json

        Writes Foton_BaselineCompare.html next to day1.json.

    .OUTPUTS
        Path to the HTML file.
    #>
    [CmdletBinding(DefaultParameterSetName = 'Paths')]
    param(
        [Parameter(ParameterSetName = 'Paths', Mandatory)]
        [string]$ReferencePath,
        [Parameter(ParameterSetName = 'Paths', Mandatory)]
        [string]$DifferencePath,
        [string]$OutputPath,
        [int]$MaxRows = 400,
        [Parameter(ParameterSetName = 'Context', Mandatory)]
        $Changes,
        [Parameter(ParameterSetName = 'Context')]
        [string]$Mode,
        [Parameter(ParameterSetName = 'Context')]
        $ReferenceHeader,
        [Parameter(ParameterSetName = 'Context')]
        $DifferenceHeader
    )

    if ($null -eq $script:FotonSession) { Initialize-FotonSession }

    $refHeader = $ReferenceHeader
    $difHeader = $DifferenceHeader
    $cmpMode = $Mode
    $rows = @($Changes)

    if ($PSCmdlet.ParameterSetName -eq 'Paths') {
        $rows = @(Compare-FotonBaseline -ReferencePath $ReferencePath -DifferencePath $DifferencePath -NoHtml)
        $refJson = Get-FotonBaselineJsonPath -Path $ReferencePath
        $difJson = Get-FotonBaselineJsonPath -Path $DifferencePath
        $refHeader = (Get-Content -LiteralPath $refJson -Raw -Encoding UTF8 | ConvertFrom-Json).Header
        $difHeader = (Get-Content -LiteralPath $difJson -Raw -Encoding UTF8 | ConvertFrom-Json).Header
        $cmpMode = 'Fleet'
        if ($refHeader.Hostname -eq $difHeader.Hostname) { $cmpMode = 'Temporal' }
        if (-not $OutputPath) {
            $OutputPath = Join-Path (Split-Path -Parent $difJson) 'Foton_BaselineCompare.html'
        }
    }
    else {
        if (-not $OutputPath) {
            $OutputPath = Join-Path $env:TEMP 'Foton_BaselineCompare.html'
        }
    }

    if (-not $cmpMode) { $cmpMode = 'Temporal' }

    $refHost = [string]$refHeader.Hostname
    $difHost = [string]$difHeader.Hostname
    if (-not $refHost) { $refHost = '(unknown)' }
    if (-not $difHost) { $difHost = '(unknown)' }

    $css = @'
<style>
:root{
  --bg:#0b1016; --panel:#121a24; --panel2:#0f1720; --line:#22303f;
  --text:#dfe8f1; --beam:#37d6ff; --beam2:#7cf5c4; --med:#ffb340; --high:#ff6b6b; --low:#8fa3b8;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 "Segoe UI",system-ui,sans-serif}
.wrap{max-width:1240px;margin:0 auto;padding:28px 22px 80px}
header.hero{border:1px solid var(--line);border-radius:14px;padding:26px 28px;background:
  radial-gradient(1100px 200px at 12% -40%,rgba(55,214,255,.18),transparent 60%),
  linear-gradient(180deg,#121b26,#0e151e)}
h1{margin:0;font-size:28px;letter-spacing:3px;font-weight:700;color:var(--beam);text-transform:uppercase}
.tagline{color:#93a7bb;font-size:13px;font-style:italic;margin-top:6px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:10px 26px;margin-top:20px}
.meta div{font-size:13px;color:#a9bccf}
.meta b{display:block;color:#6f8399;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.9px;margin-bottom:2px}
.notice{margin-top:18px;border-left:3px solid var(--med);background:rgba(255,179,64,.08);padding:12px 16px;border-radius:0 8px 8px 0;font-size:13px;color:#e8d4b4}
h2{font-size:17px;margin:34px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px;margin:16px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:14px 16px}
.card .n{font-size:22px;font-weight:600;color:var(--beam2)}
.card .l{font-size:11px;text-transform:uppercase;letter-spacing:.9px;color:#7f93a8;margin-top:4px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:12.5px}
th{background:var(--panel2);text-align:left;padding:9px 12px;color:#8fa3b8;font-size:11px;text-transform:uppercase;letter-spacing:.8px;border-bottom:1px solid var(--line)}
td{padding:8px 12px;border-bottom:1px solid rgba(34,48,63,.6);vertical-align:top;word-break:break-word}
tr:last-child td{border-bottom:none}
.dim{color:#7f93a8}
.sev-High{color:var(--high);font-weight:600}
.sev-Medium{color:var(--med);font-weight:600}
.sev-Low,.sev-Info{color:var(--low)}
.ct-Added{color:var(--beam2)}
.ct-Removed{color:var(--high)}
.ct-Modified{color:var(--med)}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);color:#6f8399;font-size:12px}
</style>
'@
    $css = $css + (Get-FotonReportNavCss)

    $added = @($rows | Where-Object { $_.ChangeType -eq 'Added' }).Count
    $removed = @($rows | Where-Object { $_.ChangeType -eq 'Removed' }).Count
    $modified = @($rows | Where-Object { $_.ChangeType -eq 'Modified' }).Count
    $high = 0
    foreach ($c in $rows) {
        if ((Get-FotonBaselineChangeSeverity -Change $c) -eq 'High') { $high++ }
    }

    $shown = @($rows)
    $extra = ''
    if ($shown.Count -gt $MaxRows) {
        $extra = " (showing $MaxRows of $($shown.Count))"
        $shown = @($shown | Select-Object -First $MaxRows)
    }

    $sb = New-Object System.Text.StringBuilder
    $null = $sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    $null = $sb.AppendLine('<meta name="viewport" content="width=device-width,initial-scale=1">')
    $null = $sb.AppendLine("<title>Foton Baseline Compare - $(ConvertTo-FotonSafeHtml $difHost)</title>")
    $null = $sb.AppendLine($css)
    $null = $sb.AppendLine('</head><body><div class="wrap" id="top">')
    $null = $sb.AppendLine('<header class="hero">')
    $null = $sb.AppendLine('<h1>Foton</h1>')
    $null = $sb.AppendLine('<div class="tagline">Baseline compare - field-level change between two observations. Not a compromise verdict. Not a clean-host certificate.</div>')
    $null = $sb.AppendLine('<div class="meta">')
    $null = $sb.AppendLine("<div><b>Mode</b>$(ConvertTo-FotonSafeHtml $cmpMode)</div>")
    $null = $sb.AppendLine("<div><b>Reference host</b>$(ConvertTo-FotonSafeHtml $refHost)</div>")
    $null = $sb.AppendLine("<div><b>Difference host</b>$(ConvertTo-FotonSafeHtml $difHost)</div>")
    $null = $sb.AppendLine("<div><b>Reference UTC</b>$(ConvertTo-FotonSafeHtml ([string]$refHeader.CapturedUtc))</div>")
    $null = $sb.AppendLine("<div><b>Difference UTC</b>$(ConvertTo-FotonSafeHtml ([string]$difHeader.CapturedUtc))</div>")
    $null = $sb.AppendLine("<div><b>Schema</b>$(ConvertTo-FotonSafeHtml ([string]$refHeader.BaselineSchemaVersion))</div>")
    $null = $sb.AppendLine('</div>')
    $caveat = 'Diff proves change between two snapshots, never when or who. High attention marks persistence and trust surfaces that deserve review against change control. Software updates, GPO, and lab DNS overrides are common benign sources.'
    $null = $sb.AppendLine("<div class=""notice""><b>Read this first.</b> $(ConvertTo-FotonSafeHtml $caveat)</div>")
    $null = $sb.AppendLine('</header>')
    $null = $sb.AppendLine((Get-FotonReportNavBarHtml))

    $null = $sb.AppendLine('<h2 id="sec-counts">Change counts</h2><div class="cards">')
    $null = $sb.AppendLine("<div class=""card""><div class=""n"">$($rows.Count)</div><div class=""l"">Total</div></div>")
    $null = $sb.AppendLine("<div class=""card""><div class=""n"">$added</div><div class=""l"">Added</div></div>")
    $null = $sb.AppendLine("<div class=""card""><div class=""n"">$removed</div><div class=""l"">Removed</div></div>")
    $null = $sb.AppendLine("<div class=""card""><div class=""n"">$modified</div><div class=""l"">Modified</div></div>")
    $null = $sb.AppendLine("<div class=""card""><div class=""n"">$high</div><div class=""l"">High attention</div></div>")
    $null = $sb.AppendLine('</div>')

    $null = $sb.AppendLine('<div class="controls">')
    $null = $sb.AppendLine('<button type="button" class="btn on" data-change="all">All</button>')
    $null = $sb.AppendLine('<button type="button" class="btn" data-change="Added">Added</button>')
    $null = $sb.AppendLine('<button type="button" class="btn" data-change="Removed">Removed</button>')
    $null = $sb.AppendLine('<button type="button" class="btn" data-change="Modified">Modified</button>')
    $null = $sb.AppendLine("</div>")

    if ($shown.Count -eq 0) {
        $null = $sb.AppendLine('<h2 id="sec-changes">Changes</h2>')
        $null = $sb.AppendLine('<p class="dim">No field-level differences in the compared payload.</p>')
    }
    else {
        $typeOrder = @($shown | ForEach-Object { [string]$_.RecordType } | Sort-Object -Unique)
        foreach ($type in $typeOrder) {
            $chunk = @($shown | Where-Object { [string]$_.RecordType -eq $type })
            $sid = Get-FotonReportSectionId -Name $type
            $null = $sb.AppendLine("<h2 id=""$sid"">$(ConvertTo-FotonSafeHtml $type) <small>$($chunk.Count) change(s)$extra</small></h2>")
            $null = $sb.AppendLine('<table><thead><tr>')
            foreach ($col in @('Attention', 'Change', 'Identity', 'Field', 'OldValue', 'NewValue')) {
                $null = $sb.AppendLine("<th>$(ConvertTo-FotonSafeHtml $col)</th>")
            }
            $null = $sb.AppendLine('</tr></thead><tbody>')
            foreach ($c in $chunk) {
                $sev = Get-FotonBaselineChangeSeverity -Change $c
                $ct = [string]$c.ChangeType
                $null = $sb.AppendLine("<tr data-change=""$ct"">")
                $null = $sb.AppendLine("<td class=""sev-$sev"">$(ConvertTo-FotonSafeHtml $sev)</td>")
                $null = $sb.AppendLine("<td class=""ct-$ct"">$(ConvertTo-FotonSafeHtml $ct)</td>")
                $null = $sb.AppendLine("<td>$(ConvertTo-FotonSafeHtml ([string]$c.Identity))</td>")
                $null = $sb.AppendLine("<td>$(ConvertTo-FotonSafeHtml ([string]$c.Field))</td>")
                $null = $sb.AppendLine("<td>$(ConvertTo-FotonSafeHtml ([string]$c.OldValue))</td>")
                $null = $sb.AppendLine("<td>$(ConvertTo-FotonSafeHtml ([string]$c.NewValue))</td>")
                $null = $sb.AppendLine('</tr>')
            }
            $null = $sb.AppendLine('</tbody></table>')
        }
    }

    $null = $sb.AppendLine("<footer>Foton baseline compare &middot; $(ConvertTo-FotonSafeHtml $cmpMode) &middot; schema $(ConvertTo-FotonSafeHtml ([string]$refHeader.BaselineSchemaVersion)) &middot; source of truth remains baseline.json</footer>")
    $null = $sb.AppendLine('</div>')
    $null = $sb.AppendLine((Get-FotonReportNavScript))
    $null = $sb.AppendLine('</body></html>')

    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($OutputPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding $false))
    Write-FotonStatus "Baseline compare report: $OutputPath" 'Good'
    return $OutputPath
}
