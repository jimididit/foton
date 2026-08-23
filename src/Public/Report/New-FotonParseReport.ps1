function New-FotonParseReport {
    <#
    .SYNOPSIS
        HTML preview of Invoke-FotonParse rows (offline). Not a findings report.

    .DESCRIPTION
        Capped tables grouped by parser Format. Escapes every cell. CSV remains
        the source of truth. Does not say the host executed malware.

    .PARAMETER Records
        Normalized parse rows (SourcePath, Format, Supported, Identity, SizeBytes, SHA256, Note).

    .PARAMETER OutputPath
        HTML file.

    .PARAMETER EmptyReason
        Shown when Records is empty (visibility gap, not a clean host).

    .PARAMETER MaxRows
        Max rows per Format table (default 400).

    .EXAMPLE
        New-FotonParseReport -Records $rows -OutputPath D:\Cases\CASE-0001\analysis\Foton_Parse.html

    .OUTPUTS
        Path to the HTML file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$OutputPath,
        [object[]]$Records,
        [string]$EmptyReason,
        [int]$MaxRows = 400
    )

    if ($null -eq $script:FotonSession) { Initialize-FotonSession }

    $rows = @()
    if ($null -ne $Records) {
        $rows = @($Records | Where-Object { $null -ne $_ })
    }
    $hostName = '(unknown host)'
    $osInfo = $null
    if ($script:FotonSession.Data) { $osInfo = $script:FotonSession.Data['os_info'] }
    if ($osInfo -and $osInfo.Hostname) { $hostName = [string]$osInfo.Hostname }

    $supported = @($rows | Where-Object { $_.Supported -eq $true -or [string]$_.Supported -eq 'True' }).Count
    $mam = @($rows | Where-Object { [string]$_.Format -eq 'MAM-compressed' }).Count
    $lnk = @($rows | Where-Object { [string]$_.Format -eq 'LNK' }).Count

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
    $null = $sb.AppendLine("<title>Foton Parse - $(ConvertTo-FotonSafeHtml $hostName)</title>")
    $null = $sb.AppendLine($css)
    $null = $sb.AppendLine('</head><body><div class="wrap" id="top">')
    $null = $sb.AppendLine('<header class="hero">')
    $null = $sb.AppendLine('<div class="brand">')
    $null = $sb.AppendLine((Get-FotonReportMarkSvg))
    $null = $sb.AppendLine('<div class="brand-text">')
    $null = $sb.AppendLine('<h1>Foton</h1>')
    $null = $sb.AppendLine('<div class="tagline">Offline parse - Prefetch and LNK already in the package. Not triage findings. Not a compromise verdict.</div>')
    $null = $sb.AppendLine('</div></div>')
    $null = $sb.AppendLine('<div class="meta">')
    $null = $sb.AppendLine("<div><b>Hostname</b>$(ConvertTo-FotonSafeHtml $hostName)</div>")
    $null = $sb.AppendLine("<div><b>Rows</b>$($rows.Count)</div>")
    $null = $sb.AppendLine("<div><b>Supported names</b>$supported</div>")
    $null = $sb.AppendLine("<div><b>MAM-compressed</b>$mam</div>")
    $null = $sb.AppendLine("<div><b>LNK</b>$lnk</div>")
    $null = $sb.AppendLine('</div>')
    $caveat = 'CSV is the source of truth (analysis/parsed_records.csv). This HTML is a capped preview. MAM-compressed Prefetch is not inflated. EVTX rows are selected Event IDs only, capped. Amcache hive and SRUM ESE copies are not parsed here (wrong fields would be worse than missing ones).'
    $null = $sb.AppendLine("<div class=""notice""><b>Read this first.</b> $(ConvertTo-FotonSafeHtml $caveat)</div>")
    $null = $sb.AppendLine('</header>')
    $null = $sb.AppendLine((Get-FotonReportNavBarHtml))

    $null = $sb.AppendLine('<h2 id="sec-counts">Parse counts</h2><div class="cards">')
    $null = $sb.AppendLine("<div class=""card""><div class=""n"">$($rows.Count)</div><div class=""l"">Total</div></div>")
    $null = $sb.AppendLine("<div class=""card""><div class=""n"">$supported</div><div class=""l"">Supported</div></div>")
    $null = $sb.AppendLine("<div class=""card""><div class=""n"">$mam</div><div class=""l"">MAM Prefetch</div></div>")
    $null = $sb.AppendLine("<div class=""card""><div class=""n"">$lnk</div><div class=""l"">LNK</div></div>")
    $null = $sb.AppendLine('</div>')

    $formats = @($rows | ForEach-Object { [string]$_.Format } | Where-Object { $_ } | Sort-Object -Unique)
    if ($formats.Count -gt 0) {
        $null = $sb.AppendLine('<div class="controls">')
        $null = $sb.AppendLine('<button type="button" class="btn on" data-change="all">All</button>')
        foreach ($fmt in $formats) {
            $null = $sb.AppendLine("<button type=""button"" class=""btn"" data-change=""$(ConvertTo-FotonSafeHtml $fmt)"">$(ConvertTo-FotonSafeHtml $fmt)</button>")
        }
        $null = $sb.AppendLine('</div>')
    }

    if ($rows.Count -eq 0) {
        $msg = $EmptyReason
        if (-not $msg) { $msg = 'No Prefetch or LNK files were parsed.' }
        $null = $sb.AppendLine('<h2 id="sec-empty">Nothing parsed</h2>')
        $null = $sb.AppendLine("<p class=""dim"">$(ConvertTo-FotonSafeHtml $msg)</p>")
    }
    else {
        foreach ($fmt in $formats) {
            $chunk = @($rows | Where-Object { [string]$_.Format -eq $fmt })
            $shown = $chunk
            $extra = ''
            if ($shown.Count -gt $MaxRows) {
                $extra = " (showing $MaxRows of $($shown.Count))"
                $shown = @($shown | Select-Object -First $MaxRows)
            }
            $sid = Get-FotonReportSectionId -Name $fmt
            $null = $sb.AppendLine("<h2 id=""$sid"">$(ConvertTo-FotonSafeHtml $fmt) <small>$($chunk.Count) row(s)$extra</small></h2>")
            $null = $sb.AppendLine('<table><thead><tr>')
            foreach ($col in @('Identity', 'Supported', 'SizeBytes', 'SHA256', 'SourcePath', 'Note')) {
                $null = $sb.AppendLine("<th>$(ConvertTo-FotonSafeHtml $col)</th>")
            }
            $null = $sb.AppendLine('</tr></thead><tbody>')
            foreach ($c in $shown) {
                $null = $sb.AppendLine("<tr data-change=""$(ConvertTo-FotonSafeHtml ([string]$c.Format))"">")
                $null = $sb.AppendLine("<td>$(ConvertTo-FotonSafeHtml ([string]$c.Identity))</td>")
                $null = $sb.AppendLine("<td>$(ConvertTo-FotonSafeHtml ([string]$c.Supported))</td>")
                $null = $sb.AppendLine("<td>$(ConvertTo-FotonSafeHtml ([string]$c.SizeBytes))</td>")
                $null = $sb.AppendLine("<td>$(ConvertTo-FotonSafeHtml ([string]$c.SHA256))</td>")
                $null = $sb.AppendLine("<td>$(ConvertTo-FotonSafeHtml ([string]$c.SourcePath))</td>")
                $null = $sb.AppendLine("<td>$(ConvertTo-FotonSafeHtml ([string]$c.Note))</td>")
                $null = $sb.AppendLine('</tr>')
            }
            $null = $sb.AppendLine('</tbody></table>')
        }
    }

    $null = $sb.AppendLine('<footer>Foton parse report &middot; not findings.csv &middot; source of truth is parsed_records.csv</footer>')
    $null = $sb.AppendLine('</div>')
    $null = $sb.AppendLine((Get-FotonReportNavScript))
    $null = $sb.AppendLine('</body></html>')

    $dir = Split-Path -Parent $OutputPath
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
    [System.IO.File]::WriteAllText($OutputPath, $sb.ToString(), (New-Object System.Text.UTF8Encoding $false))
    Write-FotonStatus "Parse report: $OutputPath" 'Good'
    return $OutputPath
}
