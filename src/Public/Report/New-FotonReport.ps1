# New-FotonReport
# HTML from session findings + package data. Escape all untrusted strings.
# Write beside the case root so relative artifact links resolve.
function New-FotonReport {
    <#
    .SYNOPSIS
        Render the triage HTML report from a loaded package and findings.

    .DESCRIPTION
        Uses ConvertTo-FotonSafeHtml for host- and artifact-derived text. Default
        output is Foton_Report.html in the case root so links like
        06_Security_Posture/defender_status.json resolve. Does not rewrite hashes.csv.

    .PARAMETER Path
        Output HTML path. Defaults to <CaseRoot>\Foton_Report.html.

    .EXAMPLE
        Get-FotonPackage -Path C:\Cases\WinFoton_PC1_20260101-120000Z
        Invoke-FotonAnalysis
        New-FotonReport

        Writes Foton_Report.html next to the original WinFoton_Report.html.
    #>
    [CmdletBinding()]
    param(
        [string]$Path
    )

    if ($null -eq $script:FotonSession -or $null -eq $script:FotonSession.Data) {
        throw 'No package data loaded. Call Get-FotonPackage (and typically Invoke-FotonAnalysis) first.'
    }
    if (-not $Path) {
        if (-not $script:FotonSession.CaseRoot) { throw 'Specify -Path or load a package with a CaseRoot.' }
        $Path = Join-Path $script:FotonSession.CaseRoot 'Foton_Report.html'
    }
    Write-FotonStatus 'Building HTML overview report' 'Step'

    $sb = New-Object System.Text.StringBuilder
    $osInfo = $script:FotonSession.Data['os_info']
    $hostName = ''
    if ($osInfo) { $hostName = [string]$osInfo.Hostname }
    if (-not $hostName) { $hostName = '(unknown host)' }
    $cov = $script:FotonSession.Data['collection_coverage']
    $elevated = $false
    if ($cov -and ($null -ne $cov.Elevated)) { $elevated = [bool]$cov.Elevated }
    elseif ($script:FotonSession.IsElevated) { $elevated = $true }
    $collectedUtc = '(not recorded)'
    if ($script:FotonSession.StartTimeUtc) {
        $collectedUtc = $script:FotonSession.StartTimeUtc.ToString('yyyy-MM-dd HH:mm:ss')
    }

    $sevOrder = @{ 'High' = 0; 'Medium' = 1; 'Low' = 2; 'Info' = 3 }
    $findings = @($script:FotonSession.Findings | Sort-Object @{ Expression = { $sevOrder[$_.Severity] } }, Category)
    $counts = @{ High = 0; Medium = 0; Low = 0; Info = 0 }
    foreach ($f in $findings) { $counts[$f.Severity] = $counts[$f.Severity] + 1 }

    $css = @'
<style>
:root{
  --bg:#0b1016; --panel:#121a24; --panel2:#0f1720; --line:#22303f;
  --text:#dfe8f1; --muted:#8da0b4; --beam:#37d6ff; --beam2:#7cf5c4;
  --high:#ff5c6c; --med:#ffb340; --low:#7cc4ff; --info:#8fa3b8;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 "Segoe UI",system-ui,-apple-system,sans-serif}
a{color:var(--beam);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:1240px;margin:0 auto;padding:28px 22px 80px}
header.hero{border:1px solid var(--line);border-radius:14px;padding:26px 28px;background:
  radial-gradient(1100px 200px at 12% -40%,rgba(55,214,255,.20),transparent 60%),
  linear-gradient(180deg,#121b26,#0e151e)}
.brand{display:flex;align-items:center;gap:18px;flex-wrap:wrap}
.mark{flex:0 0 auto;display:block}
.brand-text h1{margin:0;font-size:32px;letter-spacing:4px;font-weight:700;color:var(--beam);text-transform:uppercase}
.tagline{color:#93a7bb;font-size:13px;font-style:italic;margin-top:4px}
.credits{color:#6f8399;font-size:12px;margin-top:6px;letter-spacing:.2px}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:10px 26px;margin-top:20px}
.meta div{font-size:13px;color:#a9bccf}
.meta b{display:block;color:#6f8399;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.9px;margin-bottom:2px}
.notice{margin-top:18px;border-left:3px solid var(--med);background:rgba(255,179,64,.08);padding:12px 16px;border-radius:0 8px 8px 0;font-size:13px;color:#e8d4b4}
h2{font-size:17px;margin:34px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line);letter-spacing:.3px}
h2 small{color:#6f8399;font-weight:400;font-size:12px;margin-left:8px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:14px 16px}
.card .n{font-size:26px;font-weight:600;line-height:1.1}
.card .l{font-size:11px;text-transform:uppercase;letter-spacing:.9px;color:#7f93a8;margin-top:4px}
.c-high .n{color:var(--high)} .c-med .n{color:var(--med)} .c-low .n{color:var(--low)} .c-info .n{color:var(--info)}
.controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:14px 0 18px}
.btn{background:var(--panel);border:1px solid var(--line);color:#b9cadb;border-radius:20px;padding:6px 15px;font-size:12.5px;cursor:pointer}
.btn:hover{border-color:var(--beam);color:#fff}
.btn.on{background:rgba(55,214,255,.14);border-color:var(--beam);color:#fff}
input[type=search]{flex:1;min-width:230px;background:var(--panel2);border:1px solid var(--line);border-radius:20px;color:var(--text);padding:7px 15px;font-size:13px}
.finding{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:10px;margin-bottom:11px;overflow:hidden}
.f-high{border-left-color:var(--high)} .f-med{border-left-color:var(--med)}
.f-low{border-left-color:var(--low)} .f-info{border-left-color:var(--info)}
.f-head{display:flex;gap:12px;align-items:center;padding:13px 16px;cursor:pointer}
.f-head:hover{background:rgba(255,255,255,.02)}
.chip{font-size:10.5px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;padding:3px 9px;border-radius:20px;white-space:nowrap}
.chip-high{background:rgba(255,92,108,.16);color:var(--high)}
.chip-med{background:rgba(255,179,64,.16);color:var(--med)}
.chip-low{background:rgba(124,196,255,.14);color:var(--low)}
.chip-info{background:rgba(143,163,184,.16);color:var(--info)}
.chip-cat{background:rgba(124,245,196,.10);color:var(--beam2)}
.chip-tier{background:rgba(255,255,255,.06);color:#9db1c5}
.f-title{flex:1;font-weight:600}
.f-body{display:none;padding:2px 18px 18px;border-top:1px solid var(--line)}
.finding.open .f-body{display:block}
.f-body p{margin:12px 0 0;line-height:1.55}
.f-body .obs-block{margin:12px 0 0}
.f-body .lbl{font-size:11px;text-transform:uppercase;letter-spacing:.9px;color:#6f8399;display:block;margin-bottom:6px}
.f-body .obs{display:block;background:var(--panel2);border:1px solid var(--line);border-radius:8px;padding:12px 14px;font-family:ui-monospace,Consolas,monospace;font-size:12.5px;line-height:1.55;word-break:break-word}
.obs-lead{margin:0;color:var(--text);font-family:inherit;line-height:1.55}
.obs-list{margin:8px 0 0;padding:0 0 0 18px;line-height:1.55}
.obs-list li{margin:0 0 8px;padding:0;line-height:1.55}
.obs-list li:last-child{margin-bottom:0}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden;font-size:12.5px}
th{background:var(--panel2);text-align:left;padding:9px 12px;color:#8fa3b8;font-size:11px;text-transform:uppercase;letter-spacing:.8px;border-bottom:1px solid var(--line)}
td{padding:8px 12px;border-bottom:1px solid rgba(34,48,63,.6);vertical-align:top;word-break:break-word}
tr:last-child td{border-bottom:none}
tr:hover td{background:rgba(255,255,255,.02)}
.ok{color:var(--beam2)} .bad{color:var(--high)} .warn{color:var(--med)} .dim{color:#7f93a8}
details.method{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 18px;margin-top:12px}
details.method summary{cursor:pointer;font-weight:600}
details.method p,details.method li{color:#b6c7d8;font-size:13px}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);color:#6f8399;font-size:12px}
.hidden{display:none!important}
</style>
'@

    $js = @'
<script>
(function(){
  document.addEventListener("click",function(e){
    var h=e.target.closest(".f-head");
    if(h){h.parentElement.classList.toggle("open");return;}
    var b=e.target.closest(".btn[data-sev]");
    if(b){
      document.querySelectorAll(".btn[data-sev]").forEach(function(x){x.classList.remove("on")});
      b.classList.add("on");
      applyFilters();
    }
  });
  var box=document.getElementById("q");
  if(box){box.addEventListener("input",applyFilters);}
  function applyFilters(){
    var active=document.querySelector(".btn[data-sev].on");
    var sev=active?active.getAttribute("data-sev"):"all";
    var q=(box&&box.value||"").toLowerCase();
    var shown=0;
    document.querySelectorAll(".finding").forEach(function(f){
      var okSev=(sev==="all"||f.getAttribute("data-sev")===sev);
      var okQ=(q===""||f.textContent.toLowerCase().indexOf(q)>-1);
      if(okSev&&okQ){f.classList.remove("hidden");shown++;}else{f.classList.add("hidden");}
    });
    var none=document.getElementById("nores");
    if(none){none.style.display=shown?"none":"block";}
  }
  document.querySelectorAll(".finding").forEach(function(f){
    if(f.getAttribute("data-sev")==="High"){f.classList.add("open");}
  });
})();
</script>
'@

    $null = $sb.AppendLine('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    $null = $sb.AppendLine('<meta name="viewport" content="width=device-width,initial-scale=1">')
    $null = $sb.AppendLine("<title>Foton Triage Report - $(ConvertTo-FotonSafeHtml $hostName)</title>")
    $null = $sb.AppendLine($css)
    $null = $sb.AppendLine('</head><body><div class="wrap">')

    # ---- Hero ----
    $verDisplay = ConvertTo-FotonSafeHtml ([string]$script:FotonSession.Version)
    $null = $sb.AppendLine('<header class="hero">')
    $null = $sb.AppendLine('<div class="brand">')
    $null = $sb.AppendLine('<svg class="mark" width="56" height="56" viewBox="0 0 48 48" aria-hidden="true">')
    $null = $sb.AppendLine('<defs><linearGradient id="fotonBeam" x1="0" y1="24" x2="48" y2="24"><stop offset="0" stop-color="#37d6ff" stop-opacity=".15"/><stop offset=".45" stop-color="#37d6ff"/><stop offset="1" stop-color="#7cf5c4" stop-opacity=".7"/></linearGradient></defs>')
    $null = $sb.AppendLine('<line x1="1" y1="24" x2="47" y2="24" stroke="url(#fotonBeam)" stroke-width="2.2"/>')
    $null = $sb.AppendLine('<polygon points="24,7 41,24 24,41 7,24" fill="rgba(55,214,255,.08)" stroke="#37d6ff" stroke-width="1.8"/>')
    $null = $sb.AppendLine('<circle cx="24" cy="24" r="4" fill="#37d6ff"/>')
    $null = $sb.AppendLine('</svg>')
    $null = $sb.AppendLine('<div class="brand-text">')
    $null = $sb.AppendLine('<h1>Foton</h1>')
    $null = $sb.AppendLine('<div class="tagline">Windows DFIR triage report - light through the glass</div>')
    $null = $sb.AppendLine("<div class=""credits"">J. Flynn &middot; jimididit &middot; v$verDisplay &middot; updated 2026-08-22</div>")
    $null = $sb.AppendLine('</div></div>')
    $null = $sb.AppendLine('<div class="meta">')
    $null = $sb.AppendLine("<div><b>Hostname</b>$(ConvertTo-FotonSafeHtml $hostName)</div>")
    if ($osInfo) {
        $null = $sb.AppendLine("<div><b>Operating System</b>$(ConvertTo-FotonSafeHtml ("{0} (build {1})" -f $osInfo.Caption, $osInfo.BuildNumber))</div>")
        $null = $sb.AppendLine("<div><b>Domain</b>$(ConvertTo-FotonSafeHtml ([string]$osInfo.Domain))</div>")
        $null = $sb.AppendLine("<div><b>Last Boot (UTC)</b>$(ConvertTo-FotonSafeHtml ([string]$osInfo.LastBootUtc)) &middot; up $(ConvertTo-FotonSafeHtml ([string]$osInfo.UptimeDays))d</div>")
    }
    $caseDisplay = '(not supplied)'
    $examinerDisplay = '(not supplied)'
    if ($script:FotonSession.Package -and $script:FotonSession.Package.CaseNumber) { $caseDisplay = [string]$script:FotonSession.Package.CaseNumber }
    if ($script:FotonSession.Package -and $script:FotonSession.Package.Examiner) { $examinerDisplay = [string]$script:FotonSession.Package.Examiner }
    $null = $sb.AppendLine("<div><b>Case</b>$(ConvertTo-FotonSafeHtml $caseDisplay)</div>")
    $null = $sb.AppendLine("<div><b>Examiner</b>$(ConvertTo-FotonSafeHtml $examinerDisplay)</div>")
    $null = $sb.AppendLine("<div><b>Collected (UTC)</b>$(ConvertTo-FotonSafeHtml $collectedUtc)</div>")
    $null = $sb.AppendLine("<div><b>Event Window</b>Last $($script:FotonSession.EventLogDays) days (analysis default if not stored in package)</div>")
    $null = $sb.AppendLine("<div><b>Privilege</b>$(if ($elevated) { 'Elevated (Administrator)' } else { 'Standard user - reduced coverage' })</div>")
    $null = $sb.AppendLine('</div>')
    $null = $sb.AppendLine('<div class="notice"><b>Read this first.</b> Every item below is an automated observation produced by pattern matching, not a conclusion. Nothing here establishes that this host is compromised. Each finding cites the artifact file it came from - verify against that artifact, and against the host owner''s expectations, before it goes anywhere near a report or a remediation decision.</div>')
    $null = $sb.AppendLine('</header>')

    # ---- Counts ----
    $null = $sb.AppendLine('<h2>Triage Summary</h2>')
    $null = $sb.AppendLine('<div class="cards">')
    $null = $sb.AppendLine("<div class=""card c-high""><div class=""n"">$($counts['High'])</div><div class=""l"">High attention</div></div>")
    $null = $sb.AppendLine("<div class=""card c-med""><div class=""n"">$($counts['Medium'])</div><div class=""l"">Medium</div></div>")
    $null = $sb.AppendLine("<div class=""card c-low""><div class=""n"">$($counts['Low'])</div><div class=""l"">Low</div></div>")
    $null = $sb.AppendLine("<div class=""card c-info""><div class=""n"">$($counts['Info'])</div><div class=""l"">Informational</div></div>")
    $procCount = 0
    if ($script:FotonSession.Data['running_processes']) { $procCount = @($script:FotonSession.Data['running_processes']).Count }
    $svcCount = 0
    if ($script:FotonSession.Data['services']) { $svcCount = @($script:FotonSession.Data['services']).Count }
    $taskCount = 0
    if ($script:FotonSession.Data['scheduled_tasks']) { $taskCount = @($script:FotonSession.Data['scheduled_tasks']).Count }
    $connCount = 0
    if ($script:FotonSession.Data['active_connections']) { $connCount = @($script:FotonSession.Data['active_connections']).Count }
    $null = $sb.AppendLine('</div>')
    $null = $sb.AppendLine('<div class="cards">')
    $null = $sb.AppendLine("<div class=""card""><div class=""n"">$procCount</div><div class=""l"">Processes</div></div>")
    $null = $sb.AppendLine("<div class=""card""><div class=""n"">$svcCount</div><div class=""l"">Services</div></div>")
    $null = $sb.AppendLine("<div class=""card""><div class=""n"">$taskCount</div><div class=""l"">Scheduled tasks</div></div>")
    $null = $sb.AppendLine("<div class=""card""><div class=""n"">$connCount</div><div class=""l"">Connections</div></div>")
    $null = $sb.AppendLine('</div>')

    # ---- Findings ----
    $null = $sb.AppendLine('<h2>Observations<small>click any row to expand</small></h2>')
    $null = $sb.AppendLine('<div class="controls">')
    $null = $sb.AppendLine('<button class="btn on" data-sev="all">All</button><button class="btn" data-sev="High">High</button><button class="btn" data-sev="Medium">Medium</button><button class="btn" data-sev="Low">Low</button><button class="btn" data-sev="Info">Info</button>')
    $null = $sb.AppendLine('<input id="q" type="search" placeholder="Filter observations (e.g. defender, persistence, rdp)">')
    $null = $sb.AppendLine('</div>')

    foreach ($f in $findings) {
        $cls = 'f-info'; $chip = 'chip-info'
        switch ($f.Severity) {
            'High' { $cls = 'f-high'; $chip = 'chip-high' }
            'Medium' { $cls = 'f-med'; $chip = 'chip-med' }
            'Low' { $cls = 'f-low'; $chip = 'chip-low' }
        }
        $null = $sb.AppendLine("<div class=""finding $cls"" data-sev=""$($f.Severity)"">")
        $null = $sb.AppendLine('<div class="f-head">')
        $null = $sb.AppendLine("<span class=""chip $chip"">$($f.Severity)</span>")
        $null = $sb.AppendLine("<span class=""chip chip-cat"">$(ConvertTo-FotonSafeHtml $f.Category)</span>")
        $null = $sb.AppendLine("<span class=""f-title"">$(ConvertTo-FotonSafeHtml $f.Title)</span>")
        $null = $sb.AppendLine("<span class=""chip chip-tier"">Tier $($f.Tier)</span>")
        $null = $sb.AppendLine('</div><div class="f-body">')
        $null = $sb.AppendLine('<div class="obs-block"><span class="lbl">What was observed</span>')
        $null = $sb.AppendLine((ConvertTo-FotonObservationHtml $f.Observation))
        $null = $sb.AppendLine('</div>')
        if ($f.WhyItMatters) {
            $null = $sb.AppendLine("<p><span class=""lbl"">Why it matters</span>$(ConvertTo-FotonSafeHtml $f.WhyItMatters)</p>")
        }
        if ($f.NextStep) {
            $null = $sb.AppendLine("<p><span class=""lbl"">Suggested next step</span>$(ConvertTo-FotonSafeHtml $f.NextStep)</p>")
        }
        if ($f.Artifact) {
            $null = $sb.AppendLine("<p><span class=""lbl"">Source artifact</span><a href=""$(ConvertTo-FotonSafeHtml $f.Artifact)"">$(ConvertTo-FotonSafeHtml $f.Artifact)</a></p>")
        }
        $null = $sb.AppendLine('</div></div>')
    }
    $null = $sb.AppendLine('<div id="nores" style="display:none;color:#7f93a8;padding:14px">No observations match the current filter.</div>')

    # ---- Quick reference tables ----
    $admins = @()
    if ($script:FotonSession.Data['local_group_membership']) {
        $admins = @($script:FotonSession.Data['local_group_membership'] | Where-Object { $_.Group -eq 'Administrators' -and $_.Member -ne '(none)' })
    }
    if ($admins.Count -gt 0) {
        $null = $sb.AppendLine('<h2>Local Administrators<small>compare against the expected baseline</small></h2><table><tr><th>Member</th><th>Type</th><th>Source</th><th>SID</th></tr>')
        foreach ($a in $admins) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-FotonSafeHtml $a.Member)</td><td>$(ConvertTo-FotonSafeHtml $a.ObjectClass)</td><td>$(ConvertTo-FotonSafeHtml $a.PrincipalSource)</td><td class=""dim"">$(ConvertTo-FotonSafeHtml $a.SID)</td></tr>")
        }
        $null = $sb.AppendLine('</table>')
    }

    $ext = @()
    if ($script:FotonSession.Data['active_connections']) {
        $ext = @($script:FotonSession.Data['active_connections'] | Where-Object { $_.RemoteIsExternal -eq $true } | Select-Object -First 40)
    }
    if ($ext.Count -gt 0) {
        $null = $sb.AppendLine('<h2>External Network Connections<small>point-in-time snapshot at collection</small></h2><table><tr><th>Process</th><th>PID</th><th>Remote</th><th>State</th><th>Path</th></tr>')
        foreach ($c in $ext) {
            $pathClass = 'dim'
            if ($c.UserWritablePath -eq $true) { $pathClass = 'warn' }
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-FotonSafeHtml $c.ProcessName)</td><td>$(ConvertTo-FotonSafeHtml ([string]$c.OwningPID))</td><td>$(ConvertTo-FotonSafeHtml ("{0}:{1}" -f $c.RemoteAddress, $c.RemotePort))</td><td>$(ConvertTo-FotonSafeHtml $c.State)</td><td class=""$pathClass"">$(ConvertTo-FotonSafeHtml $c.ProcessPath)</td></tr>")
        }
        $null = $sb.AppendLine('</table>')
    }

    if ($script:FotonSession.Data['hardening_registry_settings']) {
        $mismatch = @($script:FotonSession.Data['hardening_registry_settings'] | Where-Object { $_.MatchesRecommended -eq $false -and $_.RecommendedValue -ne '' })
        if ($mismatch.Count -gt 0) {
            $null = $sb.AppendLine('<h2>Hardening Settings Not At Recommended Value<small>configuration review, not compromise indicators</small></h2><table><tr><th>Setting</th><th>Current</th><th>Recommended</th><th>Meaning</th></tr>')
            foreach ($m in $mismatch) {
                $null = $sb.AppendLine("<tr><td>$(ConvertTo-FotonSafeHtml $m.Setting)</td><td class=""warn"">$(ConvertTo-FotonSafeHtml $m.Value)</td><td class=""dim"">$(ConvertTo-FotonSafeHtml $m.RecommendedValue)</td><td>$(ConvertTo-FotonSafeHtml $m.Meaning)</td></tr>")
            }
            $null = $sb.AppendLine('</table>')
        }
    }

    # ---- Manifest ----
    $null = $sb.AppendLine('<h2>Collection Manifest<small>every artifact in this package</small></h2><table><tr><th>Category</th><th>Artifact</th><th>What it contains</th><th>Records</th><th>Status</th></tr>')
    foreach ($m in $script:FotonSession.Manifest) {
        $statusClass = 'ok'
        if ($m.Status -eq 'NoData') { $statusClass = 'dim' }
        elseif ($m.Status -ne 'Success') { $statusClass = 'bad' }
        $link = ($m.File -replace '\\', '/')
        $null = $sb.AppendLine("<tr><td class=""dim"">$(ConvertTo-FotonSafeHtml $m.Category)</td><td><a href=""$(ConvertTo-FotonSafeHtml $link)"">$(ConvertTo-FotonSafeHtml (Split-Path $m.File -Leaf))</a></td><td>$(ConvertTo-FotonSafeHtml $m.Description)</td><td>$($m.Records)</td><td class=""$statusClass"">$(ConvertTo-FotonSafeHtml $m.Status)</td></tr>")
    }
    $null = $sb.AppendLine('</table>')

    if ($script:FotonSession.Errors.Count -gt 0) {
        $null = $sb.AppendLine('<h2>Collection Errors<small>gaps to disclose in any report built from this data</small></h2><table><tr><th>Task</th><th>Error</th></tr>')
        foreach ($e in $script:FotonSession.Errors) {
            $null = $sb.AppendLine("<tr><td>$(ConvertTo-FotonSafeHtml $e.Task)</td><td class=""warn"">$(ConvertTo-FotonSafeHtml $e.Error)</td></tr>")
        }
        $null = $sb.AppendLine('</table>')
    }

    # ---- Methodology ----
    $null = $sb.AppendLine('<h2>Methodology, Tiers, and Limitations</h2>')
    $null = $sb.AppendLine(@'
<details class="method" open><summary>How to read the tiers</summary>
<p><b>Tier 1 - Observed artifact.</b> Directly present in the collected data, no interpretation applied. A registry value, an event ID, a signature status. State these as fact.</p>
<p><b>Tier 2 - Supported inference.</b> A reasonable reading of one or more Tier 1 artifacts where other readings remain possible. An unsigned binary in AppData holding an outbound connection is consistent with C2 and equally consistent with a portable application. Cite the artifact and name the assumption.</p>
<p><b>Tier 3 - Unverified hypothesis.</b> Not stated as findings by this tool. If you form one during analysis, record what evidence would move it to Tier 2.</p>
</details>
'@)
    $null = $sb.AppendLine(@'
<details class="method"><summary>Limitations of this collection</summary>
<ul>
<li><b>Live collection.</b> Running this tool altered the host: a process was created, files were written, event log entries were generated, and prefetch and AmCache were updated. No memory image and no disk image were produced.</li>
<li><b>Point-in-time volatile data.</b> Process, connection, and session data reflect the moment of collection only. Activity that ended before collection is absent from those artifacts.</li>
<li><b>Log retention bounds the window.</b> Event data is limited to the configured window and to what retention preserved. Where a log was cleared, everything before that point is unavailable from this host.</li>
<li><b>Heuristics are not detections.</b> The pattern lists used here match on common attacker tradecraft and also match legitimate administrative tooling. Expect false positives, and treat an empty findings list as an absence of matched patterns, not an absence of compromise.</li>
<li><b>Signature status is not integrity.</b> A valid signature does not mean the binary is benign, and an invalid one does not mean it is malicious. Catalog-signed system files frequently return non-Valid status.</li>
<li><b>No anti-rootkit capability.</b> All data is gathered through the operating system''s own APIs. Kernel-level tampering could render any of it unreliable.</li>
<li><b>Standard-user coverage.</b> If this package was collected without Administrator rights, the Security log, Prefetch, VSS, secedit/auditpol, and other users'' artifacts were skipped by design. See 00_Collection/collection_coverage.json. Do not read those gaps as a clean host.</li>
<li><b>Timestamps.</b> All times are UTC as reported by this host. Verify the host clock against the time source data before building a timeline, and note that file MACB times are trivially modifiable.</li>
</ul>
</details>
'@)

    $null = $sb.AppendLine("<footer>Foton v$(ConvertTo-FotonSafeHtml $script:FotonSession.Version) &middot; J. Flynn / jimididit &middot; collected $(ConvertTo-FotonSafeHtml $collectedUtc) UTC on $(ConvertTo-FotonSafeHtml $hostName) by $(ConvertTo-FotonSafeHtml $examinerDisplay) &middot; verify artifact hashes in 00_Collection/hashes.csv before analysis</footer>")
    $null = $sb.AppendLine('</div>')
    $null = $sb.AppendLine($js)
    $null = $sb.AppendLine('</body></html>')

    $sb.ToString() | Out-File -FilePath $Path -Encoding UTF8
    Write-FotonStatus "Report written: $Path" 'Good'
}

