function ConvertTo-FotonObservationHtml {
    <#
        Renders a finding Observation. ConvertTo-FotonSample joins items with ' ; ',
        which wrapped badly inside an inline span. Lead sentence stays a paragraph;
        sampled paths/commands become a list.
    #>
    param([string]$Text)
    $safe = ConvertTo-FotonSafeHtml $Text
    $marker = 'Sample: '
    $pos = $safe.IndexOf($marker)
    $lead = ''
    $items = @()
    if ($pos -ge 0) {
        $lead = $safe.Substring(0, $pos).Trim()
        $rest = $safe.Substring($pos + $marker.Length)
        $items = @($rest -split ' ; ' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    elseif ($safe.Contains(' ; ')) {
        $items = @($safe -split ' ; ' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    else {
        return "<div class=""obs""><p class=""obs-lead"">$safe</p></div>"
    }
    $html = '<div class="obs">'
    if ($lead) {
        $html += "<p class=""obs-lead"">$lead</p>"
    }
    $html += '<ul class="obs-list">'
    foreach ($item in $items) {
        $html += "<li>$item</li>"
    }
    $html += '</ul></div>'
    return $html
}
