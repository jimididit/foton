function ConvertTo-FotonSample {
    <# Join a few example values for finding Observation text. Same ' ; ' marker the HTML list renderer splits on. #>
    param($Items, [int]$Max = 5)
    if (-not $Items) { return '' }
    $arr = @($Items)
    $shown = $arr | Select-Object -First $Max
    $text = ($shown -join ' ; ')
    if ($arr.Count -gt $Max) { $text += (" ... (+{0} more, see artifact)" -f ($arr.Count - $Max)) }
    return $text
}
