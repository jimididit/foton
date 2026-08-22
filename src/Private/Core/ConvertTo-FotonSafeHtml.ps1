function ConvertTo-FotonSafeHtml {
    <# Escape for HTML report bodies. All untrusted strings must pass through here. #>
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    $s = [string]$Text
    $s = $s.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
    return $s
}
