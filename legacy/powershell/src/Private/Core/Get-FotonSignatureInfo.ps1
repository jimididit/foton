function Get-FotonSignatureInfo {
    <# Authenticode status for a path. Invalid/Unknown is not malice; catalog-signed OS files often fail this API. #>
    param([string]$Path)
    $result = [PSCustomObject]@{ Status = 'Unknown'; Signer = ''; IsOSBinary = $false }
    if ([string]::IsNullOrWhiteSpace($Path)) { return $result }
    try {
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            $result.Status = 'FileNotFound'
            return $result
        }
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
        $result.Status = [string]$sig.Status
        if ($sig.SignerCertificate) { $result.Signer = [string]$sig.SignerCertificate.Subject }
        if ($sig.IsOSBinary) { $result.IsOSBinary = $true }
    }
    catch { $result.Status = 'SignatureCheckError' }
    return $result
}
