function Initialize-FotonCase {
    <# Create Foton_<host>_<stamp>Z case tree and session Dirs. Live collect only. #>
    param([Parameter(Mandatory)][string]$OutputPath)

    $host_ = $env:COMPUTERNAME
    $stamp = $script:FotonSession.StartTimeUtc.ToString('yyyyMMdd-HHmmss')
    $caseFolderName = "Foton_{0}_{1}Z" -f $host_, $stamp

    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
    $script:FotonSession.CaseRoot = Join-Path $OutputPath $caseFolderName
    New-Item -Path $script:FotonSession.CaseRoot -ItemType Directory -Force | Out-Null

    foreach ($key in $script:FotonSession.Categories.Keys) {
        $dir = Join-Path $script:FotonSession.CaseRoot $script:FotonSession.Categories[$key]
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        $script:FotonSession.Dirs[$key] = $dir
    }

    $script:FotonSession.LogFile = Join-Path $script:FotonSession.Dirs['Collection'] 'collection.log'
    "Foton $($script:FotonSession.Version) collection log" | Out-File -FilePath $script:FotonSession.LogFile -Encoding UTF8
    return $script:FotonSession.CaseRoot
}
