function Resolve-FotonCaseRoot {
    param([string]$SearchRoot)
    $probe = Join-Path $SearchRoot '00_Collection'
    if (Test-Path -LiteralPath $probe) { return $SearchRoot }
    $dirs = @(Get-ChildItem -LiteralPath $SearchRoot -Directory -ErrorAction SilentlyContinue)
    foreach ($d in $dirs) {
        if (Test-Path -LiteralPath (Join-Path $d.FullName '00_Collection')) {
            return $d.FullName
        }
    }
    throw "No 00_Collection folder under $SearchRoot. Point at an extracted WinFoton/Foton case."
}

function Get-FotonNestedDuplicateRoot {
    <#
        A well-formed package has exactly one 00_Collection. Some packages arrive
        with the whole case tree copied inside itself, usually because the ZIP was
        extracted into the case folder and re-zipped in transit. That is not a
        second collection: the inner hashes.csv is byte-identical.

        Returns the nested duplicate directory so callers can skip it. Left in
        place, it makes recursive walks (parse, carve, hashing) count every
        artifact twice, which inflates row counts without adding evidence.
    #>
    param([string]$CaseRoot)
    if (-not $CaseRoot -or -not (Test-Path -LiteralPath $CaseRoot)) { return $null }
    foreach ($d in @(Get-ChildItem -LiteralPath $CaseRoot -Directory -ErrorAction SilentlyContinue)) {
        if (Test-Path -LiteralPath (Join-Path $d.FullName '00_Collection')) {
            return $d.FullName
        }
    }
    return $null
}

function Convert-FotonCsvBooleans {
    <# Import-Csv stores True/False as strings. Analysis compares -eq $true. #>
    param($Rows)
    foreach ($row in @($Rows)) {
        if ($null -eq $row) { continue }
        foreach ($prop in $row.PSObject.Properties) {
            $v = $prop.Value
            if ($v -ceq 'True') { $row.($prop.Name) = $true }
            elseif ($v -ceq 'False') { $row.($prop.Name) = $false }
        }
    }
    return $Rows
}

function Test-FotonArtifactSentinel {
    param([string]$Path)
    try {
        $first = Get-Content -LiteralPath $Path -TotalCount 1 -ErrorAction Stop
        if ($first -match '^(Foton|WinFoton):') { return $true }
    }
    catch { }
    return $false
}

function Import-FotonArtifactFile {
    param([string]$Path)
    $ext = [IO.Path]::GetExtension($Path).ToLower()
    if (Test-FotonArtifactSentinel -Path $Path) { return $null }
    try {
        switch ($ext) {
            '.json' {
                $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
                if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
                return ($raw | ConvertFrom-Json)
            }
            '.csv' {
                $rows = @(Import-Csv -LiteralPath $Path -ErrorAction Stop)
                if ($rows.Count -eq 0) { return @() }
                return (Convert-FotonCsvBooleans -Rows $rows)
            }
            '.txt' {
                return @(Get-Content -LiteralPath $Path -ErrorAction Stop)
            }
            default { return $null }
        }
    }
    catch {
        return $null
    }
}

function Import-FotonPackageData {
    <#
        Load collected artifacts from a case folder into $script:FotonSession.
        Does not read the live host. Skips hashes, reports, EVTX, and prior findings
        so re-analysis does not treat those as collect tasks.
    #>
    param([Parameter(Mandatory)][string]$CaseRoot)

    $script:FotonSession.CaseRoot = $CaseRoot
    $script:FotonSession.Data = @{}
    $script:FotonSession.Findings = New-Object System.Collections.ArrayList
    $script:FotonSession.Manifest = New-Object System.Collections.ArrayList
    $script:FotonSession.Errors = New-Object System.Collections.ArrayList
    $script:FotonSession.Dirs = @{}

    foreach ($key in $script:FotonSession.Categories.Keys) {
        $dir = Join-Path $CaseRoot $script:FotonSession.Categories[$key]
        $script:FotonSession.Dirs[$key] = $dir
    }

    $skipNames = @(
        'hashes.csv', 'hashes.txt', 'findings.csv', 'collection.log',
        'chain_of_custody.txt', 'collection_manifest.csv', 'collection_errors.csv'
    )

    $collectionDir = Join-Path $CaseRoot '00_Collection'
    $manifestPath = Join-Path $collectionDir 'collection_manifest.csv'
    if (Test-Path -LiteralPath $manifestPath) {
        foreach ($row in @(Import-Csv -LiteralPath $manifestPath -ErrorAction SilentlyContinue)) {
            $null = $script:FotonSession.Manifest.Add($row)
        }
    }
    $errPath = Join-Path $collectionDir 'collection_errors.csv'
    if (Test-Path -LiteralPath $errPath) {
        foreach ($row in @(Import-Csv -LiteralPath $errPath -ErrorAction SilentlyContinue)) {
            $null = $script:FotonSession.Errors.Add($row)
        }
    }

    $files = @(Get-ChildItem -LiteralPath $CaseRoot -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Extension -match '\.(json|csv|txt)$' -and
                $_.Extension -ne '.evtx' -and
                $skipNames -notcontains $_.Name -and
                $_.DirectoryName -notmatch '[\\/](evtx|analysis)([\\/]|$)' -and
                $_.Name -notmatch 'Report\.html$'
            })

    foreach ($f in $files) {
        $data = Import-FotonArtifactFile -Path $f.FullName
        if ($null -eq $data) { continue }
        $name = [IO.Path]::GetFileNameWithoutExtension($f.Name)
        $script:FotonSession.Data[$name] = $data
    }

    $leaf = Split-Path $CaseRoot -Leaf
    if ($leaf -match '_(20\d{6}-\d{6})Z$') {
        $stamp = $Matches[1]
        try {
            $script:FotonSession.StartTimeUtc = [datetime]::ParseExact($stamp, 'yyyyMMdd-HHmmss', [cultureinfo]::InvariantCulture).ToUniversalTime()
        }
        catch { }
    }
}
