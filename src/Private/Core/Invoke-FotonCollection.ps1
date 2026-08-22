function Invoke-FotonCollection {
    <#
        Runs one collection task: write artifact, manifest row, timing, error capture, cache.
        A failure here is logged and does not stop the run - partial collection is evidence.

        -RequiresElevation: skip with Status SkippedNotElevated when the token is not admin.
        That is a visibility gap, not a collection error.
    #>
    param(
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Script,
        [ValidateSet('Json', 'Csv', 'Txt')][string]$Format = 'Json',
        [string]$Description = '',
        [switch]$NoCache,
        [switch]$RequiresElevation
    )

    $dir = $script:FotonSession.Dirs[$Category]
    $file = Join-Path $dir ("{0}.{1}" -f $Name, $Format.ToLower())
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $status = 'Success'
    $errMsg = ''
    $data = $null
    $count = 0
    $categories = $script:FotonSession.Categories

    if ($RequiresElevation -and -not $script:FotonSession.IsElevated) {
        $status = 'SkippedNotElevated'
        $errMsg = 'Requires an Administrator token; skipped in standard-user coverage.'
        $skipText = @(
            "Foton: task '$Name' was not run."
            "Status: SkippedNotElevated"
            $errMsg
            'This is a visibility gap. Do not treat a missing or empty artifact as proof the underlying data was absent on the host.'
        ) -join [Environment]::NewLine
        try { $skipText | Out-File -FilePath $file -Encoding UTF8 } catch { }
        $sw.Stop()
        $null = $script:FotonSession.Manifest.Add([PSCustomObject]@{
                Category    = $Category
                Task        = $Name
                Description = $Description
                File        = (Join-Path $categories[$Category] (Split-Path $file -Leaf))
                Records     = 0
                Status      = $status
                DurationMs  = [int]$sw.ElapsedMilliseconds
                Error       = $errMsg
            })
        if (-not $NoCache) { $script:FotonSession.Data[$Name] = $null }
        Write-FotonStatus "$Name - skipped (not elevated)" 'Info'
        return $null
    }

    try {
        $data = & $Script
    }
    catch {
        $status = 'Error'
        $errMsg = $_.Exception.Message
        $null = $script:FotonSession.Errors.Add([PSCustomObject]@{ Task = $Name; Error = $errMsg })
    }

    try {
        if ($null -eq $data -or ($data -is [System.Array] -and $data.Count -eq 0)) {
            if ($status -eq 'Success') { $status = 'NoData' }
            "Foton: no data returned for '$Name'. Status: $status. $errMsg" |
                Out-File -FilePath $file -Encoding UTF8
        }
        else {
            $count = @($data).Count
            switch ($Format) {
                'Json' { $data | ConvertTo-Json -Depth 5 -Compress:$false | Out-File -FilePath $file -Encoding UTF8 }
                'Csv' { $data | Export-Csv -Path $file -NoTypeInformation -Encoding UTF8 }
                'Txt' { $data | Out-String -Width 4096 | Out-File -FilePath $file -Encoding UTF8 }
            }
        }
    }
    catch {
        $status = 'WriteError'
        $errMsg = $_.Exception.Message
        try { "Foton write error for '$Name': $errMsg" | Out-File -FilePath $file -Encoding UTF8 } catch { }
    }

    $sw.Stop()

    $null = $script:FotonSession.Manifest.Add([PSCustomObject]@{
            Category    = $Category
            Task        = $Name
            Description = $Description
            File        = (Join-Path $categories[$Category] (Split-Path $file -Leaf))
            Records     = $count
            Status      = $status
            DurationMs  = [int]$sw.ElapsedMilliseconds
            Error       = $errMsg
        })

    if (-not $NoCache) { $script:FotonSession.Data[$Name] = $data }

    switch ($status) {
        'Success' { Write-FotonStatus "$Name ($count records, $([int]$sw.ElapsedMilliseconds) ms)" 'Good' }
        'NoData' { Write-FotonStatus "$Name - no data returned" 'Info' }
        default { Write-FotonStatus "$Name - $status : $errMsg" 'Warn' }
    }

    return $data
}
