function Find-FotonRecmdBatch {
    <#
        RECmd batch file shipped beside the binary. DFIRBatch.reb is Eric Zimmerman's
        broad DFIR set; Kroll_Batch.reb is the older equivalent. $null when neither exists.
    #>
    param([Parameter(Mandatory)][string]$RecmdPath)
    $dir = Split-Path -Parent $RecmdPath
    foreach ($leaf in @('DFIRBatch.reb', 'Kroll_Batch.reb')) {
        $p = Join-Path $dir (Join-Path 'BatchExamples' $leaf)
        if (Test-Path -LiteralPath $p -PathType Leaf) { return (Get-Item -LiteralPath $p).FullName }
    }
    return $null
}

function Find-FotonChainsawRules {
    <#
        Chainsaw rule sources beside the binary: rules\ (Chainsaw rules) and sigma\
        (Sigma rules, which need mappings\sigma-event-logs-all.yml to run).
    #>
    param([Parameter(Mandatory)][string]$ChainsawPath)
    $dir = Split-Path -Parent $ChainsawPath
    $result = [PSCustomObject]@{ RulesPath = $null; SigmaPath = $null; MappingPath = $null }
    $rules = Join-Path $dir 'rules'
    if (Test-Path -LiteralPath $rules -PathType Container) { $result.RulesPath = (Get-Item -LiteralPath $rules).FullName }
    $sigma = Join-Path $dir 'sigma'
    $mapping = $null
    foreach ($m in @((Join-Path $dir 'mappings\sigma-event-logs-all.yml'), (Join-Path $dir 'sigma-event-logs-all.yml'))) {
        if (Test-Path -LiteralPath $m -PathType Leaf) { $mapping = (Get-Item -LiteralPath $m).FullName; break }
    }
    if ((Test-Path -LiteralPath $sigma -PathType Container) -and $mapping) {
        $result.SigmaPath = (Get-Item -LiteralPath $sigma).FullName
        $result.MappingPath = $mapping
    }
    return $result
}

function Test-FotonToolMissingRuntime {
    <# True when a tool's captured output says its .NET runtime is not installed. #>
    param([string[]]$Paths)
    foreach ($p in @($Paths)) {
        if (-not $p -or -not (Test-Path -LiteralPath $p -PathType Leaf)) { continue }
        try {
            $text = Get-Content -LiteralPath $p -Raw -ErrorAction Stop
            if ($text -match 'You must install or update \.NET|install the missing framework') { return $true }
        }
        catch { }
    }
    return $false
}
