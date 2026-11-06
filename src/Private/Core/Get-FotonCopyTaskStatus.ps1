function Get-FotonCopyTaskStatus {
    <#
        Derive a task status from per-file copy rows (Copy-FotonHostFile family,
        Save-FotonRegistryHive). Only explicit copy failures count: CappedSkip,
        Missing, NotCollectedByDesign, and SupersededBySave are recorded outcomes,
        and a Status column on ordinary data (PnP device Status = Error) is not a
        copy row at all, so only CopyError / SaveError are treated as failures.

        Returns Success (no failures), Partial (some captured, some failed), or
        Failed (nothing captured and at least one failure).
    #>
    param([object]$Rows)

    $result = [PSCustomObject]@{ Status = 'Success'; Message = '' }
    $list = @($Rows | Where-Object { $null -ne $_ -and $_.PSObject.Properties['Status'] })
    if ($list.Count -eq 0) { return $result }

    $failed = @($list | Where-Object { [string]$_.Status -in @('CopyError', 'SaveError') })
    if ($failed.Count -eq 0) { return $result }

    $ok = @($list | Where-Object { [string]$_.Status -in @('Copied', 'Saved') })
    $first = $failed[0]
    $what = [string]$first.SourcePath
    $why = [string]$first.Note
    $result.Message = ('{0} of {1} file(s) not captured. First: {2} - {3}' -f $failed.Count, $list.Count, $what, $why)
    if ($ok.Count -gt 0) { $result.Status = 'Partial' } else { $result.Status = 'Failed' }
    return $result
}
