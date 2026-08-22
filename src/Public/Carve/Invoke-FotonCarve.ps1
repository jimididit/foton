function Invoke-FotonCarve {
    <#
    .SYNOPSIS
        Placeholder. Full NTFS carving is not implemented in this PowerShell toolkit.

    .DESCRIPTION
        Signature carving of known headers in a blob may be added later. Unallocated
        cluster walks, FILE record parsing, and slack reconstruction need a
        purpose-built engine (see docs/CARVE.md). Guessing NTFS in PowerShell would
        produce wrong timestamps and paths — worse than missing data.

        Carved hits, when they exist, are Tier 3 until corroborated.

    .EXAMPLE
        # Read the proposal rather than running a fake carver:
        Get-Content .\docs\CARVE.md
    #>
    [CmdletBinding()]
    param(
        [string]$Path
    )
    throw 'Invoke-FotonCarve is not implemented. Full NTFS unallocated parsing will not be built in PowerShell. See docs/CARVE.md for the proposed approach.'
}
