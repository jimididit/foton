function Add-FotonFinding {
    <#
        Records an automated observation for the report.

        Tier is evidentiary strength, not urgency:
          1 = Observed artifact. Stated as fact.
          2 = Supported inference. Other readings remain possible.
          3 = Unverified hypothesis. Carved or uncorroborated data only.

        Never assert compromise, attribution, intent, or causation.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('High', 'Medium', 'Low', 'Info')][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][string]$Observation,
        [ValidateSet(1, 2, 3)][int]$Tier = 2,
        [string]$WhyItMatters = '',
        [string]$Artifact = '',
        [string]$NextStep = ''
    )
    $null = $script:FotonSession.Findings.Add([PSCustomObject]@{
            Severity     = $Severity
            Category     = $Category
            Title        = $Title
            Observation  = $Observation
            Tier         = $Tier
            WhyItMatters = $WhyItMatters
            Artifact     = $Artifact
            NextStep     = $NextStep
        })
}
