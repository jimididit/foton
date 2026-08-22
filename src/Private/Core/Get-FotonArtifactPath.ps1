function Get-FotonArtifactPath {
    <# Relative package path used in findings (forward slashes) so HTML links resolve inside the extracted folder. #>
    param(
        [string]$Category,
        [string]$Name,
        [string]$Format = 'json'
    )
    return ("{0}/{1}.{2}" -f $script:FotonSession.Categories[$Category], $Name, $Format)
}
