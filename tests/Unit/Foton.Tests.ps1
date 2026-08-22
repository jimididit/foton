# Foton.Tests.ps1 — module import smoke test
# Confirms the scaffold loads on Windows PowerShell 5.1 / PS7 without Collect present.

$moduleManifest = Join-Path $PSScriptRoot '..\Foton.psd1'

Describe 'Foton module scaffold' {
    It 'has a parse-clean module manifest' {
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $moduleManifest,
            [ref]$null,
            [ref]$errors
        )
        $errors | Should -BeNullOrEmpty
    }

    It 'imports and reports version metadata' {
        Import-Module $moduleManifest -Force
        $v = Get-FotonVersion
        $v.ProductName | Should -Be 'Foton'
        $v.ModuleVersion | Should -Be '1.2.0'
        $v.CollectSchemaVersion | Should -Be '1.0.0'
        $v.BaselineSchemaVersion | Should -Be '1.0.0'
        $v.FindingsSchemaVersion | Should -Be '1.0.0'
    }

    It 'exports package, analysis, and report commands (Collect stays unexported)' {
        Import-Module $moduleManifest -Force
        Get-Command -Module Foton | Select-Object -ExpandProperty Name | Sort-Object |
            Should -Be @('Get-FotonPackage', 'Get-FotonVersion', 'Invoke-FotonAnalysis', 'Invoke-FotonTriage', 'New-FotonReport')
    }
}
