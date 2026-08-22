BeforeAll {
    $script:FotonPsd1 = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Foton.psd1'))
    $script:Ref = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\Fixtures\Baseline\ref.json'))
    $script:Dif = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\Fixtures\Baseline\dif.json'))
    Import-Module $script:FotonPsd1 -Force
}

Describe 'Baseline providers and diff' {
    It 'registers the first provider set' {
        InModuleScope Foton {
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'Service'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'LocalAccount'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'ScheduledTask'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'Autorun'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'Driver'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'FirewallRule'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'Certificate'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'Listener'
        }
    }

    It 'diffs field-level changes and fires High on service PathName and new admin' {
        $changes = Compare-FotonBaseline -ReferencePath $script:Ref -DifferencePath $script:Dif
        $path = @($changes | Where-Object { $_.RecordType -eq 'Service' -and $_.Field -eq 'PathName' })
        $path.Count | Should -Be 1
        $path[0].ChangeType | Should -Be 'Modified'
        $admin = @($changes | Where-Object { $_.RecordType -eq 'LocalGroupMember' -and $_.ChangeType -eq 'Added' })
        $admin.Count | Should -Be 1
        $ver = @($changes | Where-Object { $_.Field -eq 'DisplayVersion' })
        $ver[0].ChangeType | Should -Be 'Modified'
        InModuleScope Foton {
            $script:FotonSession.Findings | Where-Object { $_.Title -eq 'Modified Service' -and $_.Severity -eq 'High' } |
                Should -Not -BeNullOrEmpty
            $script:FotonSession.Findings | Where-Object { $_.Title -eq 'Added LocalGroupMember' -and $_.Severity -eq 'High' } |
                Should -Not -BeNullOrEmpty
        }
    }

    It 'does not treat a software version bump as High' {
        Compare-FotonBaseline -ReferencePath $script:Ref -DifferencePath $script:Dif | Out-Null
        InModuleScope Foton {
            @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Modified InstalledSoftware' -and $_.Severity -eq 'Info' }) |
                Should -Not -BeNullOrEmpty
        }
    }

    It 'refuses a schema mismatch' {
        $tmp = Join-Path $env:TEMP ('foton-base-' + [guid]::NewGuid().ToString('N') + '.json')
        $j = Get-Content -LiteralPath $script:Dif -Raw | ConvertFrom-Json
        $j.Header.BaselineSchemaVersion = '9.9.9'
        ($j | ConvertTo-Json -Depth 8) | Out-File -FilePath $tmp -Encoding utf8
        try {
            { Compare-FotonBaseline -ReferencePath $script:Ref -DifferencePath $tmp } | Should -Throw
        }
        finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
}
