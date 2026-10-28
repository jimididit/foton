BeforeAll {
    $script:FotonPsd1 = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Foton.psd1'))
    Import-Module $script:FotonPsd1 -Force
}

Describe 'Collect category functions (extracted)' {
    It 'defines all nine category collectors' {
        InModuleScope Foton {
            Get-Command Invoke-FotonSystemCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
            Get-Command Invoke-FotonUserCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
            Get-Command Invoke-FotonProcessCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
            Get-Command Invoke-FotonNetworkCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
            Get-Command Invoke-FotonPersistenceCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
            Get-Command Invoke-FotonSecurityCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
            Get-Command Invoke-FotonEventLogCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
            Get-Command Invoke-FotonFilesystemCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
            Get-Command Invoke-FotonSoftwareCollection -ErrorAction Stop | Should -Not -BeNullOrEmpty
        }
    }

    It 'does not interpret command text during collection' {
        # Collectors never interpret, and the pattern list cannot ship in the flatten
        # (Defender AMSI blocks it as Trojan:PowerShell/PSAttackTool.A). Matching
        # belongs to Invoke-FotonAnalysis.
        foreach ($leaf in @('Invoke-FotonProcessCollection.ps1', 'Invoke-FotonPersistenceCollection.ps1')) {
            $src = Get-Content -LiteralPath (Join-Path $PSScriptRoot "..\..\src\Public\Collect\$leaf") -Raw
            $src | Should -Not -Match 'Test-FotonSuspiciousCommand'
        }
    }

    It 'records local group membership enum failures instead of pretending empty' {
        $src = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\src\Public\Collect\Invoke-FotonUserCollection.ps1') -Raw
        $src | Should -Match '\(error:'
        $src | Should -Match 'enumError'
    }

    It 'probes scheduled-task Arguments for user-writable targets' {
        $src = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\src\Public\Collect\Invoke-FotonPersistenceCollection.ps1') -Raw
        $src | Should -Match 'writableProbe'
        $src | Should -Match 'WorkingDirectory'
    }

    It 'keeps the suspicious-command pattern list out of the generated flatten' {
        $build = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\build\Build-Standalone.ps1') -Raw
        $build | Should -Match 'SuspiciousCommandPatterns\s*=\s*@\(\)'

        $flat = Join-Path $PSScriptRoot '..\..\dist\Foton-Collect.ps1'
        if (Test-Path -LiteralPath $flat) {
            # One representative string from the blocked array. Its presence means the
            # embed came back and the collector will be quarantined on the endpoint.
            (Get-Content -LiteralPath $flat -Raw) | Should -Not -Match 'sekurlsa'
        }
    }

    It 'adds named persistence CSVs for CmdAutoRun, Session Manager, KnownDLLs, Winsock, Active Setup' {
        $src = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\src\Public\Collect\Invoke-FotonPersistenceCollection.ps1') -Raw
        $src | Should -Match "Name 'cmd_autorun'"
        $src | Should -Match "Name 'session_manager_boot'"
        $src | Should -Match "Name 'known_dlls'"
        $src | Should -Match "Name 'winsock_lsp'"
        $src | Should -Match "Name 'active_setup'"
        $src | Should -Match "Name 'silent_process_exit'"
        $src | Should -Match "Name 'netsh_helpers'"
        $src | Should -Match "Name 'time_providers'"
        $src | Should -Match "Name 'screensaver'"
    }

    It 'adds copy-into-package tasks for Prefetch, Amcache, and SRUM' {
        $src = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\src\Public\Collect\Invoke-FotonFilesystemCollection.ps1') -Raw
        $src | Should -Match "Name 'prefetch_files'"
        $src | Should -Match "Name 'amcache_hive'"
        $src | Should -Match "Name 'srum_database'"
        $src | Should -Match "Name 'prefetch_listing'"
        $src | Should -Match "Name 'bam_dam_user_settings'"
        $src | Should -Match "Name 'appcompatcache_export'"
        $src | Should -Match "Name 'onedrive_teams_local'"
        $src | Should -Match "Name 'registry_hives_machine'"
        $src | Should -Match "Name 'registry_hives_user'"
        $src | Should -Match "Name 'usn_journal'"
        $src | Should -Match "Name 'shortcut_and_jumplist_files'"
        $src | Should -Match "Name 'scheduled_task_xml'"
        $src | Should -Match "Name 'browser_databases'"
        $src | Should -Match "Name 'host_text_logs'"
        $src | Should -Match 'IncludeUsnJournal'
        $src | Should -Not -Match 'graph\.microsoft'
    }

    It 'exports additional EVTX channels for hunt compose' {
        $src = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\src\Public\Collect\Invoke-FotonEventLogCollection.ps1') -Raw
        $src | Should -Match 'Microsoft-Windows-Bits-Client/Operational'
        $src | Should -Match 'Microsoft-Windows-Sysmon/Operational'
        $src | Should -Match 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
    }

    It 'adds entra_workplace_join on the System collector' {
        $src = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\src\Public\Collect\Invoke-FotonSystemCollection.ps1') -Raw
        $src | Should -Match "Name 'entra_workplace_join'"
        $src | Should -Not -Match 'dsregcmd\.exe'
        $src | Should -Match 'Get-FotonCloudJoinRows'
    }

    It 'adds a named_pipes collect task' {
        $src = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\src\Public\Collect\Invoke-FotonProcessCollection.ps1') -Raw
        $src | Should -Match "Name 'named_pipes'"
    }

    It 'wires -Deep through triage, session, flatten, and custody' {
        $triage = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\src\Public\Invoke-FotonTriage.ps1') -Raw
        $triage | Should -Match '\[switch\]\$Deep'
        $triage | Should -Match '-Deep:\$Deep'
        $triage | Should -Match 'IncludeFileTimeline = \$true'
        $triage | Should -Match 'IncludeUsnJournal = \$true'

        $session = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\src\Private\Core\Initialize-FotonSession.ps1') -Raw
        $session | Should -Match '\[switch\]\$Deep'
        $session | Should -Match 'Deep\s+=\s+\[bool\]\$Deep'

        $build = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\build\Build-Standalone.ps1') -Raw
        $build | Should -Match '\[switch\]\`\$Deep'

        $custody = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\src\Private\Core\Write-FotonChainOfCustody.ps1') -Raw
        $custody | Should -Match 'IncludeUsnJournal'
        $custody | Should -Match 'Deep\s+='
    }

    It 'gates Deep collectors behind FotonSession.Deep' {
        $fs = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\src\Public\Collect\Invoke-FotonFilesystemCollection.ps1') -Raw
        $fs | Should -Match "Name 'task_action_scripts'"
        $fs | Should -Match 'FotonSession\.Deep'
        $fs | Should -Match 'Test-FotonDeepDiskBudget'
        $fs | Should -Match 'Get-FotonTaskActionScriptPath'
        $fs | Should -Match 'SkippedUnc'
        $fs | Should -Match 'GetFullPath'
        $fs | Should -Match 'Substring\(0, 1\)'

        $sw = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\src\Public\Collect\Invoke-FotonSoftwareCollection.ps1') -Raw
        $sw | Should -Match "Name 'pnp_devices'"
        $sw | Should -Match "Name 'driverstore_inventory'"
        $sw | Should -Match 'Win32_PnPEntity'
        $sw | Should -Match 'DriverStore\\FileRepository'

        $sec = Get-Content -LiteralPath (Join-Path $PSScriptRoot '..\..\src\Public\Collect\Invoke-FotonSecurityCollection.ps1') -Raw
        $sec | Should -Match "Name 'gpresult_html'"
        $sec | Should -Match 'gpresult\.exe /h'
    }

    It 'does not export Collect commands on the public module surface yet' {
        Get-Command -Module Foton | Select-Object -ExpandProperty Name | Sort-Object |
            Should -Be @(
                'Compare-FotonBaseline'
                'ConvertFrom-FotonAmcache'
                'ConvertFrom-FotonEvtx'
                'ConvertFrom-FotonJumplist'
                'ConvertFrom-FotonLnk'
                'ConvertFrom-FotonPrefetch'
                'Get-FotonPackage'
                'Get-FotonVersion'
                'Install-FotonTool'
                'Invoke-FotonAnalysis'
                'Invoke-FotonCarve'
                'Invoke-FotonExternalParse'
                'Invoke-FotonIocMatch'
                'Invoke-FotonParse'
                'Invoke-FotonTriage'
                'New-FotonBaseline'
                'New-FotonBaselineCompareReport'
                'New-FotonBaselineReport'
                'New-FotonParseReport'
                'New-FotonReport'
            )
    }
}
