BeforeAll {
    $script:FotonPsd1 = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Foton.psd1'))
    $script:Fixture = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\Fixtures\WinFoton_FIXTURE_20260115-120000Z'))
    Import-Module $script:FotonPsd1 -Force
}

Describe 'Get-FotonPackage and offline analysis' {
    It 'loads v1-style folder artifacts and does not treat hashes as collect data' {
        $pkg = Get-FotonPackage -Path $script:Fixture
        $pkg.Kind | Should -Be 'Folder'
        InModuleScope Foton {
            $script:FotonSession.Data.ContainsKey('os_info') | Should -Be $true
            $script:FotonSession.Data['os_info'].Hostname | Should -Be 'FIXTURE-PC'
            $script:FotonSession.Data.ContainsKey('hashes') | Should -Be $false
            $script:FotonSession.Data.ContainsKey('security_process_creation') | Should -Be $false
            $script:FotonSession.Data['running_processes'][1].UserWritablePath | Should -Be $true
        }
    }

    It 'fires WDigest and RTP heuristics and not for a benign hardening value' {
        Get-FotonPackage -Path $script:Fixture | Out-Null
        Invoke-FotonAnalysis
        InModuleScope Foton {
            $titles = @($script:FotonSession.Findings | ForEach-Object { $_.Title })
            $titles | Should -Contain 'WDigest cleartext credential storage is enabled'
            $titles | Should -Contain 'Defender real-time protection is disabled'
            $titles | Should -Contain 'Unsigned processes running from user-writable paths'
            $titles | Should -Contain 'Host and collection baseline'
            $titles | Should -Contain 'Collection ran without Administrator rights'
        }
        $analysisCsv = Join-Path $script:Fixture 'analysis\findings.csv'
        Test-Path -LiteralPath $analysisCsv | Should -Be $true
    }

    It 'derives suspicious-command hits from raw columns when Collect left them empty' {
        InModuleScope Foton {
            Initialize-FotonSession
            # Collect schema 1.10.0: endpoint writes the column empty, raw text stays.
            $script:FotonSession.Data['running_processes'] = @(
                [PSCustomObject]@{
                    Name = 'powershell.exe'; PID = 4242; Path = 'C:\Windows\System32\powershell.exe'
                    SuspiciousCmdHits = ''; CommandLine = 'powershell -encodedcommand ZQBjAGgAbwA='
                }
            )
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis

            $hit = @($script:FotonSession.Findings |
                    Where-Object { $_.Title -eq 'Running process command lines contain high-risk patterns' })
            $hit | Should -HaveCount 1
            $hit[0].Observation | Should -Match 'encodedcommand'
        }
    }

    It 'excludes collector-caused Hayabusa rows from the severity bands' {
        $tmp = Join-Path $env:TEMP ('foton-self-' + [guid]::NewGuid().ToString('N'))
        $hay = Join-Path $tmp 'analysis\external\hayabusa'
        New-Item -Path $hay -ItemType Directory -Force | Out-Null
        try {
            # Two medium rows: one is the collector's own script block, one is not.
            $lines = @(
                '"Timestamp","RuleTitle","Level","Computer","Channel","EventID","RecordID","Details","ExtraFieldInfo","RuleID"'
                '"2026-01-01 00:00:00 +00:00","Potentially Malicious PwSh","med","H","Sec",4104,1,"ScriptBlock: Get-FotonRegValue -Path HKLM:\\x","x","id1"'
                '"2026-01-01 00:00:01 +00:00","WMI Persistence","med","H","Sec",1,2,"genuine host activity","x","id2"'
            )
            Set-Content -LiteralPath (Join-Path $hay 'hayabusa.csv') -Value $lines -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
                Invoke-FotonAnalysis

                $med = @($script:FotonSession.Findings | Where-Object { $_.Title -like '*medium-level*' })
                $med | Should -HaveCount 1
                # Only the non-collector row counts toward the band.
                $med[0].Observation | Should -Match '^1 medium-level'
                $med[0].Observation | Should -Match 'WMI Persistence'
                $med[0].Observation | Should -Not -Match 'Potentially Malicious PwSh'
                $med[0].Observation | Should -Match 'Excludes 1 row'

                $self = @($script:FotonSession.Findings |
                        Where-Object { $_.Title -eq 'Hayabusa hits caused by the Foton collection itself' })
                $self | Should -HaveCount 1
                $self[0].Severity | Should -Be 'Info'
                $self[0].Category | Should -Be 'Methodology'
                $self[0].Observation | Should -Match 'Potentially Malicious PwSh'
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'does not treat a bare Foton case-path substring as collector Hayabusa noise' {
        $tmp = Join-Path $env:TEMP ('foton-path-' + [guid]::NewGuid().ToString('N'))
        $hay = Join-Path $tmp 'analysis\external\hayabusa'
        New-Item -Path $hay -ItemType Directory -Force | Out-Null
        try {
            $lines = @(
                '"Timestamp","RuleTitle","Level","Computer","Channel","EventID","RecordID","Details","ExtraFieldInfo","RuleID"'
                '"2026-01-01 00:00:00 +00:00","EncodedCommand","high","H","Sec",4104,1,"powershell -enc ABC path C:\Cases\Foton_HOST_Z\x","x","id1"'
            )
            Set-Content -LiteralPath (Join-Path $hay 'hayabusa.csv') -Value $lines -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
                Invoke-FotonAnalysis
                $hi = @($script:FotonSession.Findings | Where-Object { $_.Title -like '*high-level*' })
                $hi | Should -HaveCount 1
                $hi[0].Observation | Should -Match 'EncodedCommand'
                $hi[0].Observation | Should -Not -Match 'Excludes'
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'attributes Hayabusa rows inside the collection window to the collector' {
        $tmp = Join-Path $env:TEMP ('foton-win-' + [guid]::NewGuid().ToString('N'))
        $hay = Join-Path $tmp 'analysis\external\hayabusa'
        New-Item -Path $hay -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $tmp '00_Collection') -ItemType Directory -Force | Out-Null
        try {
            # collection.log bounds the run; Analyze reads the first and last stamp.
            Set-Content -LiteralPath (Join-Path $tmp '00_Collection\collection.log') -Encoding UTF8 -Value @(
                'Foton test collection log'
                '2026-01-01 00:10:00 UTC  [Good] Case folder: X'
                '2026-01-01 00:12:00 UTC  [Good] Hashed 1 artifacts'
            )
            # Row 1 is inside the window with no Foton token, row 2 is outside it.
            $lines = @(
                '"Timestamp","RuleTitle","Level","Computer","Channel","EventID","RecordID","Details","ExtraFieldInfo","RuleID"'
                '"2026-01-01 00:11:00 +00:00","Potentially Malicious PwSh","med","H","Sec",4104,1,"ordinary powershell","x","id1"'
                '"2026-01-01 09:00:00 +00:00","WMI Persistence","med","H","Sec",1,2,"genuine host activity","x","id2"'
            )
            Set-Content -LiteralPath (Join-Path $hay 'hayabusa.csv') -Value $lines -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })

                $w = Get-FotonCollectionWindow -CaseRoot $Root
                $w.StartUtc.UtcDateTime.ToString('HH:mm:ss') | Should -Be '00:10:00'
                $w.EndUtc.UtcDateTime.ToString('HH:mm:ss') | Should -Be '00:12:00'

                Invoke-FotonAnalysis

                $med = @($script:FotonSession.Findings | Where-Object { $_.Title -like '*medium-level*' })
                $med | Should -HaveCount 1
                # The in-window row is excluded even though it never mentions Foton.
                $med[0].Observation | Should -Match '^1 medium-level'
                $med[0].Observation | Should -Match 'WMI Persistence'

                $self = @($script:FotonSession.Findings |
                        Where-Object { $_.Title -eq 'Hayabusa hits caused by the Foton collection itself' })
                $self | Should -HaveCount 1
                $self[0].Observation | Should -Match '1 fell inside the collection window'
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'raises a visibility-gap finding when no suspicious-command patterns are loaded' {
        InModuleScope Foton {
            Initialize-FotonSession
            # This is the state inside the endpoint flatten: absence of pattern
            # findings there must not read as a clean result.
            $script:FotonSession.SuspiciousCommandPatterns = @()
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis

            $gap = @($script:FotonSession.Findings |
                    Where-Object { $_.Title -eq 'Suspicious-command pattern matching did not run' })
            $gap | Should -HaveCount 1
            $gap[0].Severity | Should -Be 'Info'
            $gap[0].Tier | Should -Be 1
        }
    }

    It 'does not raise the visibility gap when patterns are loaded' {
        InModuleScope Foton {
            Initialize-FotonSession
            @($script:FotonSession.SuspiciousCommandPatterns).Count | Should -BeGreaterThan 0
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis

            @($script:FotonSession.Findings |
                Where-Object { $_.Title -eq 'Suspicious-command pattern matching did not run' }) |
                Should -HaveCount 0
        }
    }

    It 'does not fire WDigest when UseLogonCredential is 0' {
        InModuleScope Foton {
            Initialize-FotonSession
            $script:FotonSession.Data['hardening_registry_settings'] = @(
                [PSCustomObject]@{ Setting = 'UseLogonCredential'; Value = '0' }
            )
            $script:FotonSession.Data['security_process_creation'] = @(
                [PSCustomObject]@{ EventId = 4688 }
            )
            Invoke-FotonAnalysis
            @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'WDigest cleartext credential storage is enabled' }) |
                Should -HaveCount 0
        }
    }

    It 'fires on parsed user-writable paths and not on System32' {
        $tmp = Join-Path $env:TEMP ('foton-an-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path (Join-Path $tmp 'analysis') -ItemType Directory -Force | Out-Null
        try {
            @(
                [PSCustomObject]@{ Identity = 'C:\Users\Public\evil.exe'; Path = 'C:\Users\Public\evil.exe'; LocalBasePath = ''; LowerCaseLongPath = '' }
            ) | Export-Csv -Path (Join-Path $tmp 'analysis\parsed_records.csv') -NoTypeInformation -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
                Invoke-FotonAnalysis
                @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Parsed artifacts reference user-writable paths' }) |
                    Should -HaveCount 1
            }
            @(
                [PSCustomObject]@{ Identity = 'C:\Windows\System32\notepad.exe'; Path = 'C:\Windows\System32\notepad.exe'; LocalBasePath = ''; LowerCaseLongPath = '' }
            ) | Export-Csv -Path (Join-Path $tmp 'analysis\parsed_records.csv') -NoTypeInformation -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
                Invoke-FotonAnalysis
                @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Parsed artifacts reference user-writable paths' }) |
                    Should -HaveCount 0
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'bands Hayabusa hits by level and understands abbreviated level names' {
        $tmp = Join-Path $env:TEMP ('foton-haya-' + [guid]::NewGuid().ToString('N'))
        $hay = Join-Path $tmp 'analysis\external\hayabusa'
        New-Item -Path $hay -ItemType Directory -Force | Out-Null
        try {
            # Hayabusa abbreviates: crit/med, not critical/medium.
            $lines = @(
                '"Timestamp","RuleTitle","Level","Computer","Channel","EventID","RecordID","Details","ExtraFieldInfo","RuleID"'
                '"2026-01-01 00:00:00 +00:00","Nasty Rule","crit","H","Sec",1,1,"d, with comma","x","id1"'
                '"2026-01-01 00:00:01 +00:00","Dumping Hives","high","H","Sec",1,2,"d","x","id2"'
                '"2026-01-01 00:00:02 +00:00","Perms Changed","med","H","Sec",1,3,"d","x","id3"'
                '"2026-01-01 00:00:03 +00:00","Proc Exec","info","H","Sec",1,4,"d","x","id4"'
            )
            Set-Content -LiteralPath (Join-Path $hay 'hayabusa.csv') -Value $lines -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
                Invoke-FotonAnalysis

                $crit = @($script:FotonSession.Findings | Where-Object { $_.Title -like '*critical-level*' })
                $crit | Should -HaveCount 1
                $crit[0].Severity | Should -Be 'High'
                $crit[0].Observation | Should -Match 'Nasty Rule'

                $med = @($script:FotonSession.Findings | Where-Object { $_.Title -like '*medium-level*' })
                $med | Should -HaveCount 1
                $med[0].Severity | Should -Be 'Medium'

                @($script:FotonSession.Findings | Where-Object { $_.Title -like '*low and informational*' }) |
                    Should -HaveCount 1
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'ingests PECmd compose CSV: coverage and user-writable FilesLoaded' {
        $tmp = Join-Path $env:TEMP ('foton-pecmd-' + [guid]::NewGuid().ToString('N'))
        $dir = Join-Path $tmp 'analysis\external\PECmd'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        try {
            @(
                [PSCustomObject]@{
                    ExecutableName = 'NOTEPAD.EXE'
                    FilesLoaded    = 'C:\Windows\System32\notepad.exe, C:\Windows\System32\ntdll.dll'
                    Directories    = '\VOLUME\WINDOWS\SYSTEM32'
                    SourceFilename = 'C:\Windows\Prefetch\NOTEPAD.EXE-D8414F97.pf'
                }
                [PSCustomObject]@{
                    ExecutableName = 'EVIL.EXE'
                    FilesLoaded    = 'C:\Users\Public\evil.exe, C:\Windows\System32\ntdll.dll'
                    Directories    = '\VOLUME\USERS\PUBLIC'
                    SourceFilename = 'C:\Windows\Prefetch\EVIL.EXE-AAAAAAAA.pf'
                }
            ) | Export-Csv -Path (Join-Path $dir 'pecmd.csv') -NoTypeInformation -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
                Invoke-FotonAnalysis
                $cov = @($script:FotonSession.Findings |
                        Where-Object { $_.Title -eq 'PECmd Prefetch rows present in compose output' })
                $cov | Should -HaveCount 1
                $cov[0].Artifact | Should -Be 'analysis/external/PECmd'
                $cov[0].Observation | Should -Match 'PECmd'
                $w = @($script:FotonSession.Findings |
                        Where-Object { $_.Title -eq 'PECmd Prefetch references user-writable paths' })
                $w | Should -HaveCount 1
                $w[0].Severity | Should -Be 'Medium'
                $w[0].Observation | Should -Match 'Users\\Public\\evil.exe'
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'does not raise PECmd path findings for System32-only FilesLoaded' {
        $tmp = Join-Path $env:TEMP ('foton-pecmd-clean-' + [guid]::NewGuid().ToString('N'))
        $dir = Join-Path $tmp 'analysis\external\PECmd'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        try {
            @(
                [PSCustomObject]@{
                    ExecutableName = 'NOTEPAD.EXE'
                    FilesLoaded    = 'C:\Windows\System32\notepad.exe'
                    Directories    = '\VOLUME\WINDOWS\SYSTEM32'
                    SourceFilename = 'C:\Windows\Prefetch\NOTEPAD.EXE-D8414F97.pf'
                }
            ) | Export-Csv -Path (Join-Path $dir 'pecmd.csv') -NoTypeInformation -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
                Invoke-FotonAnalysis
                @($script:FotonSession.Findings |
                    Where-Object { $_.Title -eq 'PECmd Prefetch rows present in compose output' }) |
                    Should -HaveCount 1
                @($script:FotonSession.Findings |
                    Where-Object { $_.Title -eq 'PECmd Prefetch references user-writable paths' }) |
                    Should -HaveCount 0
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'ingests EvtxECmd compose CSV: coverage, EventId 1102, and ExecutableInfo paths' {
        $tmp = Join-Path $env:TEMP ('foton-evtxe-' + [guid]::NewGuid().ToString('N'))
        $dir = Join-Path $tmp 'analysis\external\EvtxECmd'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        try {
            @(
                [PSCustomObject]@{
                    EventId        = '4688'
                    Channel        = 'Security'
                    ExecutableInfo = 'C:\Windows\System32\cmd.exe'
                }
                [PSCustomObject]@{
                    EventId        = '1102'
                    Channel        = 'Security'
                    ExecutableInfo = ''
                }
                [PSCustomObject]@{
                    EventId        = '7045'
                    Channel        = 'System'
                    ExecutableInfo = 'C:\Users\Public\drop\svc.exe'
                }
            ) | Export-Csv -Path (Join-Path $dir 'evtxecmd.csv') -NoTypeInformation -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
                Invoke-FotonAnalysis
                @($script:FotonSession.Findings |
                    Where-Object { $_.Title -eq 'EvtxECmd event rows present in compose output' }) |
                    Should -HaveCount 1
                $cleared = @($script:FotonSession.Findings |
                        Where-Object { $_.Title -eq 'EvtxECmd: Security audit log cleared' })
                $cleared | Should -HaveCount 1
                $cleared[0].Severity | Should -Be 'High'
                $svc = @($script:FotonSession.Findings |
                        Where-Object { $_.Title -eq 'EvtxECmd: Service installed (System 7045)' })
                $svc | Should -HaveCount 1
                $w = @($script:FotonSession.Findings |
                        Where-Object { $_.Title -eq 'EvtxECmd ExecutableInfo references user-writable paths' })
                $w | Should -HaveCount 1
                $w[0].Observation | Should -Match 'Users\\Public\\drop\\svc.exe'
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'fires on baseline_diff service PathName and not on DisplayVersion' {
        $tmp = Join-Path $env:TEMP ('foton-diff-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path (Join-Path $tmp 'analysis') -ItemType Directory -Force | Out-Null
        try {
            @(
                [PSCustomObject]@{ RecordType = 'Service'; Identity = 'EvilSvc'; ChangeType = 'Modified'; Field = 'PathName' }
            ) | Export-Csv -Path (Join-Path $tmp 'analysis\baseline_diff.csv') -NoTypeInformation -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
                Invoke-FotonAnalysis
                $hit = @($script:FotonSession.Findings | Where-Object { $_.Title -like 'Baseline diff: service*' })
                $hit | Should -HaveCount 1
                $hit[0].WhyItMatters | Should -Match 'Patch Tuesday'
            }
            @(
                [PSCustomObject]@{ RecordType = 'InstalledSoftware'; Identity = 'App|Pub'; ChangeType = 'Modified'; Field = 'DisplayVersion' }
            ) | Export-Csv -Path (Join-Path $tmp 'analysis\baseline_diff.csv') -NoTypeInformation -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
                Invoke-FotonAnalysis
                @($script:FotonSession.Findings | Where-Object { $_.Title -like 'Baseline diff:*' }) |
                    Should -HaveCount 0
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'lifts High Winlogon and Root CA baseline_diff rows with provider FP notes' {
        $tmp = Join-Path $env:TEMP ('foton-diff-hi-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path (Join-Path $tmp 'analysis') -ItemType Directory -Force | Out-Null
        try {
            @(
                [PSCustomObject]@{ RecordType = 'Winlogon'; Identity = 'Userinit'; ChangeType = 'Modified'; Field = 'Value'; OldValue = 'userinit.exe'; NewValue = 'evil.exe' }
                [PSCustomObject]@{ RecordType = 'Certificate'; Identity = 'Cert:\LocalMachine\Root|AABB'; ChangeType = 'Added'; Field = ''; OldValue = ''; NewValue = '' }
                [PSCustomObject]@{ RecordType = 'InstalledSoftware'; Identity = 'App|Pub'; ChangeType = 'Modified'; Field = 'DisplayVersion'; OldValue = '1'; NewValue = '2' }
            ) | Export-Csv -Path (Join-Path $tmp 'analysis\baseline_diff.csv') -NoTypeInformation -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
                Invoke-FotonAnalysis
                $wl = @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Baseline diff: Modified Winlogon.Value' })
                $wl | Should -HaveCount 1
                $wl[0].Severity | Should -Be 'High'
                $wl[0].WhyItMatters | Should -Match 'EDR|MFA|Userinit'
                $ca = @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Baseline diff: Added Certificate' })
                $ca | Should -HaveCount 1
                $ca[0].WhyItMatters | Should -Match 'Root|Enterprise'
                @($script:FotonSession.Findings | Where-Object { $_.Title -like 'Baseline diff:*InstalledSoftware*' }) |
                    Should -HaveCount 0
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'does not claim enabled firewall profiles are disabled' {
        InModuleScope Foton {
            Initialize-FotonSession
            $script:FotonSession.Data['firewall_profiles'] = @(
                [PSCustomObject]@{ Name = 'Domain'; Enabled = $true }
                [PSCustomObject]@{ Name = 'Private'; Enabled = $true }
                [PSCustomObject]@{ Name = 'Public'; Enabled = $true }
            )
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'One or more firewall profiles are disabled' }) |
                Should -HaveCount 0
        }
    }

    It 'flags a disabled firewall profile' {
        InModuleScope Foton {
            Initialize-FotonSession
            $script:FotonSession.Data['firewall_profiles'] = @(
                [PSCustomObject]@{ Name = 'Public'; Enabled = $false }
            )
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'One or more firewall profiles are disabled' }) |
                Should -HaveCount 1
        }
    }

    It 'does not claim Sysmon is missing when the log is present and enabled' {
        InModuleScope Foton {
            Initialize-FotonSession
            $script:FotonSession.Data['event_log_configuration'] = @(
                [PSCustomObject]@{ LogName = 'Microsoft-Windows-Sysmon/Operational'; IsEnabled = $true; RecordCount = 100 }
            )
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Sysmon is not installed on this host' }) |
                Should -HaveCount 0
        }
    }

    It 'reports Sysmon missing only for NotPresent rows' {
        InModuleScope Foton {
            Initialize-FotonSession
            $script:FotonSession.Data['event_log_configuration'] = @(
                [PSCustomObject]@{ LogName = 'Microsoft-Windows-Sysmon/Operational'; IsEnabled = 'NotPresent'; RecordCount = 0 }
            )
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Sysmon is not installed on this host' }) |
                Should -HaveCount 1
        }
    }

    It 'treats unreadable Defender exclusion placeholders as a visibility gap' {
        InModuleScope Foton {
            Initialize-FotonSession
            $script:FotonSession.Data['defender_preferences_and_exclusions'] = [PSCustomObject]@{
                ExclusionPath    = @('N/A: Administrators are not allowed to view exclusions')
                ExclusionProcess = @('N/A: Administrators are not allowed to view exclusions')
            }
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Defender exclusions are configured' }) |
                Should -HaveCount 0
            @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Defender exclusion lists could not be read' }) |
                Should -HaveCount 1
        }
    }

    It 'flags scheduled tasks whose Actions point at user-writable paths even when UserWritableTarget is false' {
        InModuleScope Foton {
            Initialize-FotonSession
            $script:FotonSession.Data['scheduled_tasks'] = @(
                [PSCustomObject]@{
                    TaskPath = '\'; TaskName = 'LocalAdmin-Creation-CDW'
                    RunAsUser = 'NT AUTHORITY\System'; Actions = 'powershell.exe -File C:\Temp\Invoke-LocalAdmin-Creation-cdw\LocalAdmin-Creation-cdw.ps1'
                    UserWritableTarget = $false; SuspiciousHits = ''
                }
            )
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            $hit = @($script:FotonSession.Findings |
                    Where-Object { $_.Title -eq 'Scheduled tasks reference user-writable paths or risky commands' })
            $hit | Should -HaveCount 1
            $hit[0].Observation | Should -Match 'LocalAdmin-Creation-CDW'
        }
    }

    It 'excludes collector-window PowerShell operational events from high-risk script block findings' {
        $tmp = Join-Path $env:TEMP ('foton-pswin-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path (Join-Path $tmp '00_Collection') -ItemType Directory -Force | Out-Null
        try {
            @(
                '2026-01-15 12:00:00 UTC  start'
                '2026-01-15 12:05:00 UTC  end'
            ) | Set-Content -LiteralPath (Join-Path $tmp '00_Collection\collection.log') -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['powershell_operational'] = @(
                    [PSCustomObject]@{
                        TimeCreatedUtc = '2026-01-15 12:02:00'
                        Message        = 'powershell -encodedcommand ABC'
                    }
                    [PSCustomObject]@{
                        TimeCreatedUtc = '2026-01-14 10:00:00'
                        Message        = 'powershell -encodedcommand DEF'
                    }
                )
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
                Invoke-FotonAnalysis
                $hit = @($script:FotonSession.Findings |
                        Where-Object { $_.Title -eq 'PowerShell script block logs contain high-risk content' })
                $hit | Should -HaveCount 1
                $hit[0].Observation | Should -Match '^1 event'
                $hit[0].Observation | Should -Match 'Excludes 1'
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'excludes per-user service instances and non-command events from EvtxECmd counts' {
        $tmp = Join-Path $env:TEMP ('foton-evtxe2-' + [guid]::NewGuid().ToString('N'))
        $dir = Join-Path $tmp 'analysis\external\EvtxECmd'
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $tmp '00_Collection') -ItemType Directory -Force | Out-Null
        @(
            'Foton 1.35.0 collection log'
            '2026-10-29 15:10:29 UTC  [Good] Case folder: X'
            '2026-10-29 15:27:45 UTC  [Step] Compressing case package'
        ) | Set-Content -LiteralPath (Join-Path $tmp '00_Collection\collection.log')
        try {
            @(
                [PSCustomObject]@{ EventId = '4697'; TimeCreated = '2026-10-28 17:00:00.0000000'; PayloadData1 = 'ServiceName: OneSyncSvc_1701f8'; PayloadData2 = 'ServiceFileName: C:\Windows\system32\svchost.exe -k UnistackSvcGroup'; ExecutableInfo = '' }
                [PSCustomObject]@{ EventId = '4697'; TimeCreated = '2026-10-28 17:00:01.0000000'; PayloadData1 = 'ServiceName: CDPUserSvc_2a8824'; PayloadData2 = 'ServiceFileName: %SystemRoot%\system32\svchost.exe -k UnistackSvcGroup'; ExecutableInfo = '' }
                [PSCustomObject]@{ EventId = '4697'; TimeCreated = '2026-10-28 17:00:02.0000000'; PayloadData1 = 'ServiceName: CDPUserSvc_99aa11'; PayloadData2 = 'ServiceFileName: C:\ProgramData\cdp.exe'; ExecutableInfo = '' }
                [PSCustomObject]@{ EventId = '4697'; TimeCreated = '2026-10-28 17:04:16.0000000'; PayloadData1 = 'ServiceName: VendorUpdateSvc'; PayloadData2 = 'ServiceFileName: C:\Program Files\Vendor\upd.exe'; ExecutableInfo = '' }
                [PSCustomObject]@{ EventId = '4673'; TimeCreated = '2026-10-28 18:00:00.0000000'; PayloadData1 = ''; PayloadData2 = ''; ExecutableInfo = 'C:\Windows\System32\lsass.exe (PID: 0x654)' }
                [PSCustomObject]@{ EventId = '4688'; TimeCreated = '2026-10-28 18:00:01.0000000'; PayloadData1 = ''; PayloadData2 = ''; ExecutableInfo = 'C:\Windows\System32\rundll32.exe comsvcs.dll MiniDump 654 C:\Users\Public\l.dmp full lsass' }
                [PSCustomObject]@{ EventId = '4688'; TimeCreated = '2026-10-29 15:12:00.0000000'; PayloadData1 = ''; PayloadData2 = ''; ExecutableInfo = 'C:\Users\u\Desktop\Foton_HOST_20261029-151029Z\x.exe' }
            ) | Export-Csv -Path (Join-Path $dir 'evtxecmd.csv') -NoTypeInformation -Encoding UTF8
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
                Invoke-FotonAnalysis
                $susp = @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'EvtxECmd ExecutableInfo matched suspicious-command patterns' })
                $susp | Should -HaveCount 1
                # Only the 4688 row counts; the 4673 row whose image is lsass.exe does not.
                $susp[0].Observation | Should -Match 'matched 1 distinct'
                $susp[0].Observation | Should -Not -Match '\(2\)'
                $svc = @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'EvtxECmd: Service installed (Security 4697)' })
                $svc | Should -HaveCount 1
                $svc[0].Observation | Should -Match 'reported 2 EventId 4697'
                $svc[0].Observation | Should -Match 'VendorUpdateSvc'
                # Template name, but not hosted by svchost.exe: counted, not filtered.
                $svc[0].Observation | Should -Match 'CDPUserSvc_99aa11'
                $svc[0].Observation | Should -Match 'Excludes 2 per-user service instance\(s\) of known Windows templates'
                $self = @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'EvtxECmd rows inside the collection window were excluded' })
                $self | Should -HaveCount 1
                $self[0].Observation | Should -Match '^1 EvtxECmd row'
                $w = @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'EvtxECmd ExecutableInfo references user-writable paths' })
                $w | Should -HaveCount 1
                $w[0].Observation | Should -Not -Match 'Foton_HOST'
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'separates transient create/delete accounts from persistent ones and ignores default-group adds' {
        InModuleScope Foton {
            Initialize-FotonSession
            $sidT = 'S-1-5-21-1-2-3-1014'
            $sidP = 'S-1-5-21-1-2-3-1020'
            $script:FotonSession.Data['security_account_management'] = @(
                [PSCustomObject]@{ TimeCreatedUtc = '2026-10-28 20:34:54'; EventId = 4720; Message = "A user account was created. Subject: Security ID: S-1-5-18 New Account: Security ID: $sidT Account Name: tempadmin Account Domain: HOST" }
                [PSCustomObject]@{ TimeCreatedUtc = '2026-10-28 20:34:54'; EventId = 4728; Message = "A member was added to a security-enabled global group. Member: Security ID: $sidT Account Name: - Group: Security ID: S-1-5-21-1-2-3-513 Group Name: None Group Domain: HOST" }
                [PSCustomObject]@{ TimeCreatedUtc = '2026-10-28 20:34:55'; EventId = 4726; Message = "A user account was deleted. Target Account: Security ID: $sidT Account Name: tempadmin Account Domain: HOST" }
            )
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Accounts created or privileged groups changed in the exported logs' }) | Should -HaveCount 0
            $t = @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Accounts created and deleted within a minute' })
            $t | Should -HaveCount 1
            $t[0].Observation | Should -Match 'tempadmin'

            Initialize-FotonSession
            $script:FotonSession.Data['security_account_management'] = @(
                [PSCustomObject]@{ TimeCreatedUtc = '2026-10-28 21:00:00'; EventId = 4720; Message = "A user account was created. New Account: Security ID: $sidP Account Name: support Account Domain: HOST" }
                [PSCustomObject]@{ TimeCreatedUtc = '2026-10-28 21:00:01'; EventId = 4732; Message = "A member was added to a security-enabled local group. Member: Security ID: $sidP Account Name: - Group: Security ID: S-1-5-32-544 Group Name: Administrators Group Domain: Builtin" }
            )
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            $p = @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Accounts created or privileged groups changed in the exported logs' })
            $p | Should -HaveCount 1
            $p[0].Observation | Should -Match 'support'
            $p[0].Observation | Should -Match 'Administrators'
            @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Accounts created and deleted within a minute' }) | Should -HaveCount 0
        }
    }

    It 'filters only known per-user service templates, not any Name_<hex> service' {
        InModuleScope Foton {
            Test-FotonPerUserServiceName -Name 'OneSyncSvc_1701f8' | Should -Be $true
            Test-FotonPerUserServiceName -Name 'webthreatdefusersvc_2a8824' | Should -Be $true
            Test-FotonPerUserServiceName -Name 'Updater_1a2b3c' | Should -Be $false
            Test-FotonPerUserServiceName -Name 'OneSyncSvc' | Should -Be $false
        }
    }

    It 'filters a per-user service event only when svchost.exe hosts it' {
        InModuleScope Foton {
            $native = 'A service was installed in the system. Service Name:  WpnUserService_1701f8 Service File Name:  C:\WINDOWS\system32\svchost.exe -k UnistackSvcGroup Service Type:  user mode service'
            Test-FotonPerUserServiceEvent -Row ([PSCustomObject]@{ Message = $native }) | Should -Be $true
            Test-FotonPerUserServiceEvent -Row ([PSCustomObject]@{ PayloadData1 = 'Name: OneSyncSvc_1701f8'; ExecutableInfo = 'C:\Windows\system32\svchost.exe -k UnistackSvcGroup' }) | Should -Be $true
            Test-FotonPerUserServiceEvent -Row ([PSCustomObject]@{ Message = 'Service Name:  WpnUserService_1701f8 Service File Name:  C:\Users\Public\svchost.exe' }) | Should -Be $false
            Test-FotonPerUserServiceEvent -Row ([PSCustomObject]@{ PayloadData1 = 'Name: OneSyncSvc_1701f8' }) | Should -Be $false
            Test-FotonPerUserServiceEvent -Row ([PSCustomObject]@{ PayloadData1 = 'Name: Updater_1a2b3c'; ExecutableInfo = 'C:\Windows\system32\svchost.exe -k netsvcs' }) | Should -Be $false
        }
    }

    It 'reads account and group names that contain spaces' {
        InModuleScope Foton {
            $rows = @(
                [PSCustomObject]@{ TimeCreatedUtc = '2026-10-28 21:00:00'; EventId = 4720; Message = "A user account was created.`r`nNew Account:`r`n`tSecurity ID:`t`tCORP\John Smith`r`n`tAccount Name:`t`tJohn Smith`r`n`tAccount Domain:`t`tCORP" }
                [PSCustomObject]@{ TimeCreatedUtc = '2026-10-28 21:00:01'; EventId = 4732; Message = "Member:`r`n`tSecurity ID:`t`tCORP\John Smith`r`n`tAccount Name:`t`t-`r`nGroup:`r`n`tSecurity ID:`t`tBUILTIN\Remote Desktop Users`r`n`tGroup Name:`t`tRemote Desktop Users`r`n`tGroup Domain:`t`tBuiltin" }
            )
            $facts = @(Get-FotonAccountEventFacts -Rows $rows)
            $facts[0].AccountSid | Should -Be 'CORP\John Smith'
            $facts[0].AccountName | Should -Be 'John Smith'
            $facts[1].AccountSid | Should -Be 'CORP\John Smith'
            $facts[1].GroupSid | Should -Be 'BUILTIN\Remote Desktop Users'
            $facts[1].GroupName | Should -Be 'Remote Desktop Users'
            Test-FotonPrivilegedGroupSid -Sid $facts[1].GroupSid -Name $facts[1].GroupName | Should -Be $true
        }
    }

    It 'pairs transient accounts when event times are typed DateTime values' {
        InModuleScope Foton {
            $t0 = [datetime]::SpecifyKind([datetime]'2026-10-28 20:34:54', [DateTimeKind]::Local)
            $sid = 'S-1-5-21-1-2-3-1014'
            $facts = @(Get-FotonAccountEventFacts -Rows @(
                    [PSCustomObject]@{ TimeCreated = $t0; EventId = 4720; Message = "New Account: Security ID: $sid Account Name: tempadmin Account Domain: HOST" }
                    [PSCustomObject]@{ TimeCreated = $t0.AddSeconds(1); EventId = 4726; Message = "Target Account: Security ID: $sid Account Name: tempadmin Account Domain: HOST" }
                ))
            $facts[0].TimeUtc | Should -Not -BeNullOrEmpty
            $facts[0].TimeUtc.Kind | Should -Be 'Utc'
            (Get-FotonAccountChangeSummary -Facts $facts).Transient | Should -HaveCount 1
        }
    }

    It 'discloses earlier Foton packages that profile scans skipped' {
        InModuleScope Foton {
            Initialize-FotonSession
            $script:FotonSession.Data['collection_coverage'] = [PSCustomObject]@{ Elevated = $true; ExcludedEarlierPackages = @('C:\Users\u\Desktop\Foton_HOST_20260101-000000Z') }
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            $f = @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Earlier Foton package folders were skipped by profile scans' })
            $f | Should -HaveCount 1
            $f[0].Observation | Should -Match 'Foton_HOST_20260101-000000Z'

            Initialize-FotonSession
            $script:FotonSession.Data['collection_coverage'] = [PSCustomObject]@{ Elevated = $true; ExcludedEarlierPackages = @() }
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Earlier Foton package folders were skipped by profile scans' }) | Should -HaveCount 0
        }
    }

    It 'reads the service name, not the subject account, from a native 4697 message' {
        InModuleScope Foton {
            $row = [PSCustomObject]@{ EventId = 4697; Message = 'A service was installed in the system. Subject: Security ID: S-1-5-18 Account Name: HOST$ Account Domain: CORP Logon ID: 0x3E7 Service Information: Service Name: Contoso Agent Service File Name: C:\Program Files\Contoso\agent.exe Service Type: 0x10' }
            Get-FotonServiceNameFromEvent -Row $row | Should -Be 'Contoso Agent'
            Get-FotonServiceNameFromEvent -Row ([PSCustomObject]@{ PayloadData1 = 'Name: TmKmSnsr' }) | Should -Be 'TmKmSnsr'
            Get-FotonServiceNameFromEvent -Row ([PSCustomObject]@{ PayloadData1 = 'ServiceName: OneSyncSvc_1701f8' }) | Should -Be 'OneSyncSvc_1701f8'
        }
    }

    It 'treats an Administrators add as privileged when the message shows a resolved name' {
        InModuleScope Foton {
            Initialize-FotonSession
            $script:FotonSession.Data['security_account_management'] = @(
                [PSCustomObject]@{ TimeCreatedUtc = '2026-10-28 21:00:01'; EventId = 4732; Message = 'A member was added to a security-enabled local group. Member: Security ID: CORP\jdoe Account Name: - Group: Security ID: BUILTIN\Administrators Group Name: Administrators Group Domain: Builtin' }
            )
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            $p = @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Accounts created or privileged groups changed in the exported logs' })
            $p | Should -HaveCount 1
            $p[0].Observation | Should -Match '1 addition\(s\) to privileged groups'
            $p[0].Observation | Should -Match 'Administrators'
        }
    }

    It 'names native 7045 services and skips per-user instances' {
        InModuleScope Foton {
            Initialize-FotonSession
            $script:FotonSession.Data['system_service_and_driver'] = @(
                [PSCustomObject]@{ TimeCreatedUtc = '2026-10-28 17:27:20'; EventId = 7045; Message = 'A service was installed in the system. Service Name:  Contoso Agent Service File Name:  C:\Program Files\Contoso\agent.exe' }
            )
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            $f = @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Service install events in the exported logs' })
            $f | Should -HaveCount 1
            $f[0].Observation | Should -Match 'Contoso Agent'

            Initialize-FotonSession
            $script:FotonSession.Data['system_service_and_driver'] = @(
                [PSCustomObject]@{ TimeCreatedUtc = '2026-10-28 17:27:20'; EventId = 7045; Message = 'A service was installed in the system. Service Name:  WpnUserService_1701f8 Service File Name:  C:\Windows\system32\svchost.exe' }
            )
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Service install events in the exported logs' }) | Should -HaveCount 0

            Initialize-FotonSession
            $script:FotonSession.Data['system_service_and_driver'] = @(
                [PSCustomObject]@{ TimeCreatedUtc = '2026-10-28 17:27:20'; EventId = 7045; Message = 'A service was installed in the system. Service Name:  WpnUserService_1701f8 Service File Name:  C:\Windows\system32\svchost.exe' }
                [PSCustomObject]@{ TimeCreatedUtc = '2026-10-28 17:27:21'; EventId = 7045; Message = 'A service was installed in the system. Service Name:  Contoso Agent Service File Name:  C:\Program Files\Contoso\agent.exe' }
            )
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            $f = @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Service install events in the exported logs' })
            $f | Should -HaveCount 1
            $f[0].Observation | Should -Match '^1 service install'
            $f[0].Observation | Should -Match 'Excludes 1 per-user service instance'
        }
    }

    It 'flags an automatic Sysmon service that is stopped, not one that is running' {
        InModuleScope Foton {
            Initialize-FotonSession
            $script:FotonSession.Data['services'] = @([PSCustomObject]@{ Name = 'Sysmon64'; State = 'Stopped'; StartMode = 'Auto' })
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Sysmon is installed but not running' }) | Should -HaveCount 1

            Initialize-FotonSession
            $script:FotonSession.Data['services'] = @([PSCustomObject]@{ Name = 'Sysmon64'; State = 'Running'; StartMode = 'Auto' })
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Sysmon is installed but not running' }) | Should -HaveCount 0
        }
    }

    It 'reports Partial/Failed collection tasks and stays quiet when all succeeded' {
        InModuleScope Foton {
            Initialize-FotonSession
            $null = $script:FotonSession.Manifest.Add([PSCustomObject]@{ Task = 'registry_hives_machine'; Status = 'Failed' })
            $null = $script:FotonSession.Manifest.Add([PSCustomObject]@{ Task = 'prefetch_files'; Status = 'Success' })
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            $f = @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Some collection tasks captured only part of their files' })
            $f | Should -HaveCount 1
            $f[0].Observation | Should -Match 'registry_hives_machine \(Failed\)'

            Initialize-FotonSession
            $null = $script:FotonSession.Manifest.Add([PSCustomObject]@{ Task = 'prefetch_files'; Status = 'Success' })
            $script:FotonSession.Data['security_process_creation'] = @([PSCustomObject]@{ EventId = 4688 })
            Invoke-FotonAnalysis
            @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Some collection tasks captured only part of their files' }) | Should -HaveCount 0
        }
    }

    It 'writes HTML using package hostname not the analyst workstation' {
        Get-FotonPackage -Path $script:Fixture | Out-Null
        Invoke-FotonAnalysis
        $htmlPath = Join-Path $env:TEMP ('foton-report-' + [guid]::NewGuid().ToString('N') + '.html')
        try {
            New-FotonReport -Path $htmlPath
            $html = Get-Content -LiteralPath $htmlPath -Raw
            $html | Should -Match 'FIXTURE-PC'
            $html | Should -Not -Match '<script src="https://'
            $html | Should -Match 'What was observed'
            $html | Should -Match 'class="mark"'
            $html | Should -Match 'id="foton-q"'
            $html | Should -Match 'id="foton-toc"'
            $html | Should -Match '(?s)<style>.*\.foton-bar'
            $html | Should -Not -Match '</style>\s*\.foton-bar'
        }
        finally {
            Remove-Item -LiteralPath $htmlPath -Force -ErrorAction SilentlyContinue
        }
    }

    AfterAll {
        $analysisDir = Join-Path $script:Fixture 'analysis'
        if (Test-Path -LiteralPath $analysisDir) {
            Remove-Item -LiteralPath $analysisDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        $rpt = Join-Path $script:Fixture 'Foton_Report.html'
        if (Test-Path -LiteralPath $rpt) {
            Remove-Item -LiteralPath $rpt -Force -ErrorAction SilentlyContinue
        }
    }
}
