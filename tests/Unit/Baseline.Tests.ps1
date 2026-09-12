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
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'NetworkShare'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'SystemBinary'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'HostsEntry'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'Winlogon'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'StartupApproved'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'UserAutorun'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'DefenderPreference'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'RemoteAccessConfig'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'LsaPackage'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'PrintMonitor'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'BitsJob'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'CmdAutoRun'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'SessionManager'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'KnownDll'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'ProxyConfig'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'WinsockLsp'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'ActiveSetup'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'SilentProcessExit'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'NetshHelper'
            @($script:FotonBaselineProviders | ForEach-Object RecordType) |
                Should -Contain 'TimeProvider'
        }
    }

    It 'does not reset StartTimeUtc when the hardening provider loads checks' {
        InModuleScope Foton {
            Initialize-FotonSession
            $stamp = [datetime]::UtcNow
            $script:FotonSession.StartTimeUtc = $stamp
            $script:FotonSession.HardeningRegistryChecks = @()
            $prov = @($script:FotonBaselineProviders | Where-Object { $_.RecordType -eq 'HardeningRegistry' })[0]
            & $prov.Collect | Out-Null
            $script:FotonSession.StartTimeUtc | Should -Be $stamp
            @($script:FotonSession.HardeningRegistryChecks).Count | Should -BeGreaterThan 0
        }
    }

    It 'captures RemoteAccessConfig settings with a Setting identity' {
        InModuleScope Foton {
            $prov = @($script:FotonBaselineProviders | Where-Object { $_.RecordType -eq 'RemoteAccessConfig' })[0]
            $rows = @(& $prov.Collect)
            $names = @($rows | ForEach-Object { $_.Setting })
            $names | Should -Contain 'RdpNla'
            $names | Should -Contain 'Smb1LanmanServer'
            $names | Should -Contain 'WinRmPolicyAllowBasic'
            @($rows | Where-Object { $_.Setting -eq 'RdpNla' }).Count | Should -Be 1
        }
    }

    It 'splits LSA MULTI_SZ into Kind and Package rows' {
        InModuleScope Foton {
            $prov = @($script:FotonBaselineProviders | Where-Object { $_.RecordType -eq 'LsaPackage' })[0]
            $rows = @(& $prov.Collect)
            $kinds = @($rows | ForEach-Object { $_.Kind })
            $kinds | Should -Contain 'Security Packages'
            $blob = (@($rows | ForEach-Object { $_.Package }) -join ' ').ToLowerInvariant()
            $blob | Should -Match 'msv1_0|kerberos|schannel'
        }
    }

    It 'enumerates print monitor subkeys with a Driver field' {
        InModuleScope Foton {
            $prov = @($script:FotonBaselineProviders | Where-Object { $_.RecordType -eq 'PrintMonitor' })[0]
            $rows = @(& $prov.Collect)
            $rows.Count | Should -BeGreaterThan 0
            $rows[0].PSObject.Properties.Name | Should -Contain 'Name'
            $rows[0].PSObject.Properties.Name | Should -Contain 'Driver'
        }
    }

    It 'defines BitsJob as JobId with no byte-count fields' {
        InModuleScope Foton {
            $prov = @($script:FotonBaselineProviders | Where-Object { $_.RecordType -eq 'BitsJob' })[0]
            $prov.IdentityFields | Should -Contain 'JobId'
            $prov.ComparedFields | Should -Contain 'NotifyCmdLine'
            $prov.ComparedFields | Should -Not -Contain 'BytesTransferred'
            $prov.ComparedFields | Should -Not -Contain 'JobState'
            $rows = @(& $prov.Collect)
            foreach ($r in $rows) {
                $r.PSObject.Properties.Name | Should -Not -Contain 'BytesTransferred'
            }
        }
    }

    It 'captures HKLM Command Processor AutoRun as CmdAutoRun' {
        InModuleScope Foton {
            $prov = @($script:FotonBaselineProviders | Where-Object { $_.RecordType -eq 'CmdAutoRun' })[0]
            $prov.IdentityFields | Should -Contain 'Hive'
            $prov.IdentityFields | Should -Contain 'Key'
            $rows = @(& $prov.Collect)
            $hlm = @($rows | Where-Object { $_.Hive -eq 'HKLM' })
            $hlm.Count | Should -BeGreaterThan 0
            $hlm[0].Key | Should -Match 'Command Processor'
            $hlm[0].PSObject.Properties.Name | Should -Contain 'Command'
        }
    }

    It 'captures SessionManager BootExecute and omits PendingFileRenameOperations' {
        InModuleScope Foton {
            $prov = @($script:FotonBaselineProviders | Where-Object { $_.RecordType -eq 'SessionManager' })[0]
            $prov.IdentityFields | Should -Contain 'Kind'
            $prov.IdentityFields | Should -Contain 'Name'
            $rows = @(& $prov.Collect)
            $boot = @($rows | Where-Object { $_.Kind -eq 'SessionValue' -and $_.Name -eq 'BootExecute' })
            $boot.Count | Should -Be 1
            $boot[0].Value | Should -Match 'autocheck|autochk|\(not set\)'
            @($rows | Where-Object { $_.Name -eq 'PendingFileRenameOperations' }).Count | Should -Be 0
        }
    }

    It 'captures KnownDll mapped files from Session Manager' {
        InModuleScope Foton {
            $prov = @($script:FotonBaselineProviders | Where-Object { $_.RecordType -eq 'KnownDll' })[0]
            $prov.IdentityFields | Should -Contain 'Name'
            $rows = @(& $prov.Collect)
            $rows.Count | Should -BeGreaterThan 0
            $names = @($rows | ForEach-Object { $_.Name })
            ($names -join ' ') | Should -Match 'ntdll|kernel32|DllDirectory'
            $rows[0].PSObject.Properties.Name | Should -Contain 'MappedFile'
        }
    }

    It 'captures ProxyConfig machine settings and not DefaultConnectionSettings' {
        InModuleScope Foton {
            $prov = @($script:FotonBaselineProviders | Where-Object { $_.RecordType -eq 'ProxyConfig' })[0]
            $prov.IdentityFields | Should -Contain 'Scope'
            $prov.IdentityFields | Should -Contain 'Setting'
            $rows = @(& $prov.Collect)
            $machine = @($rows | Where-Object { $_.Scope -eq 'Machine' } | ForEach-Object Setting)
            $machine | Should -Contain 'ProxyEnable'
            $machine | Should -Contain 'AutoConfigURL'
            @($rows | Where-Object { $_.Scope -eq 'WinHttp' -and $_.Setting -eq 'WinHttpSettings' }).Count | Should -Be 1
            @($rows | Where-Object { $_.Setting -eq 'DefaultConnectionSettings' }).Count | Should -Be 0
        }
    }

    It 'captures WinsockLsp catalog entries with a LibraryPath' {
        InModuleScope Foton {
            $prov = @($script:FotonBaselineProviders | Where-Object { $_.RecordType -eq 'WinsockLsp' })[0]
            $prov.IdentityFields | Should -Contain 'Kind'
            $prov.IdentityFields | Should -Contain 'Entry'
            $rows = @(& $prov.Collect)
            $rows.Count | Should -BeGreaterThan 0
            $rows[0].PSObject.Properties.Name | Should -Contain 'LibraryPath'
            $proto = @($rows | Where-Object { $_.Kind -eq 'Protocol' } | Select-Object -First 1)
            if ($proto) {
                $proto.LibraryPath | Should -Match '\.dll|\(not set\)'
                $proto.LibraryPath | Should -Not -Match '[\u4e00-\u9fff]'
            }
        }
    }

    It 'captures ActiveSetup HKLM GUIDs with StubPath' {
        InModuleScope Foton {
            $prov = @($script:FotonBaselineProviders | Where-Object { $_.RecordType -eq 'ActiveSetup' })[0]
            $prov.IdentityFields | Should -Contain 'Guid'
            $rows = @(& $prov.Collect)
            $rows.Count | Should -BeGreaterThan 0
            $rows[0].PSObject.Properties.Name | Should -Contain 'StubPath'
            $rows[0].Key | Should -Match 'Active Setup'
        }
    }

    It 'defines SilentProcessExit as ImageName with MonitorProcess' {
        InModuleScope Foton {
            $prov = @($script:FotonBaselineProviders | Where-Object { $_.RecordType -eq 'SilentProcessExit' })[0]
            $prov.IdentityFields | Should -Contain 'ImageName'
            $prov.ComparedFields | Should -Contain 'MonitorProcess'
            $rows = @(& $prov.Collect)
            if ($rows.Count -gt 0) {
                $rows[0].PSObject.Properties.Name | Should -Contain 'MonitorProcess'
                $rows[0].PSObject.Properties.Name | Should -Not -Contain 'IfeoGlobalFlag'
            }
        }
    }

    It 'captures NetshHelper DLL map from HKLM NetSh' {
        InModuleScope Foton {
            $prov = @($script:FotonBaselineProviders | Where-Object { $_.RecordType -eq 'NetshHelper' })[0]
            $prov.IdentityFields | Should -Contain 'Name'
            $rows = @(& $prov.Collect)
            $rows.Count | Should -BeGreaterThan 0
            $rows[0].PSObject.Properties.Name | Should -Contain 'Dll'
            $rows[0].Key | Should -Match 'NetSh'
        }
    }

    It 'captures TimeProvider NtpClient without NTP peer lists' {
        InModuleScope Foton {
            $prov = @($script:FotonBaselineProviders | Where-Object { $_.RecordType -eq 'TimeProvider' })[0]
            $prov.IdentityFields | Should -Contain 'Name'
            $rows = @(& $prov.Collect)
            $names = @($rows | ForEach-Object { $_.Name })
            $names | Should -Contain 'NtpClient'
            $rows[0].PSObject.Properties.Name | Should -Contain 'DllName'
            $rows[0].PSObject.Properties.Name | Should -Not -Contain 'NtpServer'
        }
    }

    It 'defines WdacApplockerPolicy as Kind+Name with PolicyHash' {
        InModuleScope Foton {
            $prov = @($script:FotonBaselineProviders | Where-Object { $_.RecordType -eq 'WdacApplockerPolicy' })[0]
            $prov.IdentityFields | Should -Contain 'Kind'
            $prov.IdentityFields | Should -Contain 'Name'
            $prov.ComparedFields | Should -Contain 'PolicyHash'
            $rows = @(& $prov.Collect)
            $rows.Count | Should -BeGreaterThan 0
            $kinds = @($rows | ForEach-Object { $_.Kind })
            $kinds | Should -Contain 'Wdac'
            $kinds | Should -Contain 'AppLocker'
        }
    }

    It 'diffs field-level changes and fires High on service PathName and new admin' {
        $changes = Compare-FotonBaseline -ReferencePath $script:Ref -DifferencePath $script:Dif -NoHtml -NoCsv
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
        Compare-FotonBaseline -ReferencePath $script:Ref -DifferencePath $script:Dif -NoHtml -NoCsv | Out-Null
        InModuleScope Foton {
            @($script:FotonSession.Findings | Where-Object { $_.Title -eq 'Modified InstalledSoftware' -and $_.Severity -eq 'Info' }) |
                Should -Not -BeNullOrEmpty
        }
    }

    It 'writes baseline_diff.csv and cites provider false positives on High findings' {
        $tmp = Join-Path $env:TEMP ('foton-cmp-csv-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $tmp -ItemType Directory -Force | Out-Null
        $ref = Join-Path $tmp 'ref.json'
        $dif = Join-Path $tmp 'dif.json'
        try {
            Copy-Item -LiteralPath $script:Ref -Destination $ref -Force
            Copy-Item -LiteralPath $script:Dif -Destination $dif -Force
            Compare-FotonBaseline -ReferencePath $ref -DifferencePath $dif -NoHtml | Out-Null
            $csv = Join-Path $tmp 'baseline_diff.csv'
            Test-Path -LiteralPath $csv | Should -Be $true
            $rows = @(Import-Csv -LiteralPath $csv)
            $rows.Count | Should -BeGreaterThan 0
            $rows[0].PSObject.Properties.Name | Should -Contain 'RecordType'
            InModuleScope Foton {
                $svc = @($script:FotonSession.Findings |
                        Where-Object { $_.Title -eq 'Modified Service' -and $_.Severity -eq 'High' })
                $svc | Should -Not -BeNullOrEmpty
                $svc[0].WhyItMatters | Should -Match 'Patch Tuesday'
                $svc[0].WhyItMatters | Should -Match 'Temporal|Fleet'
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
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

Describe 'New-FotonBaselineReport' {
    It 'renders a fixture snapshot without network script tags' {
        $htmlPath = Join-Path $env:TEMP ('foton-base-html-' + [guid]::NewGuid().ToString('N') + '.html')
        try {
            $out = New-FotonBaselineReport -Path $script:Ref -OutputPath $htmlPath
            $out | Should -Be $htmlPath
            $html = Get-Content -LiteralPath $htmlPath -Raw
            $html | Should -Match 'PC1'
            $html | Should -Match 'Spooler'
            $html | Should -Match 'class="mark"'
            $html | Should -Match 'Baseline snapshot'
            $html | Should -Match 'id="foton-q"'
            $html | Should -Match 'id="foton-toc"'
            $html | Should -Match '(?s)<style>.*\.foton-bar'
            $html | Should -Not -Match '</style>\s*\.foton-bar'
            $html | Should -Not -Match '<script src="https://'
        }
        finally {
            Remove-Item -LiteralPath $htmlPath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'opens baseline.json inside a package folder' {
        $dir = Join-Path $env:TEMP ('foton-base-pkg-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $dir -ItemType Directory | Out-Null
        Copy-Item -LiteralPath $script:Ref -Destination (Join-Path $dir 'baseline.json')
        try {
            Compare-FotonBaseline -ReferencePath $dir -DifferencePath $script:Dif -NoHtml -NoCsv | Out-Null
        }
        finally {
            Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'New-FotonBaselineCompareReport' {
    It 'renders Added/Removed/Modified without network script tags' {
        $htmlPath = Join-Path $env:TEMP ('foton-base-cmp-' + [guid]::NewGuid().ToString('N') + '.html')
        try {
            $out = New-FotonBaselineCompareReport -ReferencePath $script:Ref -DifferencePath $script:Dif -OutputPath $htmlPath
            $out | Should -Be $htmlPath
            $html = Get-Content -LiteralPath $htmlPath -Raw
            $html | Should -Match 'Baseline compare'
            $html | Should -Match 'Added'
            $html | Should -Match 'LocalGroupMember'
            $html | Should -Match 'High'
            $html | Should -Match 'id="foton-q"'
            $html | Should -Match 'id="foton-toc"'
            $html | Should -Match '(?s)<style>.*\.foton-bar'
            $html | Should -Not -Match '</style>\s*\.foton-bar'
            $html | Should -Match 'data-change'
            $html | Should -Not -Match '<script src="https://'
        }
        finally {
            Remove-Item -LiteralPath $htmlPath -Force -ErrorAction SilentlyContinue
        }
    }
}
