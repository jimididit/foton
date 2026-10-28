# Core helper tests. These functions are module-private; InModuleScope is required.

$moduleManifest = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Foton.psd1'))
Import-Module $moduleManifest -Force

InModuleScope Foton {
    Describe 'ConvertTo-FotonSafeHtml' {
        It 'escapes markup and quotes' {
            ConvertTo-FotonSafeHtml "<a href=""x"">&'</a>" |
                Should -Be '&lt;a href=&quot;x&quot;&gt;&amp;&#39;&lt;/a&gt;'
        }
        It 'returns empty string for null' {
            ConvertTo-FotonSafeHtml $null | Should -Be ''
        }
    }

    Describe 'Get-FotonReportMarkSvg' {
        It 'is a wave packet, not the old diamond-and-dot' {
            $svg = Get-FotonReportMarkSvg
            $svg | Should -Match '<path '
            $svg | Should -Match 'polygon points="1.2,24'
            $svg | Should -Not -Match 'points="24,7 41,24 24,41 7,24"'
            $svg | Should -Not -Match '<circle'
        }
    }

    Describe 'Get-FotonCloudJoinRows' {
        It 'reads JoinInfo from a caller-supplied key and skips empty MDM GUIDs' {
            $root = 'HKCU:\Software\_FotonCloudJoinTest_' + [guid]::NewGuid().ToString('N')
            $joinGuid = '{' + [guid]::NewGuid().ToString() + '}'
            $emptyEnroll = '{' + [guid]::NewGuid().ToString() + '}'
            $mdmGuid = '{' + [guid]::NewGuid().ToString() + '}'
            New-Item -Path (Join-Path $root "JoinInfo\$joinGuid") -Force | Out-Null
            New-ItemProperty -Path (Join-Path $root "JoinInfo\$joinGuid") -Name 'TenantId' -Value '11111111-1111-1111-1111-111111111111' -PropertyType String | Out-Null
            New-ItemProperty -Path (Join-Path $root "JoinInfo\$joinGuid") -Name 'DeviceId' -Value '22222222-2222-2222-2222-222222222222' -PropertyType String | Out-Null
            New-ItemProperty -Path (Join-Path $root "JoinInfo\$joinGuid") -Name 'UserEmail' -Value 'user@contoso.test' -PropertyType String | Out-Null
            New-Item -Path (Join-Path $root "Enrollments\$emptyEnroll") -Force | Out-Null
            New-Item -Path (Join-Path $root "Enrollments\$mdmGuid") -Force | Out-Null
            New-ItemProperty -Path (Join-Path $root "Enrollments\$mdmGuid") -Name 'UPN' -Value 'mdm@contoso.test' -PropertyType String | Out-Null
            New-ItemProperty -Path (Join-Path $root "Enrollments\$mdmGuid") -Name 'EnrollmentType' -Value 6 -PropertyType DWord | Out-Null
            try {
                $rows = @(Get-FotonCloudJoinRows -JoinInfoRoot (Join-Path $root 'JoinInfo') -TenantInfoRoot (Join-Path $root 'NoTenant') -EnrollmentRoot (Join-Path $root 'Enrollments') -UserHiveRoots @())
                ($rows | Where-Object { $_.Kind -eq 'AzureAdJoin' }).Count | Should -Be 1
                $aad = $rows | Where-Object { $_.Kind -eq 'AzureAdJoin' } | Select-Object -First 1
                $aad.TenantId | Should -Be '11111111-1111-1111-1111-111111111111'
                $aad.UPN | Should -Be 'user@contoso.test'
                $aad.Note | Should -Match 'not a live tenant lookup'
                ($rows | Where-Object { $_.Kind -eq 'MdmEnrollment' }).Count | Should -Be 1
                $mdm = $rows | Where-Object { $_.Kind -eq 'MdmEnrollment' } | Select-Object -First 1
                $mdm.UPN | Should -Be 'mdm@contoso.test'
                $mdm.EnrollmentType | Should -Be '6'
            }
            finally {
                Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'does not treat missing join keys as a join' {
            $missing = 'HKCU:\Software\_FotonCloudJoinMissing_' + [guid]::NewGuid().ToString('N')
            @(Get-FotonCloudJoinRows -JoinInfoRoot $missing -TenantInfoRoot $missing -EnrollmentRoot $missing -UserHiveRoots @()).Count | Should -Be 0
        }
    }

    Describe 'Get-FotonOneDriveTeamsRows' {
        It 'inventories a sync root and Teams log without reading contents or walking cloud files' {
            $prof = Join-Path $env:TEMP ('foton-odt-' + [guid]::NewGuid().ToString('N'))
            $od = Join-Path $prof 'OneDrive'
            $cloud = Join-Path $od 'cloud-child'
            $logs = Join-Path $prof 'AppData\Local\Microsoft\OneDrive\logs\Business1'
            $teams = Join-Path $prof 'AppData\Roaming\Microsoft\Teams'
            New-Item -Path $cloud, $logs, $teams -ItemType Directory -Force | Out-Null
            'secret-cloud' | Set-Content -LiteralPath (Join-Path $cloud 'payload.txt') -Encoding ascii
            'log-body' | Set-Content -LiteralPath (Join-Path $logs 'sync.log') -Encoding ascii
            'teams-body' | Set-Content -LiteralPath (Join-Path $teams 'logs.txt') -Encoding ascii
            $reg = 'HKCU:\Software\_FotonOdt_' + [guid]::NewGuid().ToString('N')
            $acct = Join-Path $reg 'Software\Microsoft\OneDrive\Accounts\Business1'
            New-Item -Path $acct -Force | Out-Null
            New-ItemProperty -Path $acct -Name 'UserFolder' -Value $od -PropertyType String | Out-Null
            New-ItemProperty -Path $acct -Name 'UserEmail' -Value 'user@contoso.test' -PropertyType String | Out-Null
            New-ItemProperty -Path $acct -Name 'cid' -Value 'cid-1' -PropertyType String | Out-Null
            $profile = [PSCustomObject]@{ UserName = 'alice'; ProfilePath = $prof; Exists = $true; SID = 'S-1-5-21-1' }
            $hive = [PSCustomObject]@{ UserName = 'alice'; SID = 'S-1-5-21-1'; Root = $reg }
            try {
                $rows = @(Get-FotonOneDriveTeamsRows -UserProfiles @($profile) -UserHiveRoots @($hive) -MachineOneDriveRoot ($reg + '\NoMachine'))
                $acctRow = $rows | Where-Object { $_.Kind -eq 'OneDriveAccount' } | Select-Object -First 1
                $acctRow.Email | Should -Be 'user@contoso.test'
                $acctRow.Note | Should -Match 'Token values are omitted'
                ($rows | Where-Object { $_.Kind -eq 'OneDriveFolder' -and $_.Path -eq $od }).Count | Should -Be 1
                ($rows | Where-Object { $_.Path -like '*payload.txt' }).Count | Should -Be 0
                ($rows | Where-Object { $_.Kind -eq 'OneDriveLog' }).Count | Should -Be 1
                $tlog = $rows | Where-Object { $_.Kind -eq 'TeamsLog' } | Select-Object -First 1
                $tlog.Identity | Should -Be 'logs.txt'
                $tlog.Note | Should -Match 'Contents not read'
            }
            finally {
                Remove-Item -LiteralPath $prof -Recurse -Force -ErrorAction SilentlyContinue
                Remove-Item -LiteralPath $reg -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Describe 'ConvertFrom-FotonFileTimeUtc' {
        It 'decodes a known UTC FILETIME' {
            $dt = [datetime]::SpecifyKind([datetime]'2020-01-15 12:00:00', 'Utc')
            $bytes = [BitConverter]::GetBytes($dt.ToFileTimeUtc())
            ConvertFrom-FotonFileTimeUtc -Bytes $bytes | Should -Be '2020-01-15 12:00:00'
        }
        It 'does not invent a time for empty or zero' {
            ConvertFrom-FotonFileTimeUtc -Bytes $null | Should -Be '(not set)'
            ConvertFrom-FotonFileTimeUtc -Bytes ([byte[]]@(0, 0, 0, 0, 0, 0, 0, 0)) | Should -Be '(not set)'
        }
    }

    Describe 'Test-FotonUserWritablePath' {
        BeforeEach { Initialize-FotonSession }
        It 'flags AppData-style paths' {
            Test-FotonUserWritablePath 'C:\Users\a\AppData\Local\payload.exe' | Should -Be $true
        }
        It 'does not flag System32' {
            Test-FotonUserWritablePath 'C:\Windows\System32\svchost.exe' | Should -Be $false
        }
        It 'returns false for empty' {
            Test-FotonUserWritablePath '' | Should -Be $false
        }
    }

    Describe 'Test-FotonSuspiciousCommand' {
        BeforeEach { Initialize-FotonSession }
        It 'hits encodedcommand' {
            $r = Test-FotonSuspiciousCommand 'powershell -encodedcommand ABC'
            $r | Should -Match 'encodedcommand'
        }
        It 'hits -enc as a real flag' {
            $r = Test-FotonSuspiciousCommand 'powershell -enc ZQBjAGgAbwA='
            $r | Should -Match '-enc'
        }
        It 'does not treat Transfer-Encode as -enc' {
            Test-FotonSuspiciousCommand '... | Transfer-Encode against C:\ProgramData\jOVAL\' |
                Should -BeNullOrEmpty
        }
        It 'still hits suffixed short tokens such as psexec64' {
            $r = Test-FotonSuspiciousCommand 'C:\Tools\psexec64.exe -s cmd.exe'
            $r | Should -Match 'psexec'
        }
        It 'returns null for a benign line' {
            Test-FotonSuspiciousCommand 'notepad.exe C:\Windows\notes.txt' | Should -BeNullOrEmpty
        }
    }

    Describe 'Test-FotonMessageNamesCollector' {
        It 'matches Verb-FotonNoun cmdlets' {
            Test-FotonMessageNamesCollector 'ScriptBlock: Get-FotonRegValue -Path HKLM:\x' | Should -Be $true
            Test-FotonMessageNamesCollector 'Invoke-FotonAnalysis ran' | Should -Be $true
        }
        It 'does not treat a bare Foton substring or case path as collector' {
            Test-FotonMessageNamesCollector 'C:\Cases\Foton_HOST_20260101Z\analysis\x.csv' | Should -Be $false
            Test-FotonMessageNamesCollector 'comment: Foton was here' | Should -Be $false
        }
    }

    Describe 'Test-FotonIsFalse' {
        It 'treats bool false as false' {
            Test-FotonIsFalse $false | Should -Be $true
            Test-FotonIsFalse $true | Should -Be $false
        }
        It 'does not treat bool true as the string False' {
            # Regression: $true -eq 'False' was true because [bool]'False' is $true
            Test-FotonIsFalse $true | Should -Be $false
        }
        It 'accepts string False' {
            Test-FotonIsFalse 'False' | Should -Be $true
            Test-FotonIsFalse 'True' | Should -Be $false
        }
    }

    Describe 'Resolve-FotonSuspiciousHits' {
        BeforeEach { Initialize-FotonSession }

        It 'computes hits from raw text when the collected column is empty' {
            # Collect schema 1.10.0 onward: the endpoint writes the column empty
            # because the pattern list cannot ship in the flatten.
            $row = [PSCustomObject]@{ SuspiciousCmdHits = ''; CommandLine = 'powershell -encodedcommand ABC' }
            Resolve-FotonSuspiciousHits -Row $row -StoredProperty 'SuspiciousCmdHits' -TextProperty 'CommandLine' |
                Should -Match 'encodedcommand'
        }

        It 'trusts hits already stored by an older endpoint collection' {
            $row = [PSCustomObject]@{ SuspiciousHits = 'legacy-hit'; Command = 'notepad.exe' }
            Resolve-FotonSuspiciousHits -Row $row -StoredProperty 'SuspiciousHits' -TextProperty 'Command' |
                Should -Be 'legacy-hit'
        }

        It 'returns empty for a benign row' {
            $row = [PSCustomObject]@{ SuspiciousHits = ''; Command = 'notepad.exe C:\temp\notes.txt' }
            Resolve-FotonSuspiciousHits -Row $row -StoredProperty 'SuspiciousHits' -TextProperty 'Command' |
                Should -BeNullOrEmpty
        }

        It 'returns empty when no pattern list is loaded, as inside the flatten' {
            $script:FotonSession.SuspiciousCommandPatterns = @()
            $row = [PSCustomObject]@{ SuspiciousCmdHits = ''; CommandLine = 'powershell -encodedcommand ABC' }
            Resolve-FotonSuspiciousHits -Row $row -StoredProperty 'SuspiciousCmdHits' -TextProperty 'CommandLine' |
                Should -BeNullOrEmpty
        }

        It 'tolerates a row missing both properties' {
            $row = [PSCustomObject]@{ Other = 1 }
            Resolve-FotonSuspiciousHits -Row $row -StoredProperty 'SuspiciousHits' -TextProperty 'Command' |
                Should -BeNullOrEmpty
        }
    }

    Describe 'Get-FotonArtifactPath' {
        BeforeEach { Initialize-FotonSession }
        It 'builds a relative package path' {
            Get-FotonArtifactPath -Category 'System' -Name 'os_info' -Format 'json' |
                Should -Be '01_System/os_info.json'
        }
    }

    Describe 'Get-FotonSafeHash' {
        BeforeEach { Initialize-FotonSession }
        It 'returns empty for a blank path' {
            Get-FotonSafeHash -Path '' | Should -Be ''
        }
        It 'returns FileNotFound for a missing leaf' {
            Get-FotonSafeHash -Path 'C:\this-path-does-not-exist-foton-test.bin' | Should -Be 'FileNotFound'
        }
        It 'returns NotHashed when SkipHashing is set' {
            Initialize-FotonSession -SkipHashing
            Get-FotonSafeHash -Path 'C:\Windows\System32\kernel32.dll' | Should -Be 'NotHashed'
        }
        It 'returns a SHA-256 hex string for a small readable file' {
            $f = Join-Path $env:TEMP ("foton-hash-" + [guid]::NewGuid().ToString('N') + '.txt')
            'foton' | Out-File -FilePath $f -Encoding ASCII -NoNewline
            try {
                $h = Get-FotonSafeHash -Path $f
                $h | Should -Match '^[0-9A-F]{64}$'
            }
            finally {
                Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Describe 'Get-FotonSha256Hex' {
        It 'matches a .NET SHA-256 of the same bytes' {
            InModuleScope Foton {
                $tmp = Join-Path $env:TEMP ('foton-sha-' + [guid]::NewGuid().ToString('N') + '.bin')
                try {
                    [IO.File]::WriteAllBytes($tmp, [byte[]](9, 9, 9))
                    $h = Get-FotonSha256Hex -LiteralPath $tmp
                    $h | Should -Match '^[0-9A-Fa-f]{64}$'
                    $sha = [Security.Cryptography.SHA256]::Create()
                    $fs = [IO.File]::OpenRead($tmp)
                    try {
                        $expect = ([BitConverter]::ToString($sha.ComputeHash($fs))).Replace('-', '')
                    }
                    finally {
                        $fs.Dispose()
                        $sha.Dispose()
                    }
                    $h.ToUpperInvariant() | Should -Be $expect.ToUpperInvariant()
                }
                finally {
                    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
                }
            }
        }
    }

    Describe 'Add-FotonFinding' {
        BeforeEach { Initialize-FotonSession }
        It 'appends a finding with tier and artifact' {
            Add-FotonFinding -Severity 'Info' -Category 'System' -Title 't' -Observation 'o' -Tier 1 -Artifact '01_System/os_info.json'
            $script:FotonSession.Findings.Count | Should -Be 1
            $script:FotonSession.Findings[0].Tier | Should -Be 1
        }
    }

    Describe 'Invoke-FotonCollection' {
        BeforeEach {
            Initialize-FotonSession
            $root = Join-Path $env:TEMP ("foton-col-" + [guid]::NewGuid().ToString('N'))
            New-Item -Path $root -ItemType Directory | Out-Null
            $sys = Join-Path $root '01_System'
            New-Item -Path $sys -ItemType Directory | Out-Null
            $script:FotonSession.Dirs['System'] = $sys
        }
        AfterEach {
            $sys = $script:FotonSession.Dirs['System']
            if ($sys) {
                $root = Split-Path $sys -Parent
                if (Test-Path -LiteralPath $root) {
                    Remove-Item -LiteralPath $root -Recurse -Force
                }
            }
        }
        It 'writes csv, caches data, and records Success' {
            Invoke-FotonCollection -Category 'System' -Name 'unit_probe' -Format 'Csv' -Description 'test' -Script {
                @(
                    [PSCustomObject]@{ Name = 'a'; Value = 1 }
                    [PSCustomObject]@{ Name = 'b'; Value = 2 }
                )
            } | Out-Null
            $script:FotonSession.Manifest[0].Status | Should -Be 'Success'
            $script:FotonSession.Manifest[0].Records | Should -Be 2
            $script:FotonSession.Data['unit_probe'].Count | Should -Be 2
            Test-Path -LiteralPath (Join-Path $script:FotonSession.Dirs['System'] 'unit_probe.csv') | Should -Be $true
        }
        It 'skips RequiresElevation when not elevated' {
            $script:FotonSession.IsElevated = $false
            Invoke-FotonCollection -Category 'System' -Name 'admin_only' -Format 'Txt' -RequiresElevation -Script { 'secret' } | Out-Null
            $script:FotonSession.Manifest[0].Status | Should -Be 'SkippedNotElevated'
            $script:FotonSession.Errors.Count | Should -Be 0
            (Get-Content -LiteralPath (Join-Path $script:FotonSession.Dirs['System'] 'admin_only.txt') -Raw) | Should -Match 'SkippedNotElevated'
        }
        It 'records Error without throwing' {
            Invoke-FotonCollection -Category 'System' -Name 'boom' -Format 'Txt' -Script { throw 'unit-fail' } | Out-Null
            $script:FotonSession.Manifest[0].Status | Should -Be 'Error'
            $script:FotonSession.Errors[0].Task | Should -Be 'boom'
        }
    }

    Describe 'Pattern data files' {
        BeforeEach { Initialize-FotonSession }
        It 'loads user-writable and suspicious command lists' {
            $script:FotonSession.UserWritablePatterns.Count | Should -BeGreaterThan 0
            $script:FotonSession.SuspiciousCommandPatterns | Should -Contain '-encodedcommand'
        }
        It 'loads the expected hardening check count' {
            $script:FotonSession.HardeningRegistryChecks.Count | Should -Be 29
            $lua = $script:FotonSession.HardeningRegistryChecks | Where-Object { $_.Name -eq 'EnableLUA' } | Select-Object -First 1
            $lua.Expected | Should -Be '1'
            $lua.Path | Should -Match 'Policies\\System'
        }
        It 'loads remote-access name substrings' {
            $script:FotonSession.RemoteAccessToolNames | Should -Contain 'teamviewer'
            $script:FotonSession.RemoteAccessToolNames | Should -Contain 'putty'
        }
        It 'Get-FotonPatternLines skips comments and blanks' {
            $f = Join-Path $env:TEMP ("foton-pat-" + [guid]::NewGuid().ToString('N') + '.txt')
            @"
# comment
teamviewer

putty
"@ | Out-File -FilePath $f -Encoding ascii
            try {
                $lines = Get-FotonPatternLines -Path $f
                $lines.Count | Should -Be 2
                $lines[0] | Should -Be 'teamviewer'
            }
            finally {
                Remove-Item -LiteralPath $f -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Describe 'Test-FotonElevated' {
        It 'returns a boolean' {
            $r = Test-FotonElevated
            ($r -eq $true -or $r -eq $false) | Should -Be $true
        }
    }

    Describe 'Copy-FotonHostFile' {
        It 'copies a readable file and hashes the destination' {
            $src = Join-Path $env:TEMP ('foton-cp-src-' + [guid]::NewGuid().ToString('N') + '.bin')
            $dst = Join-Path $env:TEMP ('foton-cp-dst-' + [guid]::NewGuid().ToString('N') + '.bin')
            [IO.File]::WriteAllBytes($src, [byte[]](1, 2, 3, 4))
            try {
                $row = Copy-FotonHostFile -SourcePath $src -DestinationPath $dst
                $row.Status | Should -Be 'Copied'
                $row.SizeBytes | Should -Be 4
                $row.SHA256 | Should -Match '^[0-9A-F]{64}$'
                [IO.File]::ReadAllBytes($dst) | Should -Be ([byte[]](1, 2, 3, 4))
            }
            finally {
                Remove-Item -LiteralPath $src, $dst -Force -ErrorAction SilentlyContinue
            }
        }
        It 'records Missing when the source leaf is absent' {
            $dst = Join-Path $env:TEMP ('foton-cp-miss-' + [guid]::NewGuid().ToString('N') + '.bin')
            $row = Copy-FotonHostFile -SourcePath 'C:\foton-no-such-file-9f3c.bin' -DestinationPath $dst
            $row.Status | Should -Be 'Missing'
            Test-Path -LiteralPath $dst | Should -Be $false
        }
        It 'records CopyError when the source is exclusively locked' {
            $src = Join-Path $env:TEMP ('foton-cp-lock-' + [guid]::NewGuid().ToString('N') + '.bin')
            $dst = Join-Path $env:TEMP ('foton-cp-lockd-' + [guid]::NewGuid().ToString('N') + '.bin')
            [IO.File]::WriteAllBytes($src, [byte[]](9, 9))
            $fs = [IO.File]::Open($src, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
            try {
                $row = Copy-FotonHostFile -SourcePath $src -DestinationPath $dst
                $row.Status | Should -Be 'CopyError'
            }
            finally {
                $fs.Dispose()
                Remove-Item -LiteralPath $src, $dst -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Describe 'Copy-FotonCappedHostFiles' {
        It 'copies newest files first and records CappedSkip' {
            $srcDir = Join-Path $env:TEMP ('foton-pf-src-' + [guid]::NewGuid().ToString('N'))
            $dstDir = Join-Path $env:TEMP ('foton-pf-dst-' + [guid]::NewGuid().ToString('N'))
            New-Item -Path $srcDir -ItemType Directory | Out-Null
            try {
                $old = Join-Path $srcDir 'OLD.EXE-1.pf'
                $new = Join-Path $srcDir 'NEW.EXE-2.pf'
                [IO.File]::WriteAllBytes($old, [byte[]](1, 1))
                Start-Sleep -Milliseconds 20
                [IO.File]::WriteAllBytes($new, [byte[]](2, 2))
                # Compare against FileInfo.FullName: $env:TEMP can be an 8.3 short
                # path on CI runners (RUNNER~1) while Get-ChildItem returns the long form.
                $newFull = (Get-Item -LiteralPath $new).FullName
                $rows = @(Copy-FotonCappedHostFiles -SourceDirectory $srcDir -Filter '*.pf' -DestinationDirectory $dstDir -MaxFiles 1 -MaxTotalBytes 1000)
                ($rows | Where-Object { $_.Status -eq 'Copied' }).Count | Should -Be 1
                ($rows | Where-Object { $_.Status -eq 'CappedSkip' }).Count | Should -Be 1
                ($rows | Where-Object { $_.Status -eq 'Copied' }).SourcePath | Should -Be $newFull
            }
            finally {
                Remove-Item -LiteralPath $srcDir, $dstDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        It 'records Missing when the source directory is absent' {
            $dstDir = Join-Path $env:TEMP ('foton-pf-miss-' + [guid]::NewGuid().ToString('N'))
            $rows = @(Copy-FotonCappedHostFiles -SourceDirectory (Join-Path $env:TEMP 'foton-no-prefetch-dir') -Filter '*.pf' -DestinationDirectory $dstDir)
            $rows[0].Status | Should -Be 'Missing'
        }
    }

    Describe 'Copy-FotonHostFileFamily' {
        It 'copies the primary file and hive-style log sidecar' {
            $srcDir = Join-Path $env:TEMP ('foton-fam-src-' + [guid]::NewGuid().ToString('N'))
            $dstDir = Join-Path $env:TEMP ('foton-fam-dst-' + [guid]::NewGuid().ToString('N'))
            New-Item -Path $srcDir -ItemType Directory | Out-Null
            $hve = Join-Path $srcDir 'Amcache.hve'
            $log = Join-Path $srcDir 'Amcache.hve.LOG1'
            [IO.File]::WriteAllBytes($hve, [byte[]](10, 11))
            [IO.File]::WriteAllBytes($log, [byte[]](12))
            try {
                $rows = @(Copy-FotonHostFileFamily -SourcePath $hve -DestinationDirectory $dstDir -PackageRelativeDirectory '08_Filesystem\amcache')
                $rows.Count | Should -Be 2
                ($rows | Where-Object { $_.Status -eq 'Copied' }).Count | Should -Be 2
                Test-Path -LiteralPath (Join-Path $dstDir 'Amcache.hve.LOG1') | Should -Be $true
            }
            finally {
                Remove-Item -LiteralPath $srcDir, $dstDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Describe 'Get-FotonBaselineChangeSeverity' {
        It 'ranks RemoteAccessConfig changes as High' {
            $c = [PSCustomObject]@{
                RecordType = 'RemoteAccessConfig'
                Identity   = 'RdpNla'
                ChangeType = 'Modified'
                Field      = 'Value'
            }
            Get-FotonBaselineChangeSeverity -Change $c | Should -Be 'High'
        }
        It 'ranks LsaPackage Added as High' {
            $c = [PSCustomObject]@{
                RecordType = 'LsaPackage'
                Identity   = 'Security Packages|evil'
                ChangeType = 'Added'
                Field      = ''
            }
            Get-FotonBaselineChangeSeverity -Change $c | Should -Be 'High'
        }
        It 'ranks PrintMonitor Driver changes as High' {
            $c = [PSCustomObject]@{
                RecordType = 'PrintMonitor'
                Identity   = 'Evil Monitor'
                ChangeType = 'Modified'
                Field      = 'Driver'
            }
            Get-FotonBaselineChangeSeverity -Change $c | Should -Be 'High'
        }
        It 'ranks BitsJob NotifyCmdLine as High and other BitsJob adds as Medium' {
            $n = [PSCustomObject]@{
                RecordType = 'BitsJob'
                Identity   = '{00000000-0000-0000-0000-000000000001}'
                ChangeType = 'Modified'
                Field      = 'NotifyCmdLine'
            }
            Get-FotonBaselineChangeSeverity -Change $n | Should -Be 'High'
            $a = [PSCustomObject]@{
                RecordType = 'BitsJob'
                Identity   = '{00000000-0000-0000-0000-000000000001}'
                ChangeType = 'Added'
                Field      = ''
            }
            Get-FotonBaselineChangeSeverity -Change $a | Should -Be 'Medium'
        }
        It 'ranks CmdAutoRun changes as High' {
            $c = [PSCustomObject]@{
                RecordType = 'CmdAutoRun'
                Identity   = 'HKLM|SOFTWARE\Microsoft\Command Processor'
                ChangeType = 'Modified'
                Field      = 'Command'
            }
            Get-FotonBaselineChangeSeverity -Change $c | Should -Be 'High'
        }
        It 'ranks SessionManager changes as High' {
            $c = [PSCustomObject]@{
                RecordType = 'SessionManager'
                Identity   = 'SessionValue|BootExecute'
                ChangeType = 'Modified'
                Field      = 'Value'
            }
            Get-FotonBaselineChangeSeverity -Change $c | Should -Be 'High'
        }
        It 'ranks KnownDll and ProxyServer as High and AutoConfigURL as Medium' {
            $k = [PSCustomObject]@{
                RecordType = 'KnownDll'
                Identity   = 'evil'
                ChangeType = 'Added'
                Field      = ''
            }
            Get-FotonBaselineChangeSeverity -Change $k | Should -Be 'High'
            $p = [PSCustomObject]@{
                RecordType = 'ProxyConfig'
                Identity   = 'Machine|ProxyServer'
                ChangeType = 'Modified'
                Field      = 'Value'
            }
            Get-FotonBaselineChangeSeverity -Change $p | Should -Be 'High'
            $a = [PSCustomObject]@{
                RecordType = 'ProxyConfig'
                Identity   = 'Machine|AutoConfigURL'
                ChangeType = 'Modified'
                Field      = 'Value'
            }
            Get-FotonBaselineChangeSeverity -Change $a | Should -Be 'Medium'
        }
        It 'ranks WinsockLsp and ActiveSetup StubPath as High and ActiveSetup Version as Info' {
            $w = [PSCustomObject]@{
                RecordType = 'WinsockLsp'
                Identity   = 'Protocol|000000000001'
                ChangeType = 'Modified'
                Field      = 'LibraryPath'
            }
            Get-FotonBaselineChangeSeverity -Change $w | Should -Be 'High'
            $s = [PSCustomObject]@{
                RecordType = 'ActiveSetup'
                Identity   = 'HKLM\{guid}'
                ChangeType = 'Modified'
                Field      = 'StubPath'
            }
            Get-FotonBaselineChangeSeverity -Change $s | Should -Be 'High'
            $v = [PSCustomObject]@{
                RecordType = 'ActiveSetup'
                Identity   = 'HKLM\{guid}'
                ChangeType = 'Modified'
                Field      = 'Version'
            }
            Get-FotonBaselineChangeSeverity -Change $v | Should -Be 'Info'
        }
        It 'ranks SilentProcessExit MonitorProcess and NetshHelper as High' {
            $s = [PSCustomObject]@{
                RecordType = 'SilentProcessExit'
                Identity   = 'lsass.exe'
                ChangeType = 'Added'
                Field      = ''
            }
            Get-FotonBaselineChangeSeverity -Change $s | Should -Be 'High'
            $n = [PSCustomObject]@{
                RecordType = 'NetshHelper'
                Identity   = 'HKLM:\SOFTWARE\Microsoft\NetSh|evil'
                ChangeType = 'Modified'
                Field      = 'Dll'
            }
            Get-FotonBaselineChangeSeverity -Change $n | Should -Be 'High'
        }
        It 'ranks TimeProvider DllName as High and Enabled as Medium' {
            $d = [PSCustomObject]@{
                RecordType = 'TimeProvider'
                Identity   = 'NtpClient'
                ChangeType = 'Modified'
                Field      = 'DllName'
            }
            Get-FotonBaselineChangeSeverity -Change $d | Should -Be 'High'
            $e = [PSCustomObject]@{
                RecordType = 'TimeProvider'
                Identity   = 'NtpClient'
                ChangeType = 'Modified'
                Field      = 'Enabled'
            }
            Get-FotonBaselineChangeSeverity -Change $e | Should -Be 'Medium'
        }
        It 'still ranks software version bumps as Info' {
            $c = [PSCustomObject]@{
                RecordType = 'InstalledSoftware'
                Identity   = 'App|Pub'
                ChangeType = 'Modified'
                Field      = 'DisplayVersion'
            }
            Get-FotonBaselineChangeSeverity -Change $c | Should -Be 'Info'
        }
        It 'ranks WdacApplockerPolicy PolicyHash as High' {
            $c = [PSCustomObject]@{
                RecordType = 'WdacApplockerPolicy'
                Identity   = 'Wdac|SiPolicy.p7b'
                ChangeType = 'Modified'
                Field      = 'PolicyHash'
            }
            Get-FotonBaselineChangeSeverity -Change $c | Should -Be 'High'
        }
    }

    Describe 'Copy-FotonCappedHostFileList' {
        It 'copies explicit DestRelative paths and caps byte budget' {
            $srcDir = Join-Path $env:TEMP ('foton-list-src-' + [guid]::NewGuid().ToString('N'))
            $dstDir = Join-Path $env:TEMP ('foton-list-dst-' + [guid]::NewGuid().ToString('N'))
            New-Item -Path $srcDir -ItemType Directory | Out-Null
            try {
                $a = Join-Path $srcDir 'a.bin'
                $b = Join-Path $srcDir 'b.bin'
                [IO.File]::WriteAllBytes($a, [byte[]](1, 2, 3, 4))
                Start-Sleep -Milliseconds 20
                [IO.File]::WriteAllBytes($b, [byte[]](5, 6, 7, 8, 9, 10))
                $items = @(
                    [PSCustomObject]@{ SourcePath = $a; DestRelative = 'u1\a.bin' }
                    [PSCustomObject]@{ SourcePath = $b; DestRelative = 'u2\b.bin' }
                )
                $rows = @(Copy-FotonCappedHostFileList -Items $items -DestinationDirectory $dstDir -MaxFiles 10 -MaxTotalBytes 5)
                ($rows | Where-Object { $_.Status -eq 'Copied' }).Count | Should -Be 1
                ($rows | Where-Object { $_.Status -eq 'CappedSkip' }).Count | Should -Be 1
                Test-Path -LiteralPath (Join-Path $dstDir 'u1\a.bin') | Should -Be $true
            }
            finally {
                Remove-Item -LiteralPath $srcDir, $dstDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'refuses UNC sources without probing the network' {
            $dstDir = Join-Path $env:TEMP ('foton-list-unc-' + [guid]::NewGuid().ToString('N'))
            New-Item -Path $dstDir -ItemType Directory | Out-Null
            try {
                $items = @(
                    [PSCustomObject]@{ SourcePath = '\\evil.example\share\x.ps1'; DestRelative = 'x.ps1' }
                )
                $rows = @(Copy-FotonCappedHostFileList -Items $items -DestinationDirectory $dstDir)
                $rows.Count | Should -Be 1
                $rows[0].Status | Should -Be 'SkippedUnc'
            }
            finally {
                Remove-Item -LiteralPath $dstDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }

        It 'refuses DestRelative that would escape the destination root' {
            $srcDir = Join-Path $env:TEMP ('foton-list-esc-src-' + [guid]::NewGuid().ToString('N'))
            $dstDir = Join-Path $env:TEMP ('foton-list-esc-dst-' + [guid]::NewGuid().ToString('N'))
            New-Item -Path $srcDir -ItemType Directory | Out-Null
            New-Item -Path $dstDir -ItemType Directory | Out-Null
            try {
                $a = Join-Path $srcDir 'a.bin'
                [IO.File]::WriteAllBytes($a, [byte[]](1, 2, 3))
                $items = @(
                    [PSCustomObject]@{ SourcePath = $a; DestRelative = '..\escape.bin' }
                )
                $rows = @(Copy-FotonCappedHostFileList -Items $items -DestinationDirectory $dstDir)
                $rows[0].Status | Should -Be 'CopyError'
                $rows[0].Note | Should -Match '\.\.'
                Test-Path -LiteralPath (Join-Path (Split-Path $dstDir -Parent) 'escape.bin') | Should -Be $false
            }
            finally {
                Remove-Item -LiteralPath $srcDir, $dstDir -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }

    Describe 'Get-FotonNestedDuplicateRoot' {
        It 'finds a case tree copied inside itself' {
            $root = Join-Path $env:TEMP ('foton-nest-' + [guid]::NewGuid().ToString('N'))
            $case = Join-Path $root 'Foton_HOST_20260101-000000Z'
            $inner = Join-Path $case 'Foton_HOST_20260101-000000Z'
            New-Item -Path (Join-Path $case '00_Collection') -ItemType Directory -Force | Out-Null
            New-Item -Path (Join-Path $inner '00_Collection') -ItemType Directory -Force | Out-Null
            # FullName avoids 8.3 vs long-path mismatch when $env:TEMP is short on CI.
            $innerFull = (Get-Item -LiteralPath $inner).FullName
            try {
                Get-FotonNestedDuplicateRoot -CaseRoot $case | Should -Be $innerFull
            }
            finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'returns nothing for a well-formed single-tree package' {
            $root = Join-Path $env:TEMP ('foton-nest-ok-' + [guid]::NewGuid().ToString('N'))
            $case = Join-Path $root 'Foton_HOST_20260101-000000Z'
            New-Item -Path (Join-Path $case '00_Collection') -ItemType Directory -Force | Out-Null
            New-Item -Path (Join-Path $case '08_Filesystem') -ItemType Directory -Force | Out-Null
            try {
                Get-FotonNestedDuplicateRoot -CaseRoot $case | Should -BeNullOrEmpty
            }
            finally { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue }
        }
    }

    Describe 'Get-FotonTaskActionScriptPath' {
        It 'takes Execute when it is a rooted script path' {
            $paths = @(Get-FotonTaskActionScriptPath -Execute 'C:\Temp\payload.ps1' -Arguments '')
            $paths | Should -Contain 'C:\Temp\payload.ps1'
        }

        It 'pulls quoted and bare script paths from Arguments' {
            $args = '-File "C:\Windows\Temp\run.ps1" /c D:\Scripts\fix.bat'
            $paths = @(Get-FotonTaskActionScriptPath -Execute 'powershell.exe' -Arguments $args)
            $paths | Should -Contain 'C:\Windows\Temp\run.ps1'
            $paths | Should -Contain 'D:\Scripts\fix.bat'
        }

        It 'ignores non-script Execute and relative paths' {
            $paths = @(Get-FotonTaskActionScriptPath -Execute 'C:\Windows\System32\notepad.exe' -Arguments 'relative.ps1')
            $paths.Count | Should -Be 0
        }

        It 'returns UNC paths without resolving them (caller must not open)' {
            $paths = @(Get-FotonTaskActionScriptPath -Execute '\\evil.example\share\pay.ps1' -Arguments '')
            $paths | Should -Contain '\\evil.example\share\pay.ps1'
        }

        It 'normalizes local .. segments via GetFullPath' {
            $paths = @(Get-FotonTaskActionScriptPath -Execute 'C:\Windows\Temp\..\Temp\payload.ps1' -Arguments '')
            $paths.Count | Should -Be 1
            $paths[0] | Should -Not -Match '\\\.\.\\'
            $paths[0] | Should -Match '^[A-Za-z]:\\'
        }
    }

    Describe 'Test-FotonDeepDiskBudget' {
        It 'returns true when CaseRoot is unset (fail-open)' {
            $prev = $script:FotonSession
            $script:FotonSession = @{ CaseRoot = $null }
            try {
                Test-FotonDeepDiskBudget | Should -Be $true
            }
            finally { $script:FotonSession = $prev }
        }
    }
}
