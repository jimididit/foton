# Core helper tests. These functions are module-private; InModuleScope is required.
# Behavior must match WinFoton.ps1 helpers (sentinels, escape rules, skip status).

# Core helper tests. These functions are module-private; InModuleScope is required.
# Behavior must match WinFoton.ps1 helpers (sentinels, escape rules, skip status).

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
        It 'returns null for a benign line' {
            Test-FotonSuspiciousCommand 'notepad.exe C:\temp\notes.txt' | Should -BeNullOrEmpty
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
        It 'loads the same hardening check count as WinFoton.ps1' {
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
                $rows = @(Copy-FotonCappedHostFiles -SourceDirectory $srcDir -Filter '*.pf' -DestinationDirectory $dstDir -MaxFiles 1 -MaxTotalBytes 1000)
                ($rows | Where-Object { $_.Status -eq 'Copied' }).Count | Should -Be 1
                ($rows | Where-Object { $_.Status -eq 'CappedSkip' }).Count | Should -Be 1
                ($rows | Where-Object { $_.Status -eq 'Copied' }).SourcePath | Should -Be $new
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
        It 'still ranks software version bumps as Info' {
            $c = [PSCustomObject]@{
                RecordType = 'InstalledSoftware'
                Identity   = 'App|Pub'
                ChangeType = 'Modified'
                Field      = 'DisplayVersion'
            }
            Get-FotonBaselineChangeSeverity -Change $c | Should -Be 'Info'
        }
    }
}
