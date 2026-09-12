# Lab.Tests.ps1 - public-release lab bar as automated checks.
# Maps to docs/TODO.md Lab ticks. Live elevated/standard-user collect on a VM
# remains operator verification; these tests prove the offline/package contracts.

BeforeAll {
    $script:FotonPsd1 = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Foton.psd1'))
    $script:WinFotonFolder = [IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot '..\Fixtures\WinFoton_FIXTURE_20260115-120000Z'))
    $script:IocTxt = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\Fixtures\Ioc\lab-iocs.txt'))
    $script:IocCsv = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\Fixtures\Ioc\lab-iocs.csv'))
    $script:Pf = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\Fixtures\Parse\prefetch-scca-v23.bin'))
    Import-Module $script:FotonPsd1 -Force
}

Describe 'Public-release lab bar (automated)' {
    It 'opens a historical WinFoton_* case folder' {
        $pkg = Get-FotonPackage -Path $script:WinFotonFolder
        $pkg.Kind | Should -Be 'Folder'
        $pkg.CaseRoot | Should -Match 'WinFoton_FIXTURE'
        $pkg.ArtifactKeys.Count | Should -BeGreaterThan 0
    }

    It 'opens a historical WinFoton_* zip' {
        $tmp = Join-Path $env:TEMP ('foton-lab-zip-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $tmp -ItemType Directory -Force | Out-Null
        try {
            $zip = Join-Path $tmp 'WinFoton_FIXTURE_20260115-120000Z.zip'
            Compress-Archive -Path $script:WinFotonFolder -DestinationPath $zip -Force
            $pkg = Get-FotonPackage -Path $zip
            $pkg.Kind | Should -Be 'Zip'
            $pkg.ArtifactKeys.Count | Should -BeGreaterThan 0
            Test-Path -LiteralPath (Join-Path $pkg.CaseRoot '00_Collection') | Should -Be $true
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'opens a Foton_* flatten-style case folder' {
        $tmp = Join-Path $env:TEMP ('foton-lab-foton-' + [guid]::NewGuid().ToString('N'))
        $case = Join-Path $tmp 'Foton_FIXTURE_20260115-120000Z'
        try {
            New-Item -Path $tmp -ItemType Directory -Force | Out-Null
            Copy-Item -LiteralPath $script:WinFotonFolder -Destination $case -Recurse -Force
            $pkg = Get-FotonPackage -Path $case
            $pkg.Kind | Should -Be 'Folder'
            $pkg.CaseRoot | Should -Match 'Foton_FIXTURE'
            $pkg.ArtifactKeys.Count | Should -BeGreaterThan 0
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'parses a Prefetch file already copied into a package (not live Prefetch)' {
        $tmp = Join-Path $env:TEMP ('foton-lab-pf-' + [guid]::NewGuid().ToString('N'))
        $case = Join-Path $tmp 'Foton_LAB_PF'
        $pfDir = Join-Path $case '08_Filesystem\prefetch'
        try {
            New-Item -Path $pfDir -ItemType Directory -Force | Out-Null
            New-Item -Path (Join-Path $case '00_Collection') -ItemType Directory -Force | Out-Null
            Copy-Item -LiteralPath $script:Pf -Destination (Join-Path $pfDir 'NOTEPAD.EXE-TEST.pf') -Force
            # Mark schema so Invoke-FotonParse does not treat this as an older listing-only package.
            Set-Content -LiteralPath (Join-Path $case '00_Collection\collection_manifest.csv') -Encoding UTF8 -Value @(
                'Task,Status,Detail'
                'prefetch_files,Success,copied'
            )
            $rows = @(Invoke-FotonParse -Path $case)
            ($rows | Where-Object { $_.Supported -eq $true -or $_.Supported -eq 'True' }).Count |
                Should -BeGreaterThan 0
            Test-Path -LiteralPath (Join-Path $case 'analysis\parsed_records.csv') | Should -Be $true
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'parses EVTX already copied into a package (wevtutil export, not live Winevt)' {
        $tmp = Join-Path $env:TEMP ('foton-lab-evtx-' + [guid]::NewGuid().ToString('N'))
        $case = Join-Path $tmp 'Foton_LAB_EVTX'
        $evtxDir = Join-Path $case '05_EventLogs'
        $evtx = Join-Path $evtxDir 'Application.evtx'
        try {
            New-Item -Path $evtxDir -ItemType Directory -Force | Out-Null
            New-Item -Path (Join-Path $case '00_Collection') -ItemType Directory -Force | Out-Null
            $null = & wevtutil.exe epl Application $evtx '/q:*[System[TimeCreated[timediff(@SystemTime) <= 2592000000]]]' /ow:true 2>&1
            if (-not (Test-Path -LiteralPath $evtx) -or (Get-Item -LiteralPath $evtx).Length -lt 16) {
                Set-ItResult -Skipped -Because 'wevtutil did not export Application.evtx'
                return
            }
            $rows = @(ConvertFrom-FotonEvtx -Path $evtx -MaxEvents 5)
            if ($rows.Count -eq 0) {
                Set-ItResult -Skipped -Because 'export readable but no selected Event IDs in range'
                return
            }
            $rows[0].Format | Should -Be 'EVTX'
            $rows[0].Supported | Should -Be $true
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'matches IOC txt and csv against the WinFoton fixture package' {
        Get-FotonPackage -Path $script:WinFotonFolder | Out-Null
        $txt = @(Invoke-FotonIocMatch -IocPath $script:IocTxt)
        $csv = @(Invoke-FotonIocMatch -IocPath $script:IocCsv)
        $txt.Count | Should -BeGreaterThan 0
        $csv.Count | Should -BeGreaterThan 0
    }

    It 'carves a tiny PE and throws when the blob is missing' {
        { Invoke-FotonCarve -Path 'C:\not-an-image-lab-bar.bin' } | Should -Throw
        $tmp = Join-Path $env:TEMP ('foton-lab-pe-' + [guid]::NewGuid().ToString('N') + '.bin')
        try {
            $buf = New-Object byte[] 0x88
            $buf[0] = 0x4D; $buf[1] = 0x5A
            $buf[0x3C] = 0x80
            $buf[0x80] = 0x50; $buf[0x81] = 0x45
            [IO.File]::WriteAllBytes($tmp, $buf)
            $hits = @(Invoke-FotonCarve -Path $tmp)
            $hits.Count | Should -BeGreaterThan 0
            $hits[0].Kind | Should -Be 'PE'
        }
        finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }

    It 'records locked-file CopyError and missing-source Missing without throwing' {
        InModuleScope Foton {
            Initialize-FotonSession
            $src = Join-Path $env:TEMP ('foton-lab-lock-' + [guid]::NewGuid().ToString('N') + '.bin')
            $dst = Join-Path $env:TEMP ('foton-lab-lockd-' + [guid]::NewGuid().ToString('N') + '.bin')
            [IO.File]::WriteAllBytes($src, [byte[]](1, 2))
            $fs = [IO.File]::Open($src, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
            try {
                $locked = Copy-FotonHostFile -SourcePath $src -DestinationPath $dst
                $locked.Status | Should -Be 'CopyError'
            }
            finally {
                $fs.Dispose()
                Remove-Item -LiteralPath $src, $dst -Force -ErrorAction SilentlyContinue
            }
            $miss = Copy-FotonHostFile -SourcePath (Join-Path $env:TEMP 'foton-lab-no-such.bin') `
                -DestinationPath (Join-Path $env:TEMP ('foton-lab-miss-' + [guid]::NewGuid().ToString('N') + '.bin'))
            $miss.Status | Should -Be 'Missing'
        }
    }

    It 'skips RequiresElevation tasks as SkippedNotElevated when not elevated' {
        InModuleScope Foton {
            Initialize-FotonSession
            $script:FotonSession.IsElevated = $false
            $script:FotonSession.CaseRoot = Join-Path $env:TEMP ('foton-lab-elev-' + [guid]::NewGuid().ToString('N'))
            New-Item -Path $script:FotonSession.CaseRoot -ItemType Directory -Force | Out-Null
            $script:FotonSession.Dirs = @{ System = (Join-Path $script:FotonSession.CaseRoot '01_System') }
            New-Item -Path $script:FotonSession.Dirs['System'] -ItemType Directory -Force | Out-Null
            try {
                Invoke-FotonCollection -Category 'System' -Name 'admin_only' -Format 'Txt' -RequiresElevation -Script { 'secret' } | Out-Null
                $script:FotonSession.Manifest[-1].Status | Should -Be 'SkippedNotElevated'
            }
            finally {
                Remove-Item -LiteralPath $script:FotonSession.CaseRoot -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
    }
}
