# Tools.Tests.ps1 - Install-FotonTool / resolve (no network)

BeforeAll {
    $script:FotonPsd1 = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Foton.psd1'))
    Import-Module $script:FotonPsd1 -Force
}

Describe 'Install-FotonTool and resolve' {
    It 'lists the pinned Hayabusa catalog entry' {
        InModuleScope Foton {
            $rows = @(Get-FotonToolCatalog)
            ($rows | Where-Object { $_.Name -eq 'Hayabusa' }).Count | Should -Be 1
            ($rows | Where-Object { $_.Name -eq 'Hayabusa' }).ExpectedSha256.Length | Should -Be 64
        }
    }

    It 'installs from a local archive when the hash matches, and refuses a mismatch' {
        $tmp = Join-Path $env:TEMP ('foton-tooltest-' + [guid]::NewGuid().ToString('N'))
        $toolRoot = Join-Path $tmp 'tools'
        $payload = Join-Path $tmp 'payload'
        $catalogPath = Join-Path $tmp 'catalog.json'
        New-Item -Path $payload -ItemType Directory -Force | Out-Null
        try {
            # Tiny fake "release" tree: versioned exe name (real Hayabusa 4.x layout) + rules.
            Set-Content -LiteralPath (Join-Path $payload 'hayabusa-9.9.9-test-win-x64.exe') -Value 'fake-hayabusa' -Encoding Ascii
            New-Item -Path (Join-Path $payload 'rules') -ItemType Directory -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $payload 'rules\dummy.yml') -Value 'title: test' -Encoding Ascii
            $zip = Join-Path $tmp 'hayabusa-fake.zip'
            Compress-Archive -Path (Join-Path $payload '*') -DestinationPath $zip -Force
            $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToUpperInvariant()

            $cat = @{
                Tools = @(
                    @{
                        Name             = 'Hayabusa'
                        Version          = '9.9.9-test'
                        AssetName        = 'hayabusa-fake.zip'
                        DownloadUrl      = 'https://example.invalid/hayabusa-fake.zip'
                        ExpectedSha256   = $hash
                        License          = 'AGPL-3.0'
                        ProjectUrl       = 'https://example.invalid'
                        ExecutableNames  = @('hayabusa.exe', 'hayabusa-*.exe')
                        RulesRelativePath = 'rules'
                        Notes            = 'test pin'
                    }
                )
            }
            ($cat | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $catalogPath -Encoding UTF8

            InModuleScope Foton -Parameters @{
                Zip = $zip; Root = $toolRoot; Cat = $catalogPath; Bad = ($hash -replace '.$', '0')
            } {
                param($Zip, $Root, $Cat, $Bad)

                { Install-FotonTool -Name Hayabusa -ArchivePath $Zip -ToolRoot $Root -CatalogPath $Cat -Force } |
                    Should -Not -Throw

                $installed = Get-FotonInstalledTool -Name Hayabusa -ToolRoot $Root
                $installed | Should -Not -BeNullOrEmpty
                $installed.Version | Should -Be '9.9.9-test'
                Test-Path -LiteralPath $installed.ExecutablePath | Should -Be $true

                $resolved = Resolve-FotonExternalTool -ToolName Hayabusa `
                    -ExecutableNames @('hayabusa.exe') -ToolRoot $Root
                $resolved.Source | Should -Be 'Manifest'
                $resolved.Version | Should -Be '9.9.9-test'

                # Tamper the catalog pin: same archive must refuse to install.
                $badCat = Join-Path (Split-Path $Cat) 'catalog-bad.json'
                $raw = Get-Content -LiteralPath $Cat -Raw | ConvertFrom-Json
                $raw.Tools[0].ExpectedSha256 = $Bad
                ($raw | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $badCat -Encoding UTF8
                { Install-FotonTool -Name Hayabusa -ArchivePath $Zip -ToolRoot $Root -CatalogPath $badCat -Force } |
                    Should -Throw -ExpectedMessage '*SHA-256 mismatch*'
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'prefers an explicit ToolPath over the manifest' {
        $tmp = Join-Path $env:TEMP ('foton-toolpath-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $tmp -ItemType Directory -Force | Out-Null
        try {
            $override = Join-Path $tmp 'custom-hayabusa.exe'
            Set-Content -LiteralPath $override -Value 'x' -Encoding Ascii
            InModuleScope Foton -Parameters @{ Override = $override } {
                param($Override)
                $r = Resolve-FotonExternalTool -ToolName Hayabusa -ExecutableNames @('hayabusa.exe') `
                    -ToolPath $Override
                $r.Source | Should -Be 'ToolPath'
                $r.Path | Should -Be (Get-Item -LiteralPath $Override).FullName
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'registers an existing EZ Tools folder including per-tool subfolders' {
        $tmp = Join-Path $env:TEMP ('foton-ezreg-' + [guid]::NewGuid().ToString('N'))
        $ez = Join-Path $tmp 'EZTools'
        New-Item -Path (Join-Path $ez 'EvtxeCmd') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $ez 'RECmd') -ItemType Directory -Force | Out-Null
        foreach ($f in @('PECmd.exe', 'LECmd.exe', 'EvtxeCmd\EvtxECmd.exe', 'RECmd\RECmd.exe')) {
            Set-Content -LiteralPath (Join-Path $ez $f) -Value 'x' -Encoding Ascii
        }
        $root = Join-Path $tmp 'tools'
        try {
            InModuleScope Foton -Parameters @{ Ez = $ez; Root = $root } {
                param($Ez, $Root)
                $rows = @(Install-FotonTool -Name EZTools -Path $Ez -ToolRoot $Root)
                ($rows | Where-Object Name -eq 'EvtxECmd').Status | Should -Be 'Registered'
                ($rows | Where-Object Name -eq 'AmcacheParser').Status | Should -Be 'NotFound'
                $r = Resolve-FotonExternalTool -ToolName EvtxECmd -ExecutableNames @('EvtxECmd.exe') -ToolRoot $Root
                $r.Source | Should -Be 'Manifest'
                $r.Path | Should -Match 'EvtxeCmd\\EvtxECmd\.exe$'
                $rec = Get-FotonInstalledTool -Name RECmd -ToolRoot $Root
                $rec.Verified | Should -Be $false
                $rec.ObservedSha256 | Should -Match '^[0-9A-Fa-f]{64}$'
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'registers into the default tool root when -ToolRoot is omitted' {
        $tmp = Join-Path $env:TEMP ('foton-ezdef-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path (Join-Path $tmp 'cs') -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $tmp 'cs\chainsaw.exe') -Value 'x' -Encoding Ascii
        $savedLad = $env:LOCALAPPDATA
        $env:LOCALAPPDATA = Join-Path $tmp 'lad'
        try {
            InModuleScope Foton -Parameters @{ Dir = (Join-Path $tmp 'cs') } {
                param($Dir)
                $rows = @(Register-FotonLocalTool -Name Chainsaw -Path $Dir)
                $rows[0].Status | Should -Be 'Registered'
                (Get-FotonInstalledTool -Name Chainsaw).ExecutablePath | Should -Match 'chainsaw\.exe$'
            }
        }
        finally {
            $env:LOCALAPPDATA = $savedLad
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'rejects an unknown tool name for registration' {
        InModuleScope Foton {
            { Register-FotonLocalTool -Name 'NotATool' -Path $env:TEMP } | Should -Throw '*Unknown tool*'
        }
    }

    It 'finds RECmd batches and Chainsaw rules beside the binary' {
        $tmp = Join-Path $env:TEMP ('foton-support-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path (Join-Path $tmp 'BatchExamples') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $tmp 'mappings') -ItemType Directory -Force | Out-Null
        try {
            InModuleScope Foton -Parameters @{ Dir = $tmp } {
                param($Dir)
                $recmd = Join-Path $Dir 'RECmd.exe'
                Find-FotonRecmdBatch -RecmdPath $recmd | Should -BeNullOrEmpty
                Set-Content -LiteralPath (Join-Path $Dir 'BatchExamples\Kroll_Batch.reb') -Value 'x'
                Find-FotonRecmdBatch -RecmdPath $recmd | Should -Match 'Kroll_Batch\.reb$'
                Set-Content -LiteralPath (Join-Path $Dir 'BatchExamples\DFIRBatch.reb') -Value 'x'
                Find-FotonRecmdBatch -RecmdPath $recmd | Should -Match 'DFIRBatch\.reb$'

                $cs = Join-Path $Dir 'chainsaw.exe'
                $none = Find-FotonChainsawRules -ChainsawPath $cs
                $none.RulesPath | Should -BeNullOrEmpty
                $none.SigmaPath | Should -BeNullOrEmpty
                New-Item -Path (Join-Path $Dir 'sigma') -ItemType Directory | Out-Null
                (Find-FotonChainsawRules -ChainsawPath $cs).SigmaPath | Should -BeNullOrEmpty
                Set-Content -LiteralPath (Join-Path $Dir 'mappings\sigma-event-logs-all.yml') -Value 'x'
                $s = Find-FotonChainsawRules -ChainsawPath $cs
                $s.SigmaPath | Should -Match 'sigma$'
                $s.MappingPath | Should -Match 'sigma-event-logs-all\.yml$'
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'detects a missing .NET runtime in captured tool output' {
        $tmp = Join-Path $env:TEMP ('foton-rt-' + [guid]::NewGuid().ToString('N') + '.txt')
        try {
            Set-Content -LiteralPath $tmp -Value 'You must install or update .NET to run this application.'
            InModuleScope Foton -Parameters @{ P = $tmp } {
                param($P)
                Test-FotonToolMissingRuntime -Paths @($P, 'C:\foton-no-such.txt') | Should -Be $true
            }
            Set-Content -LiteralPath $tmp -Value 'Processed 12 files'
            InModuleScope Foton -Parameters @{ P = $tmp } {
                param($P)
                Test-FotonToolMissingRuntime -Paths @($P) | Should -Be $false
            }
        }
        finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }

    It 'runs RECmd with a batch, Hayabusa in UTC, and records Chainsaw NoRules' {
        $tmp = Join-Path $env:TEMP ('foton-composeargs-' + [guid]::NewGuid().ToString('N'))
        $pkg = Join-Path $tmp 'Foton_HOST_20260101-000000Z'
        New-Item -Path (Join-Path $pkg '00_Collection') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $pkg '07_Event_Logs\evtx') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $pkg '08_Filesystem\hives\machine') -ItemType Directory -Force | Out-Null
        $bin = Join-Path $tmp 'bin'
        New-Item -Path (Join-Path $bin 'BatchExamples') -ItemType Directory -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $bin 'BatchExamples\DFIRBatch.reb') -Value 'x'
        # Fake tools: record their arguments beside themselves.
        $fake = "@echo %* > `"%~dp0args_%~n0.txt`"`r`n@exit /b 0`r`n"
        foreach ($n in @('recmd', 'hayabusa', 'chainsaw')) {
            Set-Content -LiteralPath (Join-Path $bin "$n.cmd") -Value $fake -Encoding Ascii -NoNewline
        }
        try {
            $rows = @(Invoke-FotonExternalParse -PackagePath $pkg -ToolRoot (Join-Path $tmp 'empty') -ToolPath @{
                    RECmd    = (Join-Path $bin 'recmd.cmd')
                    Hayabusa = (Join-Path $bin 'hayabusa.cmd')
                    Chainsaw = (Join-Path $bin 'chainsaw.cmd')
                })
            (Get-Content -LiteralPath (Join-Path $bin 'args_recmd.txt') -Raw) | Should -Match '--bn .*DFIRBatch\.reb'
            (Get-Content -LiteralPath (Join-Path $bin 'args_hayabusa.txt') -Raw) | Should -Match '(^| )-U( |$)'
            ($rows | Where-Object Tool -eq 'Chainsaw').Status | Should -Be 'NoRules'
            Test-Path -LiteralPath (Join-Path $bin 'args_chainsaw.txt') | Should -Be $false
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'tells compose to use Install-FotonTool when Hayabusa is missing' {
        $pkg = Join-Path $env:TEMP ('foton-compose-miss-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path (Join-Path $pkg '00_Collection') -ItemType Directory -Force | Out-Null
        New-Item -Path (Join-Path $pkg '05_Event_Logs\evtx') -ItemType Directory -Force | Out-Null
        try {
            # Empty tool root so manifest cannot satisfy Hayabusa; PATH may still have it —
            # force isolation by pointing ToolRoot at empty and ToolPath empty; if PATH has
            # hayabusa the row will be Copied/NoInput instead. Assert the NotOnPath wording
            # only when Status is NotOnPath.
            $emptyRoot = Join-Path $pkg 'empty-tools'
            New-Item -Path $emptyRoot -ItemType Directory -Force | Out-Null
            $rows = @(Invoke-FotonExternalParse -PackagePath $pkg -ToolRoot $emptyRoot)
            $hay = @($rows | Where-Object { $_.Tool -eq 'Hayabusa' })
            $hay.Count | Should -BeGreaterThan 0
            if ($hay[0].Status -eq 'NotOnPath') {
                $hay[0].Note | Should -Match 'Install-FotonTool'
            }
            $hay[0].PSObject.Properties.Name | Should -Contain 'Version'
            $hay[0].PSObject.Properties.Name | Should -Contain 'RulesVersion'
        }
        finally {
            Remove-Item -LiteralPath $pkg -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
