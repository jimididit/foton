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
