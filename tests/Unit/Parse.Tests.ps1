BeforeAll {
    $script:FotonPsd1 = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Foton.psd1'))
    $script:Fx = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\Fixtures\Parse'))
    Import-Module $script:FotonPsd1 -Force
}

Describe 'ConvertFrom-FotonPrefetch' {
    It 'reads an uncompressed SCCA v23 executable name' {
        $r = ConvertFrom-FotonPrefetch -Path (Join-Path $script:Fx 'prefetch-scca-v23.bin')
        $r.Format | Should -Be 'SCCA'
        $r.Supported | Should -Be $true
        $r.ExecutableName | Should -Be 'NOTEPAD.EXE'
    }

    It 'does not invent a name for MAM-compressed prefetch' {
        $r = ConvertFrom-FotonPrefetch -Path (Join-Path $script:Fx 'prefetch-mam.bin')
        $r.Format | Should -Be 'MAM-compressed'
        $r.Supported | Should -Be $false
        $r.ExecutableName | Should -Be ''
    }

    It 'emits unsupported for non-prefetch bytes' {
        $r = ConvertFrom-FotonPrefetch -Path (Join-Path $script:Fx 'prefetch-not.bin')
        $r.Format | Should -Be 'Unsupported-NotPrefetch'
        $r.Supported | Should -Be $false
    }
}

Describe 'ConvertFrom-FotonLnk' {
    It 'reads LocalBasePath from a COM-created shortcut' {
        $tmp = Join-Path $env:TEMP ('foton-lnk-' + [guid]::NewGuid().ToString('N') + '.lnk')
        try {
            $w = New-Object -ComObject WScript.Shell
            $s = $w.CreateShortcut($tmp)
            $s.TargetPath = "$env:SystemRoot\System32\notepad.exe"
            $s.Save()
            $r = ConvertFrom-FotonLnk -Path $tmp
            $r.Format | Should -Be 'LNK'
            $r.Supported | Should -Be $true
            $r.LocalBasePath | Should -Match 'notepad\.exe'
        }
        finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }

    It 'emits unsupported for non-lnk bytes' {
        $r = ConvertFrom-FotonLnk -Path (Join-Path $script:Fx 'prefetch-not.bin')
        $r.Format | Should -Match 'Unsupported'
        $r.Supported | Should -Be $false
    }
}

Describe 'ConvertFrom-FotonJumplist' {
    It 'parses DestList v1 path and FILETIME from a synthetic stream' {
        InModuleScope Foton {
            $bytes = [IO.File]::ReadAllBytes((Join-Path $script:FotonModuleRoot 'tests\Fixtures\Parse\jumplist-destlist-v1.bin'))
            $rows = @(ConvertFrom-FotonDestListBytes -Bytes $bytes)
            $rows.Count | Should -Be 1
            $rows[0].Supported | Should -Be $true
            $rows[0].Identity | Should -Be 'C:\Windows\notepad.exe'
            $rows[0].LastAccessUtc | Should -Be '2020-01-15 12:00:00'
            $rows[0].PinStatus | Should -Be 'Unpinned'
            $rows[0].Hostname | Should -Be 'HOST'
        }
    }

    It 'does not invent DestList fields for an unknown version' {
        InModuleScope Foton {
            $b = New-Object byte[] 32
            [BitConverter]::GetBytes([uint32]99).CopyTo($b, 0)
            $rows = @(ConvertFrom-FotonDestListBytes -Bytes $b)
            $rows[0].Supported | Should -Be $false
            $rows[0].Identity | Should -Be ''
            $rows[0].Note | Should -Match 'not 1, 2, 3, or 4'
        }
    }

    It 'reads an embedded LNK from a custom destinations wrapper' {
        $lnk = Join-Path $env:TEMP ('foton-jl-lnk-' + [guid]::NewGuid().ToString('N') + '.lnk')
        $jl = Join-Path $env:TEMP ('foton-jl-' + [guid]::NewGuid().ToString('N') + '.customDestinations-ms')
        try {
            $w = New-Object -ComObject WScript.Shell
            $s = $w.CreateShortcut($lnk)
            $s.TargetPath = "$env:SystemRoot\System32\notepad.exe"
            $s.Save()
            $lnkBytes = [IO.File]::ReadAllBytes($lnk)
            $clsid = [byte[]](0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46)
            $footer = [byte[]](0xAB, 0xFB, 0xBF, 0xBA)
            $hdr = New-Object byte[] 12
            [BitConverter]::GetBytes([uint32]2).CopyTo($hdr, 0)
            [BitConverter]::GetBytes([uint32]1).CopyTo($hdr, 4)
            $ms = New-Object IO.MemoryStream
            $ms.Write($hdr, 0, $hdr.Length)
            $ms.Write($clsid, 0, $clsid.Length)
            $ms.Write($lnkBytes, 0, $lnkBytes.Length)
            $ms.Write($footer, 0, $footer.Length)
            [IO.File]::WriteAllBytes($jl, $ms.ToArray())
            $rows = @(ConvertFrom-FotonJumplist -Path $jl)
            $hit = $rows | Where-Object { $_.Supported -eq $true -and $_.LocalBasePath -match 'notepad\.exe' } | Select-Object -First 1
            $hit | Should -Not -BeNullOrEmpty
            $hit.Format | Should -Be 'CustomDestinations'
        }
        finally {
            Remove-Item -LiteralPath $lnk, $jl -Force -ErrorAction SilentlyContinue
        }
    }

    It 'emits unsupported for non-jumplist bytes' {
        $r = @(ConvertFrom-FotonJumplist -Path (Join-Path $script:Fx 'jumplist-not.bin'))
        $r[0].Format | Should -Match 'Unsupported'
        $r[0].Supported | Should -Be $false
    }
}

Describe 'ConvertFrom-FotonEvtx' {
    It 'emits unsupported for non-evtx bytes' {
        $r = ConvertFrom-FotonEvtx -Path (Join-Path $script:Fx 'prefetch-not.bin')
        $r.Format | Should -Be 'Unsupported-NotEvtx'
        $r.Supported | Should -Be $false
    }

    It 'parses selected IDs from a wevtutil export when Application log is readable' {
        $tmp = Join-Path $env:TEMP ('foton-evtx-' + [guid]::NewGuid().ToString('N') + '.evtx')
        try {
            $null = & wevtutil.exe epl Application $tmp '/q:*[System[TimeCreated[timediff(@SystemTime) <= 2592000000]]]' /ow:true 2>&1
            if (-not (Test-Path -LiteralPath $tmp) -or (Get-Item -LiteralPath $tmp).Length -lt 16) {
                Set-ItResult -Skipped -Because 'wevtutil did not export Application.evtx'
                return
            }
            $rows = @(ConvertFrom-FotonEvtx -Path $tmp -MaxEvents 5)
            $rows.Count | Should -BeGreaterThan 0
            $rows[0].Format | Should -Be 'EVTX'
            $rows[0].Supported | Should -Be $true
        }
        finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Invoke-FotonParse' {
    It 'says so when a package has no .pf or .lnk files' {
        $case = Join-Path $env:TEMP ('foton-parse-empty-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path (Join-Path $case '00_Collection') -ItemType Directory -Force | Out-Null
        try {
            $rows = @(Invoke-FotonParse -Path $case)
            $rows.Count | Should -Be 0
            Test-Path -LiteralPath (Join-Path $case 'analysis\Foton_Parse.html') | Should -Be $true
        }
        finally {
            Remove-Item -LiteralPath $case -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    It 'parses a .pf already copied into a case folder' {
        $case = Join-Path $env:TEMP ('foton-parse-pkg-' + [guid]::NewGuid().ToString('N'))
        $pfDir = Join-Path $case '08_Filesystem\prefetch'
        New-Item -Path (Join-Path $case '00_Collection') -ItemType Directory -Force | Out-Null
        New-Item -Path $pfDir -ItemType Directory -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $script:Fx 'prefetch-scca-v23.bin') -Destination (Join-Path $pfDir 'NOTEPAD.EXE-1.pf')
        try {
            $rows = @(Invoke-FotonParse -Path $case)
            $pf = $rows | Where-Object { $_.ExecutableName -eq 'NOTEPAD.EXE' } | Select-Object -First 1
            $pf | Should -Not -BeNullOrEmpty
            $pf.Format | Should -Be 'SCCA'
            Test-Path -LiteralPath (Join-Path $case 'analysis\parsed_records.csv') | Should -Be $true
            $html = Get-Content -LiteralPath (Join-Path $case 'analysis\Foton_Parse.html') -Raw
            $html | Should -Match 'id="foton-q"'
            $html | Should -Match 'id="foton-toc"'
            $html | Should -Match '(?s)<style>.*\.foton-bar'
            $html | Should -Not -Match '</style>\s*\.foton-bar'
            $html | Should -Match 'NOTEPAD'
        }
        finally {
            Remove-Item -LiteralPath $case -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'ConvertFrom-FotonAmcache' {
    BeforeAll {
        $script:NewFotonSyntheticRegfHive = {
            param($Kind)
    $buf = New-Object byte[] 0x3000
    $null = [Text.Encoding]::ASCII.GetBytes('regf').CopyTo($buf, 0)
    $null = [Text.Encoding]::ASCII.GetBytes('hbin').CopyTo($buf, 0x1000)
    [BitConverter]::GetBytes([int]0x2000).CopyTo($buf, 0x1008)
    $script:FotonHiveNext = 0x20
    $add = {
        param([byte[]]$Payload)
        $len = 4 + $Payload.Length
        $pad = (8 - ($len % 8)) % 8
        $total = $len + $pad
        $off = $script:FotonHiveNext
        $pos = 0x1000 + $off
        [BitConverter]::GetBytes(-$total).CopyTo($buf, $pos)
        [Array]::Copy($Payload, 0, $buf, ($pos + 4), $Payload.Length)
        $script:FotonHiveNext += $total
        return $off
    }
    $ft = [datetime]::SpecifyKind([datetime]'2020-01-15 12:00:00', 'Utc').ToFileTimeUtc()
    $mkNk = {
        param($Name, $SubCount, $SubList, $ValCount, $ValList)
        $nb = New-Object System.Collections.Generic.List[byte]
        $null = $nb.AddRange([byte[]](0x6E, 0x6B))
        $null = $nb.AddRange([BitConverter]::GetBytes([uint16]0x0020))
        $null = $nb.AddRange([BitConverter]::GetBytes([int64]$ft))
        $null = $nb.AddRange([BitConverter]::GetBytes([int32]0))
        $null = $nb.AddRange([BitConverter]::GetBytes([int32]0))
        $null = $nb.AddRange([BitConverter]::GetBytes([int32]$SubCount))
        $null = $nb.AddRange([BitConverter]::GetBytes([int32]0))
        $null = $nb.AddRange([BitConverter]::GetBytes([int32]$SubList))
        $null = $nb.AddRange([BitConverter]::GetBytes([int32]0))
        $null = $nb.AddRange([BitConverter]::GetBytes([int32]$ValCount))
        $null = $nb.AddRange([BitConverter]::GetBytes([int32]$ValList))
        $null = $nb.AddRange([BitConverter]::GetBytes([int32]-1))
        $null = $nb.AddRange([BitConverter]::GetBytes([int32]-1))
        1..5 | ForEach-Object { $null = $nb.AddRange([BitConverter]::GetBytes([int32]0)) }
        $nameBytes = [Text.Encoding]::ASCII.GetBytes($Name)
        $null = $nb.AddRange([BitConverter]::GetBytes([uint16]$nameBytes.Length))
        $null = $nb.AddRange([BitConverter]::GetBytes([uint16]0))
        $null = $nb.AddRange($nameBytes)
        return ,$nb.ToArray()
    }
    $mkLf = {
        param([int]$ChildOff)
        $lb = New-Object System.Collections.Generic.List[byte]
        $null = $lb.AddRange([byte[]](0x6C, 0x66))
        $null = $lb.AddRange([BitConverter]::GetBytes([uint16]1))
        $null = $lb.AddRange([BitConverter]::GetBytes([int32]$ChildOff))
        $null = $lb.AddRange([BitConverter]::GetBytes([int32]0))
        return ,$lb.ToArray()
    }
    if ($Kind -eq 'AmcacheFile') {
        $path = "c:\windows\notepad.exe`0"
        $pathData = [Text.Encoding]::Unicode.GetBytes($path)
        $dataOff = & $add $pathData
        $vk = New-Object System.Collections.Generic.List[byte]
        $vname = [Text.Encoding]::ASCII.GetBytes('LowerCaseLongPath')
        $null = $vk.AddRange([byte[]](0x76, 0x6B))
        $null = $vk.AddRange([BitConverter]::GetBytes([uint16]$vname.Length))
        $null = $vk.AddRange([BitConverter]::GetBytes([uint32]$pathData.Length))
        $null = $vk.AddRange([BitConverter]::GetBytes([int32]$dataOff))
        $null = $vk.AddRange([BitConverter]::GetBytes([int32]1))
        $null = $vk.AddRange([BitConverter]::GetBytes([uint16]1))
        $null = $vk.AddRange([BitConverter]::GetBytes([uint16]0))
        $null = $vk.AddRange($vname)
        $vkOff = & $add $vk.ToArray()
        $vlist = [BitConverter]::GetBytes([int32]$vkOff)
        $vlistOff = & $add $vlist
        $fileNk = & $mkNk 'aabbcc' 0 -1 1 $vlistOff
        $fileOff = & $add $fileNk
        $invLf = & $mkLf $fileOff
        $invLfOff = & $add $invLf
        $invNk = & $mkNk 'InventoryApplicationFile' 1 $invLfOff 0 -1
        $invOff = & $add $invNk
        $rootLf = & $mkLf $invOff
        $rootLfOff = & $add $rootLf
        $rootNk = & $mkNk 'ROOT' 1 $rootLfOff 0 -1
        $rootOff = & $add $rootNk
    }
    else {
        $leaf = & $mkNk '1234' 0 -1 0 -1
        $leafOff = & $add $leaf
        $volLf = & $mkLf $leafOff
        $volLfOff = & $add $volLf
        $volNk = & $mkNk 'volume' 1 $volLfOff 0 -1
        $volOff = & $add $volNk
        $fileLf = & $mkLf $volOff
        $fileLfOff = & $add $fileLf
        $fileNk = & $mkNk 'File' 1 $fileLfOff 0 -1
        $fileOff = & $add $fileNk
        $rootLf = & $mkLf $fileOff
        $rootLfOff = & $add $rootLf
        $rootNk = & $mkNk 'ROOT' 1 $rootLfOff 0 -1
        $rootOff = & $add $rootNk
    }
    [BitConverter]::GetBytes([int32]$rootOff).CopyTo($buf, 0x24)
    return $buf
        }
    }

    It 'reads InventoryApplicationFile LowerCaseLongPath from a synthetic hive' {
        $hiv = Join-Path $env:TEMP ('foton-amcache-' + [guid]::NewGuid().ToString('N') + '.hve')
        try {
            [IO.File]::WriteAllBytes($hiv, (& $script:NewFotonSyntheticRegfHive 'AmcacheFile'))
            $rows = @(ConvertFrom-FotonAmcache -Path $hiv)
            $hit = $rows | Where-Object { $_.Format -eq 'AmcacheFile' } | Select-Object -First 1
            $hit | Should -Not -BeNullOrEmpty
            $hit.Supported | Should -Be $true
            $hit.LowerCaseLongPath | Should -Be 'c:\windows\notepad.exe'
            $hit.KeyLastWriteUtc | Should -Be '2020-01-15 12:00:00'
            $hit.Note | Should -Match 'not proof of execution'
        }
        finally {
            Remove-Item -LiteralPath $hiv -Force -ErrorAction SilentlyContinue
        }
    }

    It 'does not map legacy File numeric value IDs' {
        $hiv = Join-Path $env:TEMP ('foton-amcache-leg-' + [guid]::NewGuid().ToString('N') + '.hve')
        try {
            [IO.File]::WriteAllBytes($hiv, (& $script:NewFotonSyntheticRegfHive 'LegacyFile'))
            $r = @(ConvertFrom-FotonAmcache -Path $hiv) | Select-Object -First 1
            $r.Format | Should -Be 'Amcache-LegacyFile'
            $r.Supported | Should -Be $false
            $r.Identity | Should -Be ''
        }
        finally {
            Remove-Item -LiteralPath $hiv -Force -ErrorAction SilentlyContinue
        }
    }

    It 'emits unsupported for non-hive bytes' {
        $tmp = Join-Path $env:TEMP ('foton-amcache-not-' + [guid]::NewGuid().ToString('N') + '.bin')
        try {
            $junk = New-Object byte[] 0x1200
            [IO.File]::WriteAllBytes($tmp, $junk)
            $r = @(ConvertFrom-FotonAmcache -Path $tmp)
            $r[0].Format | Should -Be 'Unsupported-NotHive'
            $r[0].Supported | Should -Be $false
        }
        finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
}

Describe 'Invoke-FotonExternalParse' {
    It 'records NotOnPath when EZ tools are absent' {
        $tmp = Join-Path $env:TEMP ('foton-ext-' + [guid]::NewGuid().ToString('N'))
        New-Item -Path $tmp -ItemType Directory | Out-Null
        try {
            InModuleScope Foton -Parameters @{ Root = $tmp } {
                param($Root)
                Initialize-FotonSession
                $script:FotonSession.CaseRoot = $Root
                $rows = @(Invoke-FotonExternalParse)
                @($rows | Where-Object { $_.Status -eq 'NotOnPath' }).Count | Should -BeGreaterThan 0
            }
            Test-Path -LiteralPath (Join-Path $tmp 'analysis\external\external_parse_inventory.csv') | Should -Be $true
        }
        finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}
