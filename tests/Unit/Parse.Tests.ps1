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
