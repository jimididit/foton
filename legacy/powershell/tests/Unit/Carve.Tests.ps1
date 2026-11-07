BeforeAll {
    $script:FotonPsd1 = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\Foton.psd1'))
    Import-Module $script:FotonPsd1 -Force
}

Describe 'Invoke-FotonCarve' {
    It 'throws when the blob is missing' {
        { Invoke-FotonCarve -Path 'C:\not-an-image.bin' } | Should -Throw
    }

    It 'reports a PE hit on a tiny MZ/PE stub' {
        $tmp = Join-Path $env:TEMP ('foton-carve-' + [guid]::NewGuid().ToString('N') + '.bin')
        try {
            $buf = New-Object byte[] 0x88
            $buf[0] = 0x4D
            $buf[1] = 0x5A
            $buf[0x3C] = 0x80
            $buf[0x80] = 0x50
            $buf[0x81] = 0x45
            [IO.File]::WriteAllBytes($tmp, $buf)
            $hits = @(Invoke-FotonCarve -Path $tmp)
            $hits.Count | Should -BeGreaterThan 0
            $hits[0].Kind | Should -Be 'PE'
        }
        finally {
            Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        }
    }
}
