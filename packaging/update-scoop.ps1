<#
.SYNOPSIS
    Points bucket\foton.json (the Scoop manifest) at a published Foton release.
.DESCRIPTION
    Run after a release is published, from the repository root, then open a PR with the changed manifest. Reads the
    ZIP's SHA-256 from the release's SHA256SUMS.txt (the same list the release notes and attestation cover), so the
    manifest pins exactly the published file.
.EXAMPLE
    .\packaging\update-scoop.ps1 -Version 3.2.1
#>
param([Parameter(Mandatory)][ValidatePattern('^\d+\.\d+\.\d+$')][string]$Version)
$ErrorActionPreference = 'Stop'
$base = "https://github.com/jimididit/foton/releases/download/v$Version"
$zip = "Foton-$Version-windows.zip"
# GitHub serves release assets as application/octet-stream, so the body can arrive as bytes.
$body = (Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS.txt").Content
if ($body -is [byte[]]) { $body = [Text.Encoding]::UTF8.GetString($body) }
$sums = $body -split "`r?`n"
$line = $sums | Where-Object { $_ -match "^([0-9a-f]{64})\s+$([regex]::Escape($zip))$" } | Select-Object -First 1
if (-not $line) { throw "SHA256SUMS.txt of v$Version lists no $zip." }
$hash = ($line -split '\s+')[0]
$path = (Resolve-Path (Join-Path $PSScriptRoot '..\bucket\foton.json')).Path
# Replace the three values in place, so the file keeps its layout in either PowerShell.
$json = [IO.File]::ReadAllText($path)
$json = [regex]::Replace($json, '(?m)^(    "version": )"[^"]*"', "`$1`"$Version`"")
$json = [regex]::Replace($json, '(?m)^(    "url": )"[^"]*"', "`$1`"$base/$zip`"")
$json = [regex]::Replace($json, '(?m)^(    "hash": )"[^"]*"', "`$1`"$hash`"")
$check = $json | ConvertFrom-Json
if ($check.version -ne $Version -or $check.hash -ne $hash -or $check.url -ne "$base/$zip") { throw 'bucket\foton.json was not updated as expected; edit it by hand.' }
[IO.File]::WriteAllText($path, $json, (New-Object System.Text.UTF8Encoding $false))
"bucket\foton.json now points at $zip ($hash)"
