<#
.SYNOPSIS
    Prove test-msi-contents.ps1's self-contained-package check can fail (docs/48 C, slice 5).
.DESCRIPTION
    Copies a real MSI twice into a temporary folder and breaks each copy in one way that a generic
    Setup (which stages ONLY the .msi) could not install:
      1. one File row marked Noncompressed (a loose external file, cabinet still embedded);
      2. the package default flipped to uncompressed, with no per-file Compressed bit.
    The unmodified MSI must pass; each broken copy must be refused. Read-only on the input MSI.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Msi)
$ErrorActionPreference = 'Stop'
$check = Join-Path $PSScriptRoot 'test-msi-contents.ps1'
$work = Join-Path ([IO.Path]::GetTempPath()) ("msi-selftest-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null

function Expect([string]$path, [bool]$pass, [string]$what) {
    $ok = $true
    try { & $check -Msi $path *> $null } catch { $ok = $false }
    if ($ok -ne $pass) { throw "self-test failed: $what (expected $(if ($pass) { 'pass' } else { 'refusal' }))" }
    Write-Host "[ok] $what"
}

function Edit-Msi([string]$path, [scriptblock]$change) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    try {
        $db = $installer.OpenDatabase($path, 1)  # msiOpenDatabaseModeTransact
        & $change $db
        $db.Commit()
        [void][Runtime.InteropServices.Marshal]::ReleaseComObject($db)
    } finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer) }
}

try {
    Expect $Msi $true 'the unmodified MSI passes'

    $loose = Join-Path $work 'loose-file.msi'
    Copy-Item -LiteralPath $Msi -Destination $loose
    Edit-Msi $loose {
        param($db)
        $view = $db.OpenView('SELECT `File`, `Attributes` FROM `File`')
        [void]$view.Execute()
        $rec = $view.Fetch()
        $rec.IntegerData(2) = (($rec.IntegerData(2) -band (-bnot 16384)) -bor 8192)
        $view.Modify(2, $rec)  # msiViewModifyUpdate
        [void]$view.Close()
    }
    Expect $loose $false 'one file marked Noncompressed is refused'

    $uncompressed = Join-Path $work 'default-uncompressed.msi'
    Copy-Item -LiteralPath $Msi -Destination $uncompressed
    Edit-Msi $uncompressed {
        param($db)
        $view = $db.OpenView('SELECT `File`, `Attributes` FROM `File`')
        [void]$view.Execute()
        while ($rec = $view.Fetch()) {
            $rec.IntegerData(2) = ($rec.IntegerData(2) -band (-bnot 16384))
            $view.Modify(2, $rec)
        }
        [void]$view.Close()
        $si = $db.SummaryInformation(1)
        $si.Property(15) = ([int]$si.Property(15) -band (-bnot 2))
        $si.Persist()
    }
    Expect $uncompressed $false 'an uncompressed package default is refused'
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
