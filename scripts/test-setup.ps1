<# Local native helper/filesystem tests. No MSI installation, UAC dialog or production access. #>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$target = Join-Path $repo 'target/setup-tests'
New-Item -ItemType Directory -Force -Path $target | Out-Null
$src = Join-Path $repo 'packaging/setup'

# BAKED fake values (the existing tests).
$bakedDir = Join-Path $target 'baked'
New-Item -ItemType Directory -Force -Path $bakedDir | Out-Null
$header = @'
#pragma once
#define SETUP_CONTROL_PLANE_URL L"https://support.example.invalid/cp"
#define SETUP_SIGNALING_URL L"wss://support.example.invalid/ws"
#define SETUP_GRANT_ISSUER_PUBKEY L"0000000000000000000000000000000000000000000000000000000000000000"
#define SETUP_MSI_SHA256 L"0000000000000000000000000000000000000000000000000000000000000000"
'@
[IO.File]::WriteAllText((Join-Path $bakedDir 'setup_config.h'), $header, [Text.Encoding]::ASCII)

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$vsRoot = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsRoot) { throw 'MSVC build tools not found.' }
$dev = Join-Path $vsRoot 'VC/Auxiliary/Build/vcvarsall.bat'

# docs/48 C: the shared deployment-pass vectors, as a tab-separated stream for the C++ test
# (test_pass_vectors.cpp documents the format). Values never contain tabs or newlines.
# System.Text.Json, NOT ConvertFrom-Json: the latter turns ISO-8601 strings into DateTime values,
# so "now" and the date fields would reach the test re-formatted.
$doc = [Text.Json.JsonDocument]::Parse([IO.File]::ReadAllText((Join-Path $repo 'control-plane/testdata/deployment-pass-vectors.json')))
$root = $doc.RootElement
$rootPub = $root.GetProperty('root_pubkey').GetString()
$testScalar = $root.GetProperty('test_root_private_scalar_TEST_ONLY').GetString()
$tsv = [Collections.Generic.List[string]]::new()
$tsv.Add("R`t$rootPub")
foreach ($v in $root.GetProperty('vectors').EnumerateArray()) {
    $get = { param($n) $p = [Text.Json.JsonElement]::new(); if ($v.TryGetProperty($n, [ref]$p)) { $p.GetString() } else { $null } }
    $pk = & $get 'pubkey'; if (-not $pk) { $pk = '-' }
    $tsv.Add(('V', (& $get 'name'), (& $get 'kind'), $pk, (& $get 'envelope_b64'), (& $get 'now'), (& $get 'expect')) -join "`t")
    $fields = [Text.Json.JsonElement]::new()
    if ($v.TryGetProperty('fields', [ref]$fields)) {
        foreach ($p in $fields.EnumerateObject()) { $tsv.Add(('F', $p.Name, $p.Value.GetString()) -join "`t") }
    }
}
$vectorTsv = Join-Path $target 'pass-vectors.tsv'
[IO.File]::WriteAllText($vectorTsv, (($tsv -join "`n") + "`n"), [Text.UTF8Encoding]::new($false))

# PASS mode, keyed to the vectors' TEST root (test_pass_setup signs with the matching scalar).
$passDir = Join-Path $target 'pass'
New-Item -ItemType Directory -Force -Path $passDir | Out-Null
[IO.File]::WriteAllText((Join-Path $passDir 'setup_config.h'), "#pragma once`n#define SETUP_MODE_PASS 1`n#define SETUP_PASS_ROOT_KEY `"$rootPub`"`n", [Text.Encoding]::ASCII)

function Invoke-Native([string]$name, [string]$configDir, [string]$runArgs, [switch]$CompileMustFail) {
    $source = Join-Path $src "$name.cpp"
    $outDir = Join-Path $target ([IO.Path]::GetFileName($configDir))
    $exe = Join-Path $outDir "$name.exe"
    $cmd = Join-Path $outDir "$name.cmd"
    $cl = 'cl.exe /nologo /MT /EHsc /std:c++17 /W4 /WX /O2 /I"{0}" /I"{1}" "{2}" /Fo"{3}" /link bcrypt.lib shell32.lib ole32.lib user32.lib advapi32.lib /SUBSYSTEM:CONSOLE /OUT:"{4}"' -f $configDir, $src, $source, (Join-Path $outDir "$name.obj"), $exe
    if ($CompileMustFail) {
        $lines = @('@echo off', ('call "{0}" x64 >nul' -f $dev), "$cl >nul", 'exit /b %errorlevel%')
    } else {
        $lines = @('@echo off', ('call "{0}" x64 >nul' -f $dev), 'if errorlevel 1 exit /b %errorlevel%', $cl,
            'if errorlevel 1 exit /b %errorlevel%', ('"{0}" {1}' -f $exe, $runArgs), 'exit /b %errorlevel%')
    }
    [IO.File]::WriteAllLines($cmd, $lines, [Text.Encoding]::ASCII)
    & $env:ComSpec /d /c $cmd
    if ($CompileMustFail) {
        if ($LASTEXITCODE -eq 0) { throw "$name compiled with a mixed configuration in $configDir; the #error guards are not firing" }
        Write-Host "PASS $name refuses to compile with the mixed configuration in $([IO.Path]::GetFileName($configDir))"
    } elseif ($LASTEXITCODE -ne 0) { throw "$name failed: $LASTEXITCODE" }
}

Invoke-Native 'test_helpers' $bakedDir ''
Invoke-Native 'test_platform' $bakedDir ''
Invoke-Native 'test_pass_vectors' $bakedDir ('"{0}"' -f $vectorTsv)
Invoke-Native 'test_pass_setup' $passDir $testScalar

# docs/48 "Principles" 1: a mixed configuration must not compile, in either direction.
foreach ($mixed in @(
        @{ name = 'mixed-pass-with-url'; text = "#pragma once`n#define SETUP_MODE_PASS 1`n#define SETUP_PASS_ROOT_KEY `"$rootPub`"`n#define SETUP_CONTROL_PLANE_URL L`"https://x.invalid/cp`"`n" },
        @{ name = 'mixed-baked-with-key'; text = ([IO.File]::ReadAllText((Join-Path $bakedDir 'setup_config.h')) + "`n#define SETUP_PASS_ROOT_KEY `"$rootPub`"`n") })) {
    $dir = Join-Path $target $mixed.name
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    [IO.File]::WriteAllText((Join-Path $dir 'setup_config.h'), $mixed.text, [Text.Encoding]::ASCII)
    Invoke-Native 'test_platform' $dir '' -CompileMustFail
}
# The mixed-configuration compiles above fail on purpose; do not leak their exit code to callers.
$global:LASTEXITCODE = 0
