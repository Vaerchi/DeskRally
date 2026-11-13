#Requires -Version 5.1
# Filesystem transaction tests with signature, process and shortcut seams mocked.
# Registry operations are simulated via an in-memory hashtable; no actual machine
# registration occurs. Real Authenticode and COM installation are separate checks.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Join-Path $env:TEMP ('client-installer-tests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
$oldLocal = $env:LOCALAPPDATA
$oldRoaming = $env:APPDATA

# ── Registry simulation ────────────────────────────────────────────────────────
# Intercepts HKCU:\ paths and simulates key/value/type storage in memory.
# Filesystem paths are delegated to real cmdlets.
# $global:DeskRallyRegistry   : path -> @{ valueName = value }
# $global:DeskRallyRegistryKinds : "path||name" -> [RegistryValueKind]
$global:DeskRallyRegistry = @{}
$global:DeskRallyRegistryKinds = @{}

function Test-Path {
    [CmdletBinding()]
    param([string]$LiteralPath = '', [string]$Path = '', [string]$PathType = '')
    $p = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($p -like 'HKCU:\*') { return $global:DeskRallyRegistry.ContainsKey($p) }
    $splat = @{}
    if ($PathType) { $splat.PathType = $PathType }
    if ($LiteralPath) { Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath @splat }
    else { Microsoft.PowerShell.Management\Test-Path -Path $Path @splat }
}
function New-Item {
    [CmdletBinding()]
    param([string]$ItemType = '', [string]$Path = '', [string]$LiteralPath = '', [switch]$Force)
    $p = if ($LiteralPath) { $LiteralPath } else { $Path }
    if ($p -like 'HKCU:\*') {
        if (-not $global:DeskRallyRegistry.ContainsKey($p)) { $global:DeskRallyRegistry[$p] = @{} }
        return [pscustomobject]@{}
    }
    $splat = @{ Force = $Force.IsPresent }
    if ($ItemType) { $splat.ItemType = $ItemType }
    if ($Path) { $splat.Path = $Path }
    if ($LiteralPath) { $splat.LiteralPath = $LiteralPath }
    Microsoft.PowerShell.Management\New-Item @splat
}
function Get-Item {
    [CmdletBinding()]
    param([string]$LiteralPath = '', [switch]$Force)
    if ($LiteralPath -like 'HKCU:\*') {
        if (-not $global:DeskRallyRegistry.ContainsKey($LiteralPath)) { return $null }
        $obj = [pscustomobject]@{ PSPath = $LiteralPath; PSChildName = ($LiteralPath -split '\\')[-1] }
        $obj | Add-Member ScriptMethod GetValueNames {
            @($global:DeskRallyRegistry[$this.PSPath].Keys)
        }
        $obj | Add-Member ScriptMethod GetValueKind {
            param($n)
            $k = "$($this.PSPath)||$n"
            if ($global:DeskRallyRegistryKinds.ContainsKey($k)) { $global:DeskRallyRegistryKinds[$k] }
            else { [Microsoft.Win32.RegistryValueKind]::String }
        }
        $obj | Add-Member ScriptMethod GetValue {
            param($n, $def, $opts)
            $d = $global:DeskRallyRegistry[$this.PSPath]
            if ($d -and $d.ContainsKey($n)) { $d[$n] } else { $def }
        }
        return $obj
    }
    Microsoft.PowerShell.Management\Get-Item -LiteralPath $LiteralPath -Force:$Force
}
function Get-ChildItem {
    [CmdletBinding()]
    param([string]$LiteralPath = '')
    if ($LiteralPath -like 'HKCU:\*') {
        $prefix = "$LiteralPath\"
        $children = @($global:DeskRallyRegistry.Keys | Where-Object {
            $_ -like "$prefix*" -and ($_.Substring($prefix.Length) -notmatch '\\')
        })
        return $children | ForEach-Object {
            [pscustomobject]@{ PSPath = $_; PSChildName = ($_ -split '\\')[-1] }
        }
    }
    Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $LiteralPath
}
function Set-ItemProperty {
    [CmdletBinding()]
    param([string]$LiteralPath = '', [string]$Name = '', $Value)
    if ($LiteralPath -like 'HKCU:\*') {
        if (-not $global:DeskRallyRegistry.ContainsKey($LiteralPath)) {
            $global:DeskRallyRegistry[$LiteralPath] = @{}
        }
        $global:DeskRallyRegistry[$LiteralPath][$Name] = $Value
        # Injection fires exactly once, not again during rollback restore.
        if ($global:DeskRallyInstallerCase -like 'protocol-rollback-*' -and
            $LiteralPath -like '*\shell\open\command' -and
            -not $global:DeskRallyInstallerInjected) {
            $global:DeskRallyInstallerInjected = $true
            throw 'Injected protocol write failure'
        }
        return
    }
    Microsoft.PowerShell.Management\Set-ItemProperty -LiteralPath $LiteralPath -Name $Name -Value $Value
}
function Get-ItemProperty {
    [CmdletBinding()]
    param([string]$LiteralPath = '')
    if ($LiteralPath -like 'HKCU:\*') {
        if ($global:DeskRallyRegistry.ContainsKey($LiteralPath)) {
            return [pscustomobject]$global:DeskRallyRegistry[$LiteralPath]
        }
        throw "Simulated registry key not found: $LiteralPath"
    }
    Microsoft.PowerShell.Management\Get-ItemProperty -LiteralPath $LiteralPath
}
function New-ItemProperty {
    [CmdletBinding()]
    param([string]$LiteralPath = '', [string]$Name = '', $Value, $PropertyType, [switch]$Force)
    if ($LiteralPath -like 'HKCU:\*') {
        if (-not $global:DeskRallyRegistry.ContainsKey($LiteralPath)) {
            $global:DeskRallyRegistry[$LiteralPath] = @{}
        }
        $global:DeskRallyRegistry[$LiteralPath][$Name] = $Value
        if ($null -ne $PropertyType) {
            $global:DeskRallyRegistryKinds["$LiteralPath||$Name"] = $PropertyType
        }
        return [pscustomobject]@{}
    }
    Microsoft.PowerShell.Management\New-ItemProperty -LiteralPath $LiteralPath -Name $Name -Value $Value -PropertyType $PropertyType -Force:$Force
}
function Remove-Item {
    [CmdletBinding()]
    param([string]$LiteralPath = '', [switch]$Recurse, [switch]$Force)
    if ($LiteralPath -like 'HKCU:\*') {
        # Match exact key or validated descendants only.
        $keys = @($global:DeskRallyRegistry.Keys | Where-Object { $_ -eq $LiteralPath -or $_ -like "$LiteralPath\*" })
        foreach ($k in $keys) {
            $global:DeskRallyRegistry.Remove($k)
            $kindKeys = @($global:DeskRallyRegistryKinds.Keys | Where-Object { $_ -like "$k||*" })
            foreach ($kk in $kindKeys) { $global:DeskRallyRegistryKinds.Remove($kk) }
        }
        return
    }
    Microsoft.PowerShell.Management\Remove-Item -LiteralPath $LiteralPath -Force:$Force
}

# ── Existing seam mocks ────────────────────────────────────────────────────────
function Get-AuthenticodeSignature([string]$LiteralPath) {
    $status = 'Valid'
    if ($global:DeskRallyInstallerCase -eq 'bad-signature' -or
        ($global:DeskRallyInstallerCase -like 'installed-verify-*' -and $LiteralPath -eq $global:DeskRallyInstallerTarget)) {
        $status = 'NotSigned'; $global:DeskRallyInstallerInjected = $true
    }
    $timestamp = [pscustomobject]@{Subject='Test timestamp'}
    if ($global:DeskRallyInstallerCase -eq 'missing-timestamp') {
        $timestamp = $null; $global:DeskRallyInstallerInjected = $true
    }
    [pscustomobject]@{ Status=$status; SignerCertificate=[pscustomobject]@{Subject='CN=Edgar Nuckols, O=Edgar Nuckols, L=Orlando, S=fl, C=US'}; TimeStamperCertificate=$timestamp }
}
function Get-Process([string]$Name) { }
function Copy-Item([string]$LiteralPath, [string]$Destination, [switch]$Force) {
    Microsoft.PowerShell.Management\Copy-Item -LiteralPath $LiteralPath -Destination $Destination -Force:$Force
    if ($global:DeskRallyInstallerCase -eq 'stage-corrupt' -and (Split-Path -Leaf $Destination) -like 'stage-*.exe') {
        [IO.File]::WriteAllText($Destination, 'corrupted stage'); $global:DeskRallyInstallerInjected = $true
    }
}
function New-Object([string]$ComObject) {
    if ($ComObject -ne 'WScript.Shell') { throw 'Unexpected COM request' }
    $obj = [pscustomobject]@{ Fail=($global:DeskRallyInstallerCase -like 'shortcut-*') }
    $obj | Add-Member ScriptMethod CreateShortcut {
        param($path)
        $link = [pscustomobject]@{Path=$path;Fail=$this.Fail;TargetPath='';WorkingDirectory='';Description=''}
        $link | Add-Member ScriptMethod Save {
            [IO.File]::WriteAllText($this.Path, 'new shortcut ' + $this.TargetPath)
            if ($this.Fail) { $global:DeskRallyInstallerInjected = $true; throw 'Injected shortcut save failure' }
        }
        return $link
    }
    return $obj
}
try {
    $allCases = @(
        'fresh','update','bad-hash','bad-signature','missing-timestamp','active-app-lock','stage-corrupt',
        'installed-verify-update','installed-verify-fresh','shortcut-update','shortcut-fresh',
        'protocol-rollback-update','protocol-rollback-fresh',
        'extra-values-update','protocol-rollback-extra'
    )
    foreach ($global:DeskRallyInstallerCase in $allCases) {
        $global:DeskRallyInstallerInjected = $false
        $global:DeskRallyRegistry = @{}
        $global:DeskRallyRegistryKinds = @{}
        $base = Join-Path $root $global:DeskRallyInstallerCase
        $package = Join-Path $base 'package with spaces'
        $env:LOCALAPPDATA = Join-Path $base 'Local'
        $env:APPDATA = Join-Path $base 'Roaming'
        $global:DeskRallyInstallerTarget = Join-Path $env:LOCALAPPDATA 'Programs\DeskRally Client\DeskRallyClient.exe'
        $shortcut = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\DeskRally.lnk'
        $profile = Join-Path $env:LOCALAPPDATA 'DeskRally Client\Profile\preserve.txt'
        foreach ($folder in @($package,(Split-Path -Parent $profile),(Split-Path -Parent $shortcut))) {
            Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path $folder -Force | Out-Null
        }
        [IO.File]::WriteAllText($profile,'profile remains unchanged')
        $source = Join-Path $package 'DeskRallyClient.exe'
        [IO.File]::WriteAllText($source,'new unsigned test-only fixture')
        $newHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
        $hash = $newHash
        if ($global:DeskRallyInstallerCase -eq 'bad-hash') { $hash = '0' * 64 }
        @{sha256=$hash} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $package 'release-manifest.json') -Encoding UTF8
        $freshCases = @('fresh','installed-verify-fresh','shortcut-fresh','protocol-rollback-fresh')
        $existing = $global:DeskRallyInstallerCase -notin $freshCases
        if ($existing) {
            Microsoft.PowerShell.Management\New-Item -ItemType Directory -Path (Split-Path -Parent $global:DeskRallyInstallerTarget) -Force | Out-Null
            [IO.File]::WriteAllText($global:DeskRallyInstallerTarget,'old executable fixture')
            [IO.File]::WriteAllText($shortcut,'old shortcut fixture')
            $oldHash = (Get-FileHash -LiteralPath $global:DeskRallyInstallerTarget -Algorithm SHA256).Hash
        }

        # Pre-populate registry for protocol-rollback-update: full existing registration.
        if ($global:DeskRallyInstallerCase -eq 'protocol-rollback-update') {
            $bk = 'HKCU:\Software\Classes\deskrally-client'
            $global:DeskRallyRegistry[$bk] = @{ '(default)' = 'URL:DeskRally Client Protocol'; 'URL Protocol' = '' }
            $global:DeskRallyRegistry["$bk\shell"] = @{}
            $global:DeskRallyRegistry["$bk\shell\open"] = @{}
            $global:DeskRallyRegistry["$bk\shell\open\command"] = @{ '(default)' = '"old\DeskRallyClient.exe" "%1"' }
        }

        # Pre-populate for extra-values-update and protocol-rollback-extra:
        # base key carries ExpandString value and there is an extra child key,
        # so we can verify these survive a successful upgrade and are fully restored on rollback.
        if ($global:DeskRallyInstallerCase -in @('extra-values-update','protocol-rollback-extra')) {
            $bk = 'HKCU:\Software\Classes\deskrally-client'
            $global:DeskRallyRegistry[$bk] = @{
                '(default)'   = 'URL:DeskRally Client Protocol'
                'URL Protocol' = ''
                'ExtraExpand'  = '%SystemRoot%\DeskRally'
            }
            $global:DeskRallyRegistryKinds["$bk||ExtraExpand"] = [Microsoft.Win32.RegistryValueKind]::ExpandString
            $global:DeskRallyRegistry["$bk\extra-child"] = @{ 'ChildVal' = 'extra child value' }
        }

        $failed = $false
        $failureMessage = ""
        $appLock = $null
        $lockPath = Join-Path (Split-Path -Parent $global:DeskRallyInstallerTarget) 'running.lock'
        if ($global:DeskRallyInstallerCase -eq 'active-app-lock') {
            $appLock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            $global:DeskRallyInstallerInjected = $true
        }
        try { & (Join-Path $PSScriptRoot 'install-client.ps1') -SourceDir $package | Out-Null }
        catch { $failed = $true; $failureMessage = $_.Exception.Message }
        finally { if ($null -ne $appLock) { $appLock.Dispose() } }
        if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $lockPath) {
            $releasedLock = [IO.File]::Open($lockPath, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            $releasedLock.Dispose()
        }
        $wantFailure = $global:DeskRallyInstallerCase -notin @('fresh','update','extra-values-update')
        if ($failed -ne $wantFailure) { throw "Unexpected outcome for $global:DeskRallyInstallerCase : $failureMessage" }
        if ($global:DeskRallyInstallerCase -eq 'bad-hash' -and $failureMessage -ne 'Release hash mismatch.') { throw 'Wrong bad-hash failure' }
        if ($global:DeskRallyInstallerCase -notin @('fresh','update','bad-hash','extra-values-update') -and -not $global:DeskRallyInstallerInjected) {
            throw "Failure seam was not reached: $global:DeskRallyInstallerCase"
        }
        if ($wantFailure -and $existing) {
            if ((Get-FileHash -LiteralPath $global:DeskRallyInstallerTarget -Algorithm SHA256).Hash -ne $oldHash) { throw 'Old executable not restored' }
            if ([IO.File]::ReadAllText($shortcut) -ne 'old shortcut fixture') { throw 'Old shortcut not restored' }
        } elseif ($wantFailure) {
            if ((Microsoft.PowerShell.Management\Test-Path -LiteralPath $global:DeskRallyInstallerTarget) -or (Microsoft.PowerShell.Management\Test-Path -LiteralPath $shortcut)) { throw 'Failed fresh install left installed files' }
        } else {
            if ((Get-FileHash -LiteralPath $global:DeskRallyInstallerTarget -Algorithm SHA256).Hash -ne $newHash) { throw 'New executable mismatch' }
            if ([IO.File]::ReadAllText($shortcut) -ne ('new shortcut ' + $global:DeskRallyInstallerTarget)) { throw 'New shortcut mismatch' }
        }
        # Verify protocol registration on success
        if (-not $wantFailure) {
            $cmdKey = 'HKCU:\Software\Classes\deskrally-client\shell\open\command'
            if (-not $global:DeskRallyRegistry.ContainsKey($cmdKey)) { throw 'Protocol command key not registered' }
            $expectedCmd = "`"$($global:DeskRallyInstallerTarget)`" `"%1`""
            if ($global:DeskRallyRegistry[$cmdKey]['(default)'] -ne $expectedCmd) { throw 'Protocol command value mismatch' }
        }
        # Verify extra values preserved on successful upgrade.
        if ($global:DeskRallyInstallerCase -eq 'extra-values-update') {
            $bk = 'HKCU:\Software\Classes\deskrally-client'
            if ($global:DeskRallyRegistry[$bk]['ExtraExpand'] -ne '%SystemRoot%\DeskRally') {
                throw 'ExpandString extra value lost on upgrade'
            }
            if (-not $global:DeskRallyRegistry.ContainsKey("$bk\extra-child") -or
                $global:DeskRallyRegistry["$bk\extra-child"]['ChildVal'] -ne 'extra child value') {
                throw 'Extra child key lost on upgrade'
            }
        }
        # Verify protocol rollback cleaned up or fully restored.
        if ($global:DeskRallyInstallerCase -like 'protocol-rollback-*') {
            $baseKey = 'HKCU:\Software\Classes\deskrally-client'
            if ($global:DeskRallyInstallerCase -eq 'protocol-rollback-fresh') {
                $leaking = @($global:DeskRallyRegistry.Keys | Where-Object { $_ -eq $baseKey -or $_ -like "$baseKey\*" })
                if ($leaking.Count -gt 0) { throw 'Protocol registry not cleaned up after rollback (fresh)' }
            }
            if ($global:DeskRallyInstallerCase -eq 'protocol-rollback-update') {
                $cmdKey = "$baseKey\shell\open\command"
                if (-not $global:DeskRallyRegistry.ContainsKey($cmdKey)) { throw 'Old protocol command key not restored' }
                $restored = $global:DeskRallyRegistry[$cmdKey]['(default)']
                if ($restored -ne '"old\DeskRallyClient.exe" "%1"') { throw "Old protocol command value not restored: $restored" }
            }
            if ($global:DeskRallyInstallerCase -eq 'protocol-rollback-extra') {
                # Extra values and child key must be restored; intermediate keys must not leak.
                if ($global:DeskRallyRegistry[$baseKey]['ExtraExpand'] -ne '%SystemRoot%\DeskRally') {
                    throw 'ExpandString extra value not restored after rollback'
                }
                $kindKey = "$baseKey||ExtraExpand"
                if ($global:DeskRallyRegistryKinds[$kindKey] -ne [Microsoft.Win32.RegistryValueKind]::ExpandString) {
                    throw 'ExpandString kind not preserved through rollback'
                }
                if (-not $global:DeskRallyRegistry.ContainsKey("$baseKey\extra-child") -or
                    $global:DeskRallyRegistry["$baseKey\extra-child"]['ChildVal'] -ne 'extra child value') {
                    throw 'Extra child key not restored after rollback'
                }
                # shell/open/command keys created during the failed write must be gone.
                if ($global:DeskRallyRegistry.ContainsKey("$baseKey\shell\open\command")) {
                    throw 'Partially-written command key leaked after rollback'
                }
            }
        }
        if ([IO.File]::ReadAllText($profile) -ne 'profile remains unchanged') { throw 'Profile changed' }
        Write-Output "PASS $global:DeskRallyInstallerCase"
    }
} finally { $env:LOCALAPPDATA=$oldLocal; $env:APPDATA=$oldRoaming }
Write-Output "15 installer transaction checks passed; retained fixtures: $root"
