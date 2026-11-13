#Requires -Version 5.1
[CmdletBinding()]
param([string]$SourceDir = "")
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ([string]::IsNullOrWhiteSpace($SourceDir)) { $SourceDir = $PSScriptRoot }
if ([string]::IsNullOrWhiteSpace($SourceDir)) { throw 'Cannot determine the client package directory.' }

$publisher = 'CN=Edgar Nuckols, O=Edgar Nuckols, L=Orlando, S=fl, C=US'
$manifest = Get-Content -LiteralPath (Join-Path $SourceDir 'release-manifest.json') -Raw | ConvertFrom-Json
$expected = [string]$manifest.sha256
if ($expected -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid release hash.' }
$source = Join-Path $SourceDir 'DeskRallyClient.exe'
$installDir = Join-Path $env:LOCALAPPDATA 'Programs\DeskRally Client'
$target = Join-Path $installDir 'DeskRallyClient.exe'
$shortcutPath = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\DeskRally.lnk'

$script:PROTOCOL_BASE = 'HKCU:\Software\Classes\deskrally-client'

function New-RegistryKeyIfAbsent {
    param([string]$KeyPath)
    if (-not (Test-Path -LiteralPath $KeyPath)) { $null = New-Item -Path $KeyPath }
}

# Captures all keys/values/types in the deskrally-client subtree so rollback can
# do a full type-faithful restore of whatever was there before.
function Get-ProtocolSnapshot {
    $snap = @{}
    $stack = [System.Collections.Generic.Stack[string]]::new()
    $stack.Push($script:PROTOCOL_BASE)
    while ($stack.Count -gt 0) {
        $path = $stack.Pop()
        $key = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
        if ($null -eq $key) {
            $snap[$path] = @{ Exists = $false; Values = @{} }
            continue
        }
        $values = @{}
        foreach ($name in $key.GetValueNames()) {
            $kind = $key.GetValueKind($name)
            # Preserve unexpanded form for REG_EXPAND_SZ so restore is exact.
            $data = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
            $values[$name] = @{ Kind = $kind; Data = $data }
        }
        $snap[$path] = @{ Exists = $true; Values = $values }
        $children = Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue
        foreach ($child in $children) { $stack.Push("$path\$($child.PSChildName)") }
    }
    return $snap
}

function Write-ProtocolUri {
    param([string]$ExePath)
    # Only create absent keys; never force-wipe an existing key's values.
    New-RegistryKeyIfAbsent $script:PROTOCOL_BASE
    Set-ItemProperty -LiteralPath $script:PROTOCOL_BASE -Name '(default)' -Value 'URL:DeskRally Client Protocol'
    Set-ItemProperty -LiteralPath $script:PROTOCOL_BASE -Name 'URL Protocol' -Value ''
    $shellPath = "$($script:PROTOCOL_BASE)\shell"
    New-RegistryKeyIfAbsent $shellPath
    $openPath = "$shellPath\open"
    New-RegistryKeyIfAbsent $openPath
    $cmdPath = "$openPath\command"
    New-RegistryKeyIfAbsent $cmdPath
    Set-ItemProperty -LiteralPath $cmdPath -Name '(default)' -Value "`"$ExePath`" `"%1`""
}

function Remove-ProtocolSubtree {
    # Limit recursive removal to exactly the deskrally-client key we own.
    $path = $script:PROTOCOL_BASE
    if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force }
}

function Restore-ProtocolSnapshot {
    param([hashtable]$Snapshot)
    Remove-ProtocolSubtree
    if ($null -eq $Snapshot) { return }
    # Sort so parent keys are created before children; then restore values with type.
    $sortedKeys = @($Snapshot.Keys | Where-Object { $Snapshot[$_].Exists } | Sort-Object)
    foreach ($keyPath in $sortedKeys) {
        New-RegistryKeyIfAbsent $keyPath
        foreach ($name in $Snapshot[$keyPath].Values.Keys) {
            $v = $Snapshot[$keyPath].Values[$name]
            $null = New-ItemProperty -LiteralPath $keyPath -Name $name -Value $v.Data -PropertyType $v.Kind -Force
        }
    }
}

function Assert-NoRedirect([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                throw "Refusing redirected destination: $current"
            }
        }
        $parent = Split-Path -Parent $current
        if ($parent -eq $current) { break }
        $current = $parent
    }
}
function Assert-Release([string]$Path) {
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $expected) { throw 'Release hash mismatch.' }
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -ne $publisher) {
        throw 'A valid DeskRally publisher signature is required.'
    }
    if ($null -eq $signature.TimeStamperCertificate) {
        throw 'A timestamped DeskRally publisher signature is required.'
    }
}

Assert-Release $source
if (Get-Process -Name DeskRallyClient -ErrorAction SilentlyContinue) {
    throw 'Close DeskRally Client before installing this update.'
}
Assert-NoRedirect $target
Assert-NoRedirect $shortcutPath
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
Assert-NoRedirect $target
# Shares the native client's lifetime barrier. Hold through the complete
# installer transaction so a new app window cannot start between checks/swap.
$lockPath = Join-Path $installDir 'running.lock'
Assert-NoRedirect $lockPath
$installLock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
try {
if (Get-Process -Name DeskRallyClient -ErrorAction SilentlyContinue) {
    throw 'Close DeskRally Client before installing this update.'
}
$stage = Join-Path $installDir ('stage-' + [guid]::NewGuid().ToString('N') + '.exe')
$backup = Join-Path $installDir ('previous-' + [guid]::NewGuid().ToString('N') + '.exe')
$oldHash = $null
if (Test-Path -LiteralPath $target) { $oldHash = (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash }
$shortcutBackup = Join-Path $installDir ('shortcut-' + [guid]::NewGuid().ToString('N') + '.lnk')
$shortcutHash = $null
if (Test-Path -LiteralPath $shortcutPath) {
    $shortcutHash = (Get-FileHash -LiteralPath $shortcutPath -Algorithm SHA256).Hash
    Copy-Item -LiteralPath $shortcutPath -Destination $shortcutBackup
    if ((Get-FileHash -LiteralPath $shortcutBackup -Algorithm SHA256).Hash -ne $shortcutHash) { throw 'Shortcut backup mismatch.' }
}
$protocolSnapshot = Get-ProtocolSnapshot
$replaced = $false
$shortcutAttempted = $false
$protocolAttempted = $false
try {
    Copy-Item -LiteralPath $source -Destination $stage
    Assert-Release $stage
    Assert-NoRedirect $target
    if (Test-Path -LiteralPath $target) {
        [IO.File]::Replace($stage, $target, $backup)
    } else {
        [IO.File]::Move($stage, $target)
    }
    $replaced = $true
    Assert-Release $target
    if ($oldHash -and (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $oldHash) {
        throw 'Previous executable backup mismatch.'
    }
    Assert-NoRedirect $shortcutPath
    New-Item -ItemType Directory -Path (Split-Path -Parent $shortcutPath) -Force | Out-Null
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($shortcutPath)
    $link.TargetPath = $target
    $link.WorkingDirectory = $installDir
    $link.Description = 'DeskRally desktop client'
    $shortcutAttempted = $true
    $link.Save()
    if (-not (Test-Path -LiteralPath $shortcutPath)) { throw 'Shortcut was not created.' }
    # Register per-user URL protocol; must be last so rollback order is clean.
    $protocolAttempted = $true
    Write-ProtocolUri -ExePath $target
} catch {
    $installFailure = $_
    try {
        # Restore protocol first: a failure in file rollback must not skip registry cleanup.
        if ($protocolAttempted) { Restore-ProtocolSnapshot -Snapshot $protocolSnapshot }
        Assert-NoRedirect $target
        if ($replaced) {
            $failed = Join-Path $installDir ('failed-' + [guid]::NewGuid().ToString('N') + '.exe')
            if ($oldHash) {
                if (-not (Test-Path -LiteralPath $backup) -or
                    (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ne $oldHash) {
                    throw 'Previous executable backup is unavailable or changed.'
                }
                if (Test-Path -LiteralPath $target) { [IO.File]::Replace($backup, $target, $failed) }
                else { [IO.File]::Move($backup, $target) }
                if ((Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -ne $oldHash) {
                    throw 'Restored executable hash mismatch.'
                }
            } elseif (Test-Path -LiteralPath $target) {
                # Preserve the failed candidate for diagnosis, but leave no installed executable.
                [IO.File]::Move($target, $failed)
            }
        }
        if ($shortcutAttempted) {
            Assert-NoRedirect $shortcutPath
            if ($shortcutHash) {
                Copy-Item -LiteralPath $shortcutBackup -Destination $shortcutPath -Force
                if ((Get-FileHash -LiteralPath $shortcutPath -Algorithm SHA256).Hash -ne $shortcutHash) {
                    throw 'Restored shortcut hash mismatch.'
                }
            } elseif (Test-Path -LiteralPath $shortcutPath) { Remove-Item -LiteralPath $shortcutPath -Force }
        }
    } catch {
        throw "Install failed: $($installFailure.Exception.Message). Rollback also failed: $($_.Exception.Message). Backups: $installDir"
    }
    throw $installFailure
} finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Force }
}

Write-Output "Installed DeskRally Client. Open DeskRally from the Start menu."
Write-Output "Executable: $target"
if (Test-Path -LiteralPath $backup) { Write-Output "Previous executable retained: $backup" }
Write-Output 'Login profile preserved. No service, startup task, or administrator access was added.'

} finally { $installLock.Dispose() }
