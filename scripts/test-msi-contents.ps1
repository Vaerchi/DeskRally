<# Read-only inspection of compiled MSI tables, not a .wxs text test. #>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Msi)
$ErrorActionPreference = 'Stop'
$installer = New-Object -ComObject WindowsInstaller.Installer
function Rows($db, $sql, $columns) {
    $view = $db.OpenView($sql)
    try {
        [void]$view.Execute()
        while ($record = $view.Fetch()) {
            $row = @()
            for ($i = 1; $i -le $columns; $i++) { $row += $record.StringData($i) }
            ,$row
        }
    } finally { [void]$view.Close() }
}
function Check($ok, $message) { if (-not $ok) { throw $message }; Write-Host "[ok] $message" }
try {
    $db = $installer.OpenDatabase((Resolve-Path -LiteralPath $Msi).Path, 0)
    # Component bitness alone does not make the package x64. An x86 package redirects
    # ProgramFiles64Folder to Program Files (x86), observed in the disposable VM.
    $summary = $db.SummaryInformation(0)
    Check (($summary.Property(7) -split ';')[0] -eq 'x64') 'Package summary declares x64 architecture'
    $seq = @{}
    Rows $db 'SELECT `Action`, `Sequence`, `Condition` FROM `InstallExecuteSequence`' 3 | ForEach-Object { $seq[$_[0]] = $_ }
    $configure = @(Rows $db 'SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`' 4 | Where-Object { $_[0] -eq 'ConfigureAgent' })
    Check ($configure.Count -eq 1) 'Exactly one ConfigureAgent action'
    # DLL + deferred + no impersonation + hide target, with checked/synchronous return.
    Check ([int]$configure[0][1] -eq (1 + 1024 + 2048 + 8192)) 'Provisioning is deferred SYSTEM DLL action with hidden data and checked return'
    Check ($configure[0][2] -eq 'AgentActions' -and $configure[0][3] -eq 'ConfigureAgent') 'Provisioning uses the embedded native bridge'
    Check ([int]$seq.ConfigureAgent[1] -gt [int]$seq.InstallFiles[1] -and [int]$seq.ConfigureAgent[1] -lt [int]$seq.InstallServices[1]) 'Provisioning runs after files, before service installation'
    Check ($seq.ConfigureAgent[2] -eq 'NOT REMOVE~="ALL"') 'Uninstall never provisions or enrolls'
    $services = @(Rows $db 'SELECT `Name`, `StartType` FROM `ServiceInstall`' 2)
    Check (@($services | Where-Object { $_[0] -eq 'RmtAgent' -and $_[1] -eq '2' }).Count -eq 1) 'RmtAgent is automatic-start'
    $control = @(Rows $db 'SELECT `Name`, `Event`, `Wait` FROM `ServiceControl`' 3)
    Check (@($control | Where-Object { $_[0] -eq 'RmtAgent' -and $_[1] -eq '163' -and $_[2] -eq '1' }).Count -eq 1) 'Service start/stop/uninstall are owned by Windows Installer'
    $properties = @{}
    Rows $db 'SELECT `Property`, `Value` FROM `Property`' 2 | ForEach-Object { $properties[$_[0]] = $_[1] }
    Check (($properties.SecureCustomProperties -split ';') -contains 'PROVISIONINGFILE') 'Provisioning path crosses elevation securely'
    Check (($properties.MsiHiddenProperties -split ';') -contains 'ConfigureAgent') 'Deferred data is hidden from MSI logging'
    # docs/48 C: Setup stages ONLY the .msi and verifies exactly its bytes, so the package must be
    # self-contained. An external cabinet would be read from beside the staged copy, unverified.
    $media = @(Rows $db 'SELECT `DiskId`, `Cabinet` FROM `Media`' 2)
    Check ($media.Count -ge 1 -and @($media | Where-Object { -not $_[1].StartsWith('#') }).Count -eq 0) 'Every cabinet is embedded in the MSI'
    # An embedded cabinet is not enough: a File row can still be stored uncompressed, i.e. as a
    # loose file beside the MSI. Effective storage = the file's own Compressed (16384) /
    # Noncompressed (8192) bit, else the package default (summary Word Count bit 2 = compressed).
    $defaultCompressed = ([int]$summary.Property(15) -band 2) -ne 0
    $loose = @(Rows $db 'SELECT `File`, `Attributes` FROM `File`' 2 | Where-Object {
        $attr = [int]$_[1]
        -not (($attr -band 16384) -or ($defaultCompressed -and -not ($attr -band 8192)))
    })
    Check ($loose.Count -eq 0) "Every file is stored inside the MSI (no loose external files; found: $(($loose | ForEach-Object { $_[0] }) -join ', '))"
# License texts travel with the binary (Apache-2.0 s4; MIT/BSD/ISC/Zlib notice clauses).
$fileNames = @(Rows $db 'SELECT `FileName` FROM `File`' 1 | ForEach-Object { ($_[0] -split '\|')[-1] })
foreach ($n in 'LICENSE.txt', 'NOTICE.txt', 'THIRD-PARTY-NOTICES.txt') {
    Check ($fileNames -contains $n) "The MSI installs $n"
}
} finally { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer) }
