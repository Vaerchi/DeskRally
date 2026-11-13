# Build container-free server packages. Requires PowerShell 7, Go and Node on the BUILD machine.
[CmdletBinding()]
param(
    [ValidateSet('windows', 'linux')][string[]]$Platform = @('windows', 'linux'),
    [ValidateSet('amd64', 'arm64')][string]$Architecture = 'amd64',
    [string]$OutputDirectory = 'dist/native-server'
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$out = [IO.Path]::GetFullPath($OutputDirectory, $repo)
New-Item -ItemType Directory -Force $out | Out-Null
foreach ($os in ($Platform | Select-Object -Unique)) {
    $destination = Join-Path $out "deskrally-server-$os-$Architecture"
    $extension = if ($os -eq 'windows') { '.zip' } else { '.tar.gz' }
    if ((Test-Path -LiteralPath $destination) -or (Test-Path -LiteralPath "$destination$extension")) {
        throw "Output already exists for $os. Use a new OutputDirectory."
    }
}
# A Linux archive written by Windows tar carries no Unix permissions (NTFS has none), so the binaries arrived without
# their execute bit and the first step after unpacking failed (server-install acceptance, 2026-11-10). Write the
# tar.gz ourselves with explicit modes: 0755 for bin/* and *.sh launchers and every directory, 0644 for the rest.
function New-TarGz([string]$Source, [string]$Archive) {
    $root = Split-Path $Source -Leaf
    $base = (Resolve-Path -LiteralPath $Source).Path.TrimEnd('\', '/')
    $exec = [IO.UnixFileMode]493   # 0755
    $file = [IO.UnixFileMode]420   # 0644
    $out = [IO.File]::Create($Archive)
    try {
        $gz = [IO.Compression.GZipStream]::new($out, [IO.Compression.CompressionLevel]::Optimal)
        $tar = [Formats.Tar.TarWriter]::new($gz, [Formats.Tar.TarEntryFormat]::Pax, $false)
        try {
            $top = [Formats.Tar.PaxTarEntry]::new([Formats.Tar.TarEntryType]::Directory, "$root/")
            $top.Mode = $exec
            $tar.WriteEntry($top)
            foreach ($item in (Get-ChildItem -LiteralPath $base -Recurse -Force | Sort-Object FullName)) {
                $rel = $item.FullName.Substring($base.Length + 1).Replace('\', '/')
                if ($item.PSIsContainer) {
                    $entry = [Formats.Tar.PaxTarEntry]::new([Formats.Tar.TarEntryType]::Directory, "$root/$rel/")
                    $entry.Mode = $exec
                    $tar.WriteEntry($entry)
                    continue
                }
                $entry = [Formats.Tar.PaxTarEntry]::new([Formats.Tar.TarEntryType]::RegularFile, "$root/$rel")
                $entry.Mode = if ($rel -like 'bin/*' -or $rel -like '*.sh') { $exec } else { $file }
                $stream = [IO.File]::OpenRead($item.FullName)
                try { $entry.DataStream = $stream; $tar.WriteEntry($entry) } finally { $stream.Dispose() }
            }
        } finally { $tar.Dispose(); $gz.Dispose() }
    } finally { $out.Dispose() }
}
function Invoke-Checked([string]$Command, [string[]]$Arguments) {
    & $Command @Arguments
    if ($LASTEXITCODE -ne 0) { throw "$Command failed ($LASTEXITCODE)" }
}
# Do not bake this build machine's deployment endpoints into a distributable viewer.
$savedVite = @{}
Get-ChildItem Env:VITE_* | ForEach-Object { $savedVite[$_.Name] = $_.Value; Remove-Item "Env:$($_.Name)" }
$savedGo = @{ GOOS=$env:GOOS; GOARCH=$env:GOARCH; CGO_ENABLED=$env:CGO_ENABLED }
try {
    Push-Location "$repo/web/viewer"
    try { Invoke-Checked 'npm' @('ci'); Invoke-Checked 'npm' @('run', 'build') } finally { Pop-Location }
    foreach ($os in ($Platform | Select-Object -Unique)) {
        Write-Host "Building native $os/$Architecture server"
        $stage = Join-Path $out "deskrally-server-$os-$Architecture"
        if (Test-Path -LiteralPath $stage) { throw "Output already exists: $stage. Use a new OutputDirectory." }
        New-Item -ItemType Directory "$stage/bin", "$stage/viewer", "$stage/download" | Out-Null
        $env:GOOS = $os; $env:GOARCH = $Architecture; $env:CGO_ENABLED = '0'
        $suffix = if ($os -eq 'windows') { '.exe' } else { '' }
        foreach ($service in @(
            @{ Directory='control-plane'; Name='controlplane'; Package='./cmd/controlplane' },
            @{ Directory='server/signaling'; Name='signaling'; Package='.' },
            @{ Directory='server/relay'; Name='relay'; Package='.' }
        )) {
            Push-Location (Join-Path $repo $service.Directory)
            try { Invoke-Checked 'go' @('build', '-trimpath', '-o', "$stage/bin/$($service.Name)$suffix", $service.Package) } finally { Pop-Location }
        }
        Copy-Item "$repo/control-plane/migrations" $stage -Recurse
        Copy-Item "$repo/web/viewer/dist/*" "$stage/viewer" -Recurse
        Copy-Item "$repo/deploy/native/*" $stage -Recurse
        Copy-Item "$repo/docs/guides/native-server.md" "$stage/INSTALL.md"
        # The client guide (2b) fetches the MSI provisioning script from the server's own /download/agent/, as the Docker
        # package ships it. Without it a native server answered 404 there (server-install acceptance, 2026-11-10).
        New-Item -ItemType Directory "$stage/download/agent" | Out-Null
        Copy-Item "$repo/scripts/new-msi-provisioning.ps1" "$stage/download/agent/"
        $provHash = (Get-FileHash -LiteralPath "$stage/download/agent/new-msi-provisioning.ps1" -Algorithm SHA256).Hash.ToLowerInvariant()
        [IO.File]::WriteAllText("$stage/download/agent/new-msi-provisioning.ps1.sha256.txt", "$provHash  new-msi-provisioning.ps1`n")
        $sourceCommit = & git -C $repo rev-parse HEAD
        if ($LASTEXITCODE -ne 0) { throw 'Cannot determine source commit' }
        $dirtyFiles = & git -C $repo status --porcelain
        if ($LASTEXITCODE -ne 0) { throw 'Cannot determine source state' }
        @{
            source_commit = $sourceCommit.Trim()
            source_has_local_changes = [bool]$dirtyFiles
            platform = $os
            architecture = $Architecture
            deployment_status = 'native-preview'
        } | ConvertTo-Json | Set-Content -Encoding utf8NoBOM "$stage/BUILD.json"
        # Archives never contain a real operator config or credentials.
        if ($os -eq 'windows') {
            $archive = "$stage.zip"
            if (Test-Path -LiteralPath $archive) { throw "Archive already exists: $archive" }
            Compress-Archive -LiteralPath $stage -DestinationPath $archive
        } else {
            $archive = "$stage.tar.gz"
            if (Test-Path -LiteralPath $archive) { throw "Archive already exists: $archive" }
            New-TarGz -Source $stage -Archive $archive
        }
        $hash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $(Split-Path $archive -Leaf)" | Set-Content -Encoding utf8NoBOM "$archive.sha256.txt"
        Write-Host "Built $archive"
    }
} finally {
    foreach ($key in $savedGo.Keys) { [Environment]::SetEnvironmentVariable($key, $savedGo[$key], 'Process') }
    Get-ChildItem Env:VITE_* | Remove-Item
    foreach ($key in $savedVite.Keys) { [Environment]::SetEnvironmentVariable($key, $savedVite[$key], 'Process') }
}
