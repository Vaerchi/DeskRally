# Run one native service in the foreground; also used by the Windows service wrapper.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('controlplane','signaling','relay','caddy')][string]$Service,
    [Parameter(ValueFromRemainingArguments)][string[]]$ServiceArguments
)
$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
$config = Join-Path $root "config/$Service.env"
if (!(Test-Path -LiteralPath $config)) { throw "Create $config from its .env.example before starting." }
$seen = @{}
foreach ($line in [IO.File]::ReadAllLines($config)) {
    if ($line -match '^\s*(#|$)') { continue }
    if ($line -notmatch '^([A-Z][A-Z0-9_]*)=(.*)$') { throw "Invalid config line in $config; use literal KEY=value (no quotes or export)." }
    $key = $Matches[1]; $value = $Matches[2]
    if ($seen.ContainsKey($key)) { throw "Duplicate setting $key in $config" }
    $seen[$key] = $true
    [Environment]::SetEnvironmentVariable($key, $value, 'Process')
}
$binary = Join-Path $root "bin/$Service.exe"
if (!(Test-Path -LiteralPath $binary)) { throw "Missing $binary" }
$defaults = switch ($Service) {
    'signaling' { @('-addr', '127.0.0.1:8080', '-relay', '127.0.0.1:9000') }
    'relay' { @('-tcp', '127.0.0.1:9000', '-ws', '127.0.0.1:9001') }
    'caddy' { @('run', '--config', (Join-Path $root 'Caddyfile'), '--adapter', 'caddyfile') }
    default { @() }
}
Push-Location $root
try {
    & $binary @defaults @ServiceArguments
    exit $LASTEXITCODE
} finally { Pop-Location }
