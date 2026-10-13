[CmdletBinding()]
param(
    [string]$Distribution = ""
)

$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
    Write-Error "smoke: $Message"
    exit 1
}

if ($env:OS -ne "Windows_NT") {
    Fail "this launcher is for Windows; run ./scripts/smoke.sh on Linux or macOS"
}

$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
if (-not $wsl) {
    Fail "WSL2 is unavailable; follow docs/setup.md"
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$wslBase = @()
if ($Distribution) {
    $wslBase += @("--distribution", $Distribution)
}

$wslPathOutput = & $wsl.Source @wslBase -- wslpath -a -u $repoRoot
if ($LASTEXITCODE -ne 0) {
    Fail "could not translate the repository path into WSL"
}
$wslRepo = ($wslPathOutput | Select-Object -Last 1).Trim()

& $wsl.Source @wslBase --cd $wslRepo -- bash ./scripts/smoke.sh
exit $LASTEXITCODE
