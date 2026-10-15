[CmdletBinding()]
param(
    [string]$Distribution = "",
    [switch]$CheckOnly,
    [switch]$InstallUpstreams,
    [switch]$InstallCoreTools
)

$ErrorActionPreference = "Stop"

function Fail([string]$Message) {
    Write-Error "bootstrap: $Message"
    exit 1
}

if ($env:OS -ne "Windows_NT") {
    Fail "this launcher is for Windows; run ./scripts/bootstrap.sh on Linux or macOS"
}

$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
if (-not $wsl) {
    Fail "WSL2 is required. Open an elevated PowerShell, run 'wsl --install -d Ubuntu-24.04', restart if requested, then rerun this script."
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$wslBase = @()
if ($Distribution) {
    $wslBase += @("--distribution", $Distribution)
}

$wslPathOutput = & $wsl.Source @wslBase -- wslpath -a -u $repoRoot
if ($LASTEXITCODE -ne 0) {
    Fail "could not translate the repository path into WSL; confirm that the selected distribution is running"
}
$wslRepo = ($wslPathOutput | Select-Object -Last 1).Trim()

if ($wslRepo.StartsWith("/mnt/")) {
    Write-Warning "This checkout is on the Windows-mounted filesystem. For faster and more reliable Git/worktree behavior, clone GATE under ~/src/GATE inside WSL."
}

$scriptArguments = @()
if ($CheckOnly) { $scriptArguments += "--check-only" }
if ($InstallUpstreams) { $scriptArguments += "--install-upstreams" }
if ($InstallCoreTools) { $scriptArguments += "--install-core-tools" }

Write-Host "bootstrap: launching GATE in WSL at $wslRepo"
& $wsl.Source @wslBase --cd $wslRepo -- bash ./scripts/bootstrap.sh @scriptArguments
exit $LASTEXITCODE
