# Install the bash-rs prebuilt binary from GitHub Releases (Windows).
#   irm https://raw.githubusercontent.com/maestrojeong/bash-rs-mcp/main/install.ps1 | iex
# Env: BASHRS_VERSION (default: latest), BASHRS_BIN_DIR (default: %LOCALAPPDATA%\bash-rs\bin)
$ErrorActionPreference = "Stop"

$Repo = "maestrojeong/bash-rs-mcp"
$Version = if ($env:BASHRS_VERSION) { $env:BASHRS_VERSION } else { "latest" }

$Arch = if ([System.Environment]::Is64BitOperatingSystem) { "x64" } else { $null }
if ($Arch -ne "x64") {
    Write-Error "Unsupported architecture. Build from source instead:`n  cargo install --git https://github.com/$Repo bashrs-mcp"
    exit 1
}
$Asset = "bash-rs-windows-x64.exe"

if ($Version -eq "latest") {
    $Url = "https://github.com/$Repo/releases/latest/download/$Asset"
} else {
    $Url = "https://github.com/$Repo/releases/download/$Version/$Asset"
}

$Dest = if ($env:BASHRS_BIN_DIR) { $env:BASHRS_BIN_DIR } else { Join-Path $env:LOCALAPPDATA "bash-rs\bin" }
New-Item -ItemType Directory -Force -Path $Dest | Out-Null

$Target = Join-Path $Dest "bash-rs.exe"
Write-Host "Downloading $Asset ($Version) -> $Target"
Invoke-WebRequest -Uri $Url -OutFile $Target -UseBasicParsing

Write-Host "Installed: $Target"

$PathEntries = $env:Path -split ";"
if ($PathEntries -contains $Dest) {
    Write-Host "Run: bash-rs --help"
} else {
    Write-Host "Add to PATH (current user):"
    Write-Host "  setx PATH `"$Dest;`$env:Path`""
    Write-Host "Then open a new terminal and run: bash-rs --help"
}

Write-Host ""
Write-Host "Note: bash-rs runs commands through Git for Windows' bash." -ForegroundColor Yellow
Write-Host "Install Git for Windows if it is not already present: https://git-scm.com/download/win"
