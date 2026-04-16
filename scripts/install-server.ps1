# VulnForge server bare-metal installer (Windows).
# Usage: Run PowerShell as Administrator and: .\install-server.ps1
# Produces: Windows service + bootstrap token + start instructions.

param(
    [string]$InstallDir = "C:\Program Files\VulnForge",
    [string]$DataDir    = "C:\ProgramData\VulnForge",
    [string]$PublicUrl  = "",
    [int]   $Port       = 3001
)

$ErrorActionPreference = "Stop"

function Log  { param($m) Write-Host "[install] $m" -ForegroundColor Cyan }
function Ok   { param($m) Write-Host "[ ok ]   $m" -ForegroundColor Green }
function Warn { param($m) Write-Host "[warn]   $m" -ForegroundColor Yellow }
function Die  { param($m) Write-Host "[fail]   $m" -ForegroundColor Red; exit 1 }

# ── Preflight ──
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrators")) {
    Die "Run PowerShell as Administrator."
}

try { $nodeVersion = (node -v) } catch { Die "Node.js not installed. Install Node >= 20 first." }
$nodeMajor = [int](($nodeVersion -replace 'v(\d+).*','$1'))
if ($nodeMajor -lt 20) { Die "Node $nodeMajor < 20. Upgrade required." }

Log "Node: $nodeVersion"
Log "Install dir: $InstallDir"
Log "Data dir:    $DataDir"

# ── Prompt for config ──
if ([string]::IsNullOrEmpty($PublicUrl)) {
    $PublicUrl = Read-Host "Public URL (e.g. https://vf.company.com)"
}
if ([string]::IsNullOrEmpty($PublicUrl)) { Die "Public URL required." }

# ── Dirs ──
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir    | Out-Null

# ── Copy payload ──
$PayloadDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$DistServer = Join-Path (Split-Path -Parent $PayloadDir) "dist-server"
if (-not (Test-Path $DistServer)) { Die "dist-server not found next to installer." }

Log "Copying payload..."
Copy-Item -Recurse -Force (Join-Path (Split-Path -Parent $PayloadDir) "dist-server")  $InstallDir
Copy-Item -Recurse -Force (Join-Path (Split-Path -Parent $PayloadDir) "plugins")      $InstallDir
Copy-Item          -Force (Join-Path (Split-Path -Parent $PayloadDir) "package.json") $InstallDir

Push-Location $InstallDir
Log "Installing production deps..."
& npm ci --omit=dev --ignore-scripts
Pop-Location

# ── Generate secrets ──
function RandomBase64 ($bytes) {
    $buf = New-Object byte[] $bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buf)
    return [Convert]::ToBase64String($buf)
}
function RandomHex ($bytes) {
    $buf = New-Object byte[] $bytes
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($buf)
    return -join ($buf | ForEach-Object { $_.ToString("x2") })
}

$JwtSecret       = RandomBase64 48
$BootstrapToken  = RandomHex 24
$DbPath          = Join-Path $DataDir "vulnforge.db"
$EnvPath         = Join-Path $DataDir ".env"

@"
VULNFORGE_MODE=server
VULNFORGE_HOST=0.0.0.0
VULNFORGE_PORT=$Port
VULNFORGE_DB_PATH=$DbPath
VULNFORGE_PUBLIC_URL=$PublicUrl
VULNFORGE_JWT_SECRET=$JwtSecret
VULNFORGE_BOOTSTRAP_TOKEN=$BootstrapToken
"@ | Set-Content -Path $EnvPath -Encoding ASCII

# ── Windows service via nssm or native sc.exe ──
$ServiceName = "VulnForgeServer"
$NodePath    = (Get-Command node).Path
$EntryPath   = Join-Path $InstallDir "dist-server\server\index.js"

Log "Creating service $ServiceName..."
& sc.exe create $ServiceName binPath= "`"$NodePath`" `"$EntryPath`"" start= auto DisplayName= "VulnForge Team Server" | Out-Null
& sc.exe description $ServiceName "VulnForge server-mode process providing sync + auth for connected desktop clients." | Out-Null

# Env file loading is not native to sc.exe; use a wrapper .cmd that sources the .env.
$WrapperPath = Join-Path $InstallDir "start-server.cmd"
@"
@echo off
for /f "usebackq tokens=1,* delims==" %%a in ("$EnvPath") do if not "%%a"=="" if not "%%a:~0,1%"=="#" set %%a=%%b
"$NodePath" "$EntryPath"
"@ | Set-Content -Path $WrapperPath -Encoding ASCII

& sc.exe config $ServiceName binPath= "cmd.exe /c `"$WrapperPath`"" | Out-Null
& sc.exe start $ServiceName | Out-Null

Ok "Installed and started."
Write-Host ""
Write-Host "  Service:        $ServiceName (auto-start)"
Write-Host "  Data:           $DataDir"
Write-Host "  Config:         $EnvPath"
Write-Host ""
Write-Host "  Bootstrap URL:  $PublicUrl/api/session/bootstrap"
Write-Host "  Bootstrap token (paste from desktop first-launch):"
Write-Host ""
Write-Host "      $BootstrapToken" -ForegroundColor Yellow
Write-Host ""
Write-Host "  After bootstrap, remove VULNFORGE_BOOTSTRAP_TOKEN from"
Write-Host "  $EnvPath and restart the service."
