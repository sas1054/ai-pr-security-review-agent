[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $env:TEMP 'prsa-webhook-receiver.zip')
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$staging = Join-Path $env:TEMP ('prsa-webhook-package-' + [guid]::NewGuid().ToString('N'))

New-Item -ItemType Directory -Path $staging | Out-Null
$functionSource = Join-Path $repoRoot 'src\webhook-receiver'
@('function_app.py', 'app.py', 'admin.py', 'admin_portal.html', 'host.json', '.funcignore', 'requirements.txt') |
    ForEach-Object { Copy-Item -LiteralPath (Join-Path $functionSource $_) -Destination $staging -Force }
@('Webhook', 'Admin') |
    ForEach-Object { Copy-Item -LiteralPath (Join-Path $functionSource $_) -Destination (Join-Path $staging $_) -Recurse -Force }
Copy-Item -Path (Join-Path $repoRoot 'src\prsa_control') -Destination (Join-Path $staging 'prsa_control') -Recurse -Force
if (Test-Path -LiteralPath $OutputPath) {
    Remove-Item -LiteralPath $OutputPath -Force
}
Compress-Archive -Path (Join-Path $staging '*') -DestinationPath $OutputPath -Force
Write-Host "Created Function deployment package: $OutputPath"
