$ErrorActionPreference = 'Stop'
$diagnostic = Join-Path $PSScriptRoot '..\native\bin\appcontainer-diagnostic.exe'
if (-not (Test-Path -LiteralPath $diagnostic)) { throw 'Diagnostic is not built. Run npm.cmd run native:diagnostic:build first.' }
$failed = $false
for ($attempt = 1; $attempt -le 3; $attempt++) {
  Write-Output "=== AppContainer diagnostic attempt $attempt/3 ==="
  & $diagnostic
  if ($LASTEXITCODE -ne 0) { $failed = $true }
}
if ($failed) { exit 1 }
