$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot '..\native\windows\appcontainer-diagnostic.c'
$output = Join-Path $PSScriptRoot '..\native\bin\appcontainer-diagnostic.exe'
$programFilesX86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
$vswhere = Join-Path $programFilesX86 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Visual Studio Build Tools were not found.' }
$installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$vcvarsall = Join-Path $installation.Trim() 'VC\Auxiliary\Build\vcvarsall.bat'
$environment = & cmd.exe /d /s /c "call `"$vcvarsall`" x64 >nul && set"
if ($LASTEXITCODE -ne 0) { throw 'Unable to load MSVC x64 environment.' }
foreach ($line in $environment) { if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process') } }
$compiler = Get-Command cl.exe -ErrorAction Stop
& $compiler.Source /nologo /W4 /WX /DUNICODE /D_UNICODE /Fe:$output $source userenv.lib advapi32.lib
if ($LASTEXITCODE -ne 0) { throw 'AppContainer diagnostic compilation failed.' }
Write-Output "Built $output"
