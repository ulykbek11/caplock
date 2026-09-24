$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot '..\native\windows\caplock-sandbox.c'
$outputDir = Join-Path $PSScriptRoot '..\native\bin'
$output = Join-Path $outputDir 'caplock-sandbox.exe'
$shellSource = Join-Path $PSScriptRoot '..\native\windows\caplock-shell.c'
$shellOutput = Join-Path $outputDir 'caplock-shell.exe'
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null

# npm can be launched from a regular PowerShell, an x86 developer prompt, or
# an x64 developer prompt. Always import the installed MSVC x64 environment.
$programFilesX86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
$vswhere = Join-Path $programFilesX86 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) {
  throw 'Visual Studio Build Tools were not found. Install the Desktop development with C++ workload.'
}
$installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or -not $installation) {
  throw 'MSVC x64 tools were not found. Install the Desktop development with C++ workload.'
}
$vcvarsall = Join-Path $installation.Trim() 'VC\Auxiliary\Build\vcvarsall.bat'
if (-not (Test-Path -LiteralPath $vcvarsall)) { throw "MSVC environment script was not found: $vcvarsall" }
$environment = & cmd.exe /d /s /c "call `"$vcvarsall`" x64 >nul && set"
if ($LASTEXITCODE -ne 0) { throw 'Unable to load the MSVC x64 build environment.' }
foreach ($line in $environment) {
  if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process') }
}
$compiler = Get-Command cl.exe -ErrorAction SilentlyContinue
if (-not $compiler) { throw 'The MSVC x64 compiler was not available after loading vcvarsall.bat x64.' }
& $compiler.Source /nologo /W4 /WX /DUNICODE /D_UNICODE /Fe:$output $source advapi32.lib userenv.lib
if ($LASTEXITCODE -ne 0) { throw 'Native helper compilation failed.' }
& $compiler.Source /nologo /W4 /WX /DUNICODE /D_UNICODE /Fe:$shellOutput $shellSource
if ($LASTEXITCODE -ne 0) { throw 'Native shell launcher compilation failed.' }

# Check the PE machine field instead of trusting the architecture of the shell.
$bytes = [IO.File]::ReadAllBytes($output)
$peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
$machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
if ($machine -ne 0x8664) { throw "Native helper was not built for x64 (PE machine 0x$('{0:X4}' -f $machine))." }
Write-Output "Built $output"
Write-Output "Built $shellOutput"
