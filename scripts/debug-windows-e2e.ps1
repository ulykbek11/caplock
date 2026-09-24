$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$logDir = Join-Path $root '.caplock-debug'
$summaryPath = Join-Path $logDir 'latest-summary.txt'
$phaseLogs = @('versions.log', 'build.log', 'native-build.log', 'selftest.log', 'npm-e2e.log', 'pnpm-e2e.log', 'doctor.log', 'verify-windows.log', 'release-check.log', 'latest-summary.txt')
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
foreach ($name in $phaseLogs) { Remove-Item -LiteralPath (Join-Path $logDir $name) -Force -ErrorAction SilentlyContinue }

$status = [ordered]@{
  'BUILD' = 'NOT RUN'; 'NATIVE BUILD' = 'NOT RUN'; 'SELFTEST' = 'NOT RUN';
  'NPM E2E' = 'NOT RUN'; 'PNPM E2E' = 'NOT RUN'; 'DOCTOR' = 'NOT RUN';
  'VERIFY WINDOWS' = 'NOT RUN'; 'RELEASE CHECK' = 'NOT RUN'
}
$firstFailure = $null
$firstExitCode = $null
$firstFailureLog = $null

function Invoke-Phase([string]$Name, [string]$Executable, [string[]]$Arguments) {
  $log = Join-Path $script:logDir $Name
  # Capture LASTEXITCODE immediately. Nothing may run between invocation and this assignment.
  $previousErrorAction = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  & $Executable @Arguments *> $log
  $exitCode = $LASTEXITCODE
  $ErrorActionPreference = $previousErrorAction
  return [pscustomobject]@{ ExitCode = $exitCode; Log = $log }
}

function Set-PhaseResult([string]$Label, $Result) {
  if ($Result.ExitCode -eq 0) { $script:status[$Label] = 'PASS'; return $true }
  $script:status[$Label] = 'FAIL'
  if ($null -eq $script:firstFailure) {
    $script:firstFailure = $Label
    $script:firstExitCode = $Result.ExitCode
    $script:firstFailureLog = $Result.Log
  }
  return $false
}

function Set-SelftestResult($Result) {
  $valid = $false
  if ($Result.ExitCode -eq 0) {
    try {
      $probe = Get-Content -LiteralPath $Result.Log -Raw | ConvertFrom-Json
      $valid = $probe.profileCreated -eq $true -and $probe.processLaunched -eq $true -and $probe.tokenIsAppContainer -eq $true -and $probe.allowedWrite -eq $true -and $probe.cleanup -eq $true -and $probe.stage -eq 'complete'
    } catch { $valid = $false }
  }
  if ($valid) { $script:status['SELFTEST'] = 'PASS'; return $true }
  $script:status['SELFTEST'] = 'FAIL'
  if ($null -eq $script:firstFailure) {
    $script:firstFailure = 'SELFTEST'
    $script:firstExitCode = $Result.ExitCode
    $script:firstFailureLog = $Result.Log
  }
  return $false
}

function Get-SafeFailureStage([string]$Log) {
  if (-not $Log -or -not (Test-Path -LiteralPath $Log)) { return 'none' }
  $matches = @(Select-String -LiteralPath $Log -Pattern 'CapLock failure stage: .*|CapLock stage: .*|CapLock sandbox child failed: .*|caplock-sandbox: [^\r\n]+' -AllMatches)
  if ($matches.Count -eq 0) { return 'none' }
  return $matches[$matches.Count - 1].Line
}

Push-Location $root
try {
  # Versions are informational only and never determine phase attribution.
  & cmd.exe /d /s /c 'node --version & npm.cmd --version & pnpm.cmd --version' *> (Join-Path $logDir 'versions.log')

  $build = Invoke-Phase 'build.log' 'npm.cmd' @('run', 'build')
  if (Set-PhaseResult 'BUILD' $build) {
    $nativeBuild = Invoke-Phase 'native-build.log' 'npm.cmd' @('run', 'native:build')
    if (Set-PhaseResult 'NATIVE BUILD' $nativeBuild) {
      $selftest = Invoke-Phase 'selftest.log' '.\native\bin\caplock-sandbox.exe' @('--selftest')
      if (Set-SelftestResult $selftest) {
        $env:CAPLOCK_DEBUG = '1'
        $npmE2e = Invoke-Phase 'npm-e2e.log' 'npm.cmd' @('run', 'test:e2e:npm')
        if (Set-PhaseResult 'NPM E2E' $npmE2e) {
          $pnpmE2e = Invoke-Phase 'pnpm-e2e.log' 'npm.cmd' @('run', 'test:e2e:pnpm')
          if (Set-PhaseResult 'PNPM E2E' $pnpmE2e) {
            $doctor = Invoke-Phase 'doctor.log' 'node.exe' @('.\dist\cli.js', 'doctor', '--json')
            if (Set-PhaseResult 'DOCTOR' $doctor) {
              $verify = Invoke-Phase 'verify-windows.log' 'npm.cmd' @('run', 'verify:windows')
              if (Set-PhaseResult 'VERIFY WINDOWS' $verify) {
                $release = Invoke-Phase 'release-check.log' 'npm.cmd' @('run', 'release:check')
                [void](Set-PhaseResult 'RELEASE CHECK' $release)
              }
            }
          }
        }
      }
    }
  }
} finally {
  Pop-Location
  $lines = @('CapLock Windows debug summary')
  foreach ($entry in $status.GetEnumerator()) { $lines += "$($entry.Key): $($entry.Value)" }
  $failure = if ($null -eq $firstFailure) { 'none' } else { $firstFailure }
  $exitCode = if ($null -eq $firstExitCode) { '0' } else { [string]$firstExitCode }
  $lines += "FIRST FAILURE: $failure"
  $lines += "EXIT CODE: $exitCode"
  $lines += "FIRST FAILURE STAGE: $(Get-SafeFailureStage $firstFailureLog)"
  $lines | Set-Content -LiteralPath $summaryPath -Encoding utf8
}
if ($null -ne $firstFailure) { exit 1 }
