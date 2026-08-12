<#
.SYNOPSIS
    VEXGuard batch scanner + evaluation driver.

.DESCRIPTION
    Runs the full VEXGuard pipeline (static pre-filter -> dynamic detonation ->
    combined verdict -> confusion matrices -> root-cause report) across the
    DataDog and VsMex corpora.

    node_modules directories are never treated as samples: dataset.js walks the
    corpora and skips them, so a single extension that ships 2,000 nested
    package.json files is still one sample.

.PARAMETER Datasets
    all | datadog | vsmex     (default: all)

.PARAMETER Concurrency
    Parallel samples. Default: CPU count - 1, capped at 8.

.PARAMETER Limit
    Cap samples per corpus. Useful for a smoke test.

.PARAMETER LatestOnly
    Analyse only the newest version of each extension (VsMex ships up to 5
    versions per extension: 3,790 artefacts for 1,609 extensions).

.PARAMETER StaticOnly
    Skip detonation. Fast, lower recall.

.PARAMETER Resume
    Skip samples already present in the results CSV.

.PARAMETER ReportOnly
    Rebuild METRICS.md / ROOT-CAUSE.md from existing CSVs without re-scanning.

.PARAMETER OutDir
    Results directory. Default: .\vexguard-results

.EXAMPLE
    .\Run-VEXGuard.ps1 -Limit 20
    Smoke test: 20 samples per corpus.

.EXAMPLE
    .\Run-VEXGuard.ps1 -LatestOnly -Concurrency 8
    Full evaluation, newest version of each extension.

.EXAMPLE
    .\Run-VEXGuard.ps1 -Datasets vsmex -Resume
    Continue an interrupted VsMex run.
#>
[CmdletBinding()]
param(
    [ValidateSet('all', 'datadog', 'vsmex')]
    [string] $Datasets = 'all',
    [int]    $Concurrency = 0,
    [int]    $Limit = 0,
    [int]    $TimeoutMs = 90000,
    [switch] $LatestOnly,
    [switch] $StaticOnly,
    [switch] $Resume,
    [switch] $ReportOnly,
    [switch] $SelfTest,
    [string] $OutDir = ''
)

$ErrorActionPreference = 'Stop'
$engine = $PSScriptRoot
Set-Location $engine

# ── Preflight ────────────────────────────────────────────────────────────────
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) { Write-Error 'Node.js not found on PATH. Install Node 18+ and retry.'; exit 1 }
$nodeVersion = (& node --version)
Write-Host "Node        : $nodeVersion"

# acorn powers the AST layer. Without it preprocess.js silently degrades to
# regex-only matching, which is exactly the false-positive-prone mode we moved
# away from — so warn loudly rather than producing quietly worse numbers.
$hasAcorn = $false
try { & node -e "require('acorn')" 2>$null; if ($?) { $hasAcorn = $true } } catch { }
if ($hasAcorn) {
    Write-Host 'AST parser  : acorn available'
} else {
    Write-Warning 'acorn NOT found - the static stage will fall back to regex matching (more false positives).'
    Write-Warning 'Install it with:  npm install acorn'
}

foreach ($f in @('VEXGuard.js', 'benchmark.js', 'preprocess.js', 'sandbox.js', 'dataset.js',
                 'data-intel.js', 'mock-vscode.js', 'time-machine.js', 'native-spoof.js',
                 'decoy-profile.js', 'zip-util.js')) {
    if (-not (Test-Path (Join-Path $engine $f))) { Write-Error "Missing engine file: $f"; exit 1 }
}

if ($SelfTest) {
    Write-Host "`nRunning pipeline self-test (synthetic OS-gated, 90-day time-bombed stealer)..." -ForegroundColor Cyan
    & node VEXGuard.js --selftest
    exit $LASTEXITCODE
}

if ($Concurrency -le 0) {
    $cpus = [Environment]::ProcessorCount
    $Concurrency = [Math]::Max(2, [Math]::Min(8, $cpus - 1))
}
if (-not $OutDir) { $OutDir = Join-Path $engine 'vexguard-results' }

# ── Build the argument list ──────────────────────────────────────────────────
$argv = @('benchmark.js', '--datasets', $Datasets, '--concurrency', "$Concurrency",
          '--timeout', "$TimeoutMs", '--out', $OutDir)
if ($Limit -gt 0)  { $argv += @('--limit', "$Limit") }
if ($LatestOnly)   { $argv += '--latest-only' }
if ($StaticOnly)   { $argv += '--static-only' }
if ($Resume)       { $argv += '--resume' }
if ($ReportOnly)   { $argv += '--report-only' }

Write-Host "Corpora     : $Datasets"
Write-Host "Concurrency : $Concurrency"
Write-Host "Output      : $OutDir"
Write-Host ''

$sw = [Diagnostics.Stopwatch]::StartNew()
& node @argv
$exit = $LASTEXITCODE
$sw.Stop()

Write-Host ''
Write-Host ("Elapsed     : {0:hh\:mm\:ss}" -f $sw.Elapsed)
if ($exit -eq 0) {
    Write-Host 'Reports:' -ForegroundColor Green
    Write-Host "  $OutDir\METRICS.md"
    Write-Host "  $OutDir\ROOT-CAUSE.md"
    Write-Host "  $OutDir\metrics.json"
    Get-ChildItem -Path $OutDir -Filter 'results-*.csv' -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host "  $($_.FullName)" }
} else {
    Write-Warning "benchmark.js exited with code $exit"
}
exit $exit
