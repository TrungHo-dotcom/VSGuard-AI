@echo off
REM ===========================================================================
REM  VEXGuard — batch scanner + evaluation driver
REM ===========================================================================
REM  Scans BOTH corpora (DataDog + VsMex) and writes confusion matrices plus a
REM  root-cause report.
REM
REM  The previous version of this script recursed over every package.json in the
REM  tree and ran one scan per hit. That treated each bundled dependency as a
REM  separate "sample" (results were named node-fetch, fetch-blob, hardhat...)
REM  and re-scanned the same extension dozens of times. Sample discovery now
REM  lives in dataset.js, which understands both corpus layouts, resolves ground
REM  truth, and never descends into node_modules.
REM
REM  Usage:
REM      VEXGuard_run.bat                 full run, both corpora
REM      VEXGuard_run.bat smoke           20 samples per corpus (quick check)
REM      VEXGuard_run.bat latest          newest version per extension only
REM      VEXGuard_run.bat datadog         DataDog corpora only
REM      VEXGuard_run.bat vsmex           VsMex corpus only (latest versions)
REM      VEXGuard_run.bat resume          continue an interrupted run
REM      VEXGuard_run.bat selftest        prove the pipeline detonates malware
REM      VEXGuard_run.bat report          rebuild reports from existing CSVs
REM ===========================================================================
TITLE VEXGuard Batch Scanner
SETLOCAL

cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Node.js not found on PATH. Install Node 18+ and retry.
    pause
    exit /b 1
)

set MODE=%~1
if "%MODE%"=="" set MODE=full

set ARGS=--datasets all --concurrency 8 --timeout 90000

if /i "%MODE%"=="smoke"    set ARGS=--datasets all --concurrency 8 --limit 20
if /i "%MODE%"=="latest"   set ARGS=--datasets all --concurrency 8 --latest-only
if /i "%MODE%"=="datadog"  set ARGS=--datasets datadog --concurrency 8
if /i "%MODE%"=="vsmex"    set ARGS=--datasets vsmex --concurrency 8 --latest-only
if /i "%MODE%"=="resume"   set ARGS=--datasets all --concurrency 8 --resume
if /i "%MODE%"=="report"   set ARGS=--datasets all --report-only

if /i "%MODE%"=="selftest" (
    echo Running pipeline self-test...
    node VEXGuard.js --selftest
    echo.
    pause
    exit /b %ERRORLEVEL%
)

echo ======================================================================
echo   VEXGuard batch scan   [mode: %MODE%]
echo   node benchmark.js %ARGS%
echo ======================================================================
echo.

node benchmark.js %ARGS%
set RC=%ERRORLEVEL%

echo.
echo ======================================================================
if "%RC%"=="0" (
    echo   Done. Reports written to vexguard-results\
    echo     METRICS.md      confusion matrices ^(strict + triage^)
    echo     ROOT-CAUSE.md   per-sample diagnosis of every FP and FN
    echo     metrics.json    machine-readable metrics
    echo     results-*.csv   one row per sample
) else (
    echo   benchmark.js exited with code %RC%
)
echo ======================================================================
pause
exit /b %RC%
