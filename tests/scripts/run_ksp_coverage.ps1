# run_ksp_coverage.ps1 - KSP Code Coverage Analysis Script
# Copyright (c) 2025 ludicrypt. All rights reserved.
# Licensed under the MIT License.

param(
    [string]$BuildConfig = "Debug",
    [string]$CoverageThreshold = "100",
    [switch]$GenerateHtml = $true,
    [switch]$Verbose = $false
)

$ErrorActionPreference = "Stop"

# Script configuration
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$TestsDir = Split-Path -Parent $ScriptDir
$KspRootDir = Split-Path -Parent $TestsDir
$BuildDir = Join-Path $KspRootDir "build\$BuildConfig"
$ReportsDir = Join-Path $TestsDir "reports"
$CoverageDir = Join-Path $ReportsDir "coverage"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] KSP Coverage: $Message"
}

function Initialize-KspCoverageEnvironment {
    Write-Log "Initializing KSP coverage environment..."
    
    # Create coverage directory
    if (-not (Test-Path $CoverageDir)) {
        New-Item -ItemType Directory -Path $CoverageDir -Force | Out-Null
    }
    
    # Check for coverage tools
    $openCppCoverage = Get-Command "OpenCppCoverage.exe" -ErrorAction SilentlyContinue
    if (-not $openCppCoverage) {
        Write-Log "OpenCppCoverage not found. Please install OpenCppCoverage." "ERROR"
        throw "OpenCppCoverage is required for KSP coverage analysis"
    }
    
    Write-Log "KSP coverage tools ready"
}

function Run-KspCoverageAnalysis {
    Write-Log "Running KSP coverage analysis..."
    
    $testExecutable = Join-Path $BuildDir "ksp_test_runner.exe"
    $kspSrcDir = Join-Path $KspRootDir "src"
    $kspIncludeDir = Join-Path $KspRootDir "include"
    
    if (-not (Test-Path $testExecutable)) {
        throw "KSP test executable not found: $testExecutable"
    }
    
    # Coverage configuration for KSP
    $coverageArgs = @(
        "--sources", $kspSrcDir,
        "--sources", $kspIncludeDir,
        "--excluded_sources", "*\tests\*",
        "--excluded_sources", "*\test\*",
        "--excluded_sources", "*\gtest\*",
        "--excluded_sources", "*\gmock\*",
        "--export_type", "cobertura:$CoverageDir\ksp_coverage.xml"
    )
    
    if ($GenerateHtml) {
        $coverageArgs += "--export_type", "html:$CoverageDir\ksp_html"
    }
    
    if ($Verbose) {
        $coverageArgs += "--verbose"
    }
    
    # Add test executable and its arguments
    $coverageArgs += "--", $testExecutable, "--gtest_color=no", "--gtest_output=xml:$CoverageDir\ksp_test_results.xml"
    
    Write-Log "Executing KSP coverage analysis..."
    $process = Start-Process -FilePath "OpenCppCoverage.exe" -ArgumentList $coverageArgs -Wait -PassThru -NoNewWindow
    
    if ($process.ExitCode -ne 0) {
        throw "KSP coverage analysis failed with exit code: $($process.ExitCode)"
    }
    
    Write-Log "KSP coverage analysis completed successfully"
}

function Analyze-KspCoverageResults {
    Write-Log "Analyzing KSP coverage results..."
    
    $coverageXmlPath = Join-Path $CoverageDir "ksp_coverage.xml"
    
    if (-not (Test-Path $coverageXmlPath)) {
        throw "KSP coverage XML file not found: $coverageXmlPath"
    }
    
    # Parse coverage XML
    [xml]$coverageXml = Get-Content $coverageXmlPath
    
    # Extract coverage metrics
    $coverage = $coverageXml.coverage
    $lineRate = [math]::Round([double]$coverage.'line-rate' * 100, 2)
    $branchRate = [math]::Round([double]$coverage.'branch-rate' * 100, 2)
    
    Write-Log "KSP Coverage Results:"
    Write-Log "  Line Coverage: $lineRate%"
    Write-Log "  Branch Coverage: $branchRate%"
    
    # Check against threshold
    $thresholdValue = [double]$CoverageThreshold
    
    if ($lineRate -ge $thresholdValue) {
        Write-Log "✓ KSP line coverage meets threshold ($CoverageThreshold%)" "SUCCESS"
    } else {
        Write-Log "✗ KSP line coverage below threshold: $lineRate% < $CoverageThreshold%" "ERROR"
        throw "KSP coverage threshold not met"
    }
    
    # Analyze per-package coverage
    Write-Log "KSP Per-Package Coverage:"
    foreach ($package in $coverage.packages.package) {
        $packageName = $package.name
        $packageLineRate = [math]::Round([double]$package.'line-rate' * 100, 2)
        Write-Log "  $packageName`: $packageLineRate%"
    }
    
    return @{
        LineRate = $lineRate
        BranchRate = $branchRate
        MeetsThreshold = ($lineRate -ge $thresholdValue)
    }
}

function Generate-KspCoverageReport {
    Write-Log "Generating KSP coverage summary report..."
    
    $reportPath = Join-Path $CoverageDir "ksp_coverage_summary.html"
    $results = Analyze-KspCoverageResults
    
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Supacrypt KSP - Coverage Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background-color: #f0f0f0; padding: 20px; border-radius: 5px; }
        .metric { margin: 10px 0; padding: 10px; border-radius: 5px; }
        .pass { background-color: #d4edda; border: 1px solid #c3e6cb; }
        .fail { background-color: #f8d7da; border: 1px solid #f5c6cb; }
        .pending { background-color: #fff3cd; border: 1px solid #ffeaa7; }
        .coverage-bar { width: 100%; height: 20px; background-color: #f0f0f0; border-radius: 10px; }
        .coverage-fill { height: 100%; background-color: #28a745; border-radius: 10px; }
        table { border-collapse: collapse; width: 100%; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>KSP Code Coverage Report</h1>
        <p>Generated on: $(Get-Date)</p>
        <p>Threshold: $CoverageThreshold%</p>
        <p>Build Configuration: $BuildConfig</p>
    </div>
    
    <div class="metric $(if($results.MeetsThreshold) { 'pass' } else { 'fail' })">
        <h2>Overall KSP Coverage: $($results.LineRate)%</h2>
        <div class="coverage-bar">
            <div class="coverage-fill" style="width: $($results.LineRate)%"></div>
        </div>
        <p>Status: $(if($results.MeetsThreshold) { '✓ MEETS THRESHOLD' } else { '✗ BELOW THRESHOLD' })</p>
    </div>
    
    <div class="metric pending">
        <h3>KSP Performance Targets</h3>
        <table>
            <tr><th>Target</th><th>Required</th><th>Status</th></tr>
            <tr>
                <td>Initialization</td>
                <td>&lt; 100ms</td>
                <td>⏳ Testing in Progress</td>
            </tr>
            <tr>
                <td>RSA-2048 Signing</td>
                <td>&lt; 100ms</td>
                <td>⏳ Testing in Progress</td>
            </tr>
            <tr>
                <td>ECC P-256 Signing</td>
                <td>&lt; 50ms</td>
                <td>⏳ Testing in Progress</td>
            </tr>
            <tr>
                <td>Key Enumeration (100 keys)</td>
                <td>&lt; 200ms</td>
                <td>⏳ Testing in Progress</td>
            </tr>
        </table>
    </div>
    
    <div class="metric">
        <h3>Coverage Breakdown</h3>
        <ul>
            <li>Line Coverage: $($results.LineRate)%</li>
            <li>Branch Coverage: $($results.BranchRate)%</li>
        </ul>
    </div>
    
    <div class="metric">
        <h3>Task 4.3 Achievement</h3>
        <table>
            <tr><th>Requirement</th><th>Target</th><th>Achieved</th><th>Status</th></tr>
            <tr>
                <td>100% Code Coverage</td>
                <td>100%</td>
                <td>$($results.LineRate)%</td>
                <td>$(if($results.LineRate -eq 100) { '✓ ACHIEVED' } else { '⚠ IN PROGRESS' })</td>
            </tr>
            <tr>
                <td>All Critical Paths</td>
                <td>100%</td>
                <td>$($results.BranchRate)%</td>
                <td>$(if($results.BranchRate -eq 100) { '✓ ACHIEVED' } else { '⚠ IN PROGRESS' })</td>
            </tr>
            <tr>
                <td>CNG API Compliance</td>
                <td>Full Compliance</td>
                <td>Testing</td>
                <td>⏳ VALIDATING</td>
            </tr>
            <tr>
                <td>Multi-Architecture Support</td>
                <td>x86, x64, ARM64</td>
                <td>Testing</td>
                <td>⏳ VALIDATING</td>
            </tr>
        </table>
    </div>
    
    <div class="metric">
        <h3>Files and Links</h3>
        <ul>
            <li><a href="ksp_coverage.xml">KSP Coverage Data (XML)</a></li>
            <li><a href="ksp_html/index.html">Detailed KSP HTML Report</a></li>
            <li><a href="ksp_test_results.xml">KSP Test Results (XML)</a></li>
        </ul>
    </div>
    
    <div class="metric">
        <h3>Next Steps</h3>
        <ul>
            $(if($results.MeetsThreshold) {
                '<li>✓ KSP coverage target achieved</li>
                <li>Run performance validation tests</li>
                <li>Execute security assessment</li>
                <li>Validate CNG API compliance</li>
                <li>Test multi-architecture compatibility</li>'
            } else {
                '<li>Add tests for uncovered KSP code paths</li>
                '<li>Focus on CNG interface coverage</li>
                '<li>Review key management operations</li>
                '<li>Test algorithm provider coverage</li>
                '<li>Validate error handling paths</li>'
            })
        </ul>
    </div>
</body>
</html>
"@
    
    $htmlContent | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Log "KSP coverage summary report generated: $reportPath"
}

function Main {
    try {
        Write-Log "Starting KSP coverage analysis for Task 4.3"
        
        Initialize-KspCoverageEnvironment
        Run-KspCoverageAnalysis
        $results = Analyze-KspCoverageResults
        Generate-KspCoverageReport
        
        Write-Log "KSP coverage analysis completed successfully!"
        Write-Log "Final KSP Results: Line Coverage = $($results.LineRate)%, Branch Coverage = $($results.BranchRate)%"
        
        if ($results.MeetsThreshold) {
            Write-Log "✓ KSP coverage threshold achieved!" "SUCCESS"
            Write-Log "KSP implementation ready for Task 4.3 validation" "SUCCESS"
            exit 0
        } else {
            Write-Log "✗ KSP coverage threshold not met" "ERROR" 
            exit 1
        }
        
    } catch {
        Write-Log "KSP coverage analysis failed: $($_.Exception.Message)" "ERROR"
        exit 2
    }
}

Main