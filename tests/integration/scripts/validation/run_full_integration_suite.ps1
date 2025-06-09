# Full Integration Test Suite Runner for KSP Provider
# Executes all integration tests and generates comprehensive reports

param(
    [string]$TestSuite = "All", # All, IIS, SQL, Enterprise, CrossProvider
    [string]$OutputPath = "../../results",
    [string]$ReportFormat = "Both", # JSON, HTML, Both
    [switch]$ContinueOnFailure,
    [switch]$Parallel,
    [int]$TimeoutMinutes = 120
)

$ErrorActionPreference = if ($ContinueOnFailure) { "Continue" } else { "Stop" }

Write-Host "=== Supacrypt KSP Full Integration Test Suite ===" -ForegroundColor Green
Write-Host "Test Suite: $TestSuite" -ForegroundColor Cyan
Write-Host "Output Path: $OutputPath" -ForegroundColor Cyan
Write-Host "Report Format: $ReportFormat" -ForegroundColor Cyan

# Ensure output directory exists
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

# Test suite configuration
$testSuites = @{
    "IIS" = @{
        Script = "../scenarios/test_iis_integration.ps1"
        Name = "IIS Integration Tests"
        Timeout = 30
    }
    "SQL" = @{
        Script = "../scenarios/test_sql_server_integration.ps1"
        Name = "SQL Server Integration Tests"
        Timeout = 60
    }
    "Enterprise" = @{
        Script = "../scenarios/test_enterprise_scenarios.ps1"
        Name = "Enterprise Scenario Tests"
        Timeout = 90
    }
    "CNG" = @{
        Script = "../scenarios/test_cng_integration.ps1"
        Name = "CNG Integration Tests"
        Timeout = 45
    }
}

# Master test results
$masterResults = @{
    StartTime = Get-Date
    EndTime = $null
    TotalDuration = 0
    TestSuites = @()
    OverallStatus = "UNKNOWN"
    TotalTests = 0
    TotalPassed = 0
    TotalFailed = 0
    SuccessRate = 0
    Environment = @{
        OSVersion = (Get-WmiObject Win32_OperatingSystem).Caption
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        MachineName = $env:COMPUTERNAME
        UserName = $env:USERNAME
        TestRunner = "Supacrypt KSP Integration Suite v1.0"
        CNGVersion = "CNG 1.0"
    }
    SystemMetrics = @{}
}

function Get-SystemMetrics {
    try {
        $cpu = Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average
        $memory = Get-WmiObject Win32_OperatingSystem
        $disk = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
        
        return @{
            CPUUsage = [math]::Round($cpu.Average, 2)
            MemoryUsage = [math]::Round(($memory.TotalVisibleMemorySize - $memory.FreePhysicalMemory) / $memory.TotalVisibleMemorySize * 100, 2)
            DiskFreeSpace = [math]::Round($disk.FreeSpace / 1GB, 2)
            Timestamp = Get-Date
        }
    } catch {
        return @{
            CPUUsage = "N/A"
            MemoryUsage = "N/A"
            DiskFreeSpace = "N/A"
            Error = $_.Exception.Message
            Timestamp = Get-Date
        }
    }
}

function Test-KSPProvider {
    try {
        # Test CNG provider enumeration
        Add-Type -TypeDefinition @"
            using System;
            using System.Runtime.InteropServices;
            public class KSPTest {
                [DllImport("ncrypt.dll")]
                public static extern int NCryptEnumStorageProviders(out int pdwProviderCount, out IntPtr ppProviderList, int dwFlags);
                
                [DllImport("ncrypt.dll")]
                public static extern int NCryptFreeBuffer(IntPtr pvInput);
            }
"@
        
        $providerCount = 0
        $providerListPtr = [IntPtr]::Zero
        
        $result = [KSPTest]::NCryptEnumStorageProviders([ref]$providerCount, [ref]$providerListPtr, 0)
        
        if ($result -eq 0) {
            [KSPTest]::NCryptFreeBuffer($providerListPtr)
            return $true
        }
        
        return $false
    } catch {
        return $false
    }
}

function Run-TestSuite {
    param($SuiteName, $SuiteConfig)
    
    Write-Host "`n--- Running $($SuiteConfig.Name) ---" -ForegroundColor Yellow
    
    $suiteResult = @{
        Name = $SuiteName
        DisplayName = $SuiteConfig.Name
        Script = $SuiteConfig.Script
        StartTime = Get-Date
        EndTime = $null
        Duration = 0
        Status = "UNKNOWN"
        ExitCode = -1
        Output = ""
        Error = ""
        SystemMetricsBefore = Get-SystemMetrics
        SystemMetricsAfter = $null
    }
    
    try {
        if (-not (Test-Path $SuiteConfig.Script)) {
            throw "Test script not found: $($SuiteConfig.Script)"
        }
        
        Write-Host "Executing: $($SuiteConfig.Script)" -ForegroundColor Cyan
        
        # Execute test script with timeout
        $job = Start-Job -ScriptBlock {
            param($scriptPath)
            & $scriptPath
        } -ArgumentList (Resolve-Path $SuiteConfig.Script)
        
        $completed = Wait-Job $job -Timeout ($SuiteConfig.Timeout * 60)
        
        if ($completed) {
            $suiteResult.Output = Receive-Job $job
            $suiteResult.ExitCode = $job.State -eq "Completed" ? 0 : 1
            $suiteResult.Status = $suiteResult.ExitCode -eq 0 ? "PASSED" : "FAILED"
        } else {
            Stop-Job $job
            $suiteResult.Status = "TIMEOUT"
            $suiteResult.Error = "Test suite timed out after $($SuiteConfig.Timeout) minutes"
            $suiteResult.ExitCode = 2
        }
        
        Remove-Job $job -Force
        
    } catch {
        $suiteResult.Status = "ERROR"
        $suiteResult.Error = $_.Exception.Message
        $suiteResult.ExitCode = 3
        Write-Host "Error executing test suite: $($_.Exception.Message)" -ForegroundColor Red
    } finally {
        $suiteResult.EndTime = Get-Date
        $suiteResult.Duration = ($suiteResult.EndTime - $suiteResult.StartTime).TotalMinutes
        $suiteResult.SystemMetricsAfter = Get-SystemMetrics
    }
    
    # Display results
    $statusColor = switch ($suiteResult.Status) {
        "PASSED" { "Green" }
        "FAILED" { "Red" }
        "TIMEOUT" { "Yellow" }
        "ERROR" { "Magenta" }
        default { "White" }
    }
    
    Write-Host "Result: $($suiteResult.Status)" -ForegroundColor $statusColor
    Write-Host "Duration: $([math]::Round($suiteResult.Duration, 2)) minutes" -ForegroundColor Cyan
    
    if ($suiteResult.Error) {
        Write-Host "Error: $($suiteResult.Error)" -ForegroundColor Red
    }
    
    return $suiteResult
}

function Generate-HTMLReport {
    param($Results, $OutputFile)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Supacrypt KSP Integration Test Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #2c3e50; margin-bottom: 10px; }
        .ksp-badge { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 5px 15px; border-radius: 20px; font-size: 0.9em; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .metric-value { font-size: 2em; font-weight: bold; margin-bottom: 5px; }
        .metric-label { font-size: 0.9em; opacity: 0.9; }
        .test-suite { margin-bottom: 30px; border: 1px solid #ddd; border-radius: 8px; overflow: hidden; }
        .suite-header { background-color: #3498db; color: white; padding: 15px; font-weight: bold; }
        .suite-content { padding: 20px; }
        .status-passed { color: #27ae60; font-weight: bold; }
        .status-failed { color: #e74c3c; font-weight: bold; }
        .status-timeout { color: #f39c12; font-weight: bold; }
        .status-error { color: #9b59b6; font-weight: bold; }
        .metrics-table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .metrics-table th, .metrics-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .metrics-table th { background-color: #f8f9fa; }
        .environment-info { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin-top: 20px; }
        .timestamp { color: #666; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 Supacrypt KSP Integration Test Report</h1>
            <div class="ksp-badge">Key Storage Provider</div>
            <p class="timestamp">Generated on $($Results.StartTime.ToString("yyyy-MM-dd HH:mm:ss"))</p>
        </div>
        
        <div class="summary">
            <div class="metric-card">
                <div class="metric-value">$($Results.TotalTests)</div>
                <div class="metric-label">Total Tests</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$($Results.TotalPassed)</div>
                <div class="metric-label">Passed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$($Results.TotalFailed)</div>
                <div class="metric-label">Failed</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$($Results.SuccessRate)%</div>
                <div class="metric-label">Success Rate</div>
            </div>
        </div>
        
        <h2>Test Suite Results</h2>
"@

    foreach ($suite in $Results.TestSuites) {
        $statusClass = "status-" + $suite.Status.ToLower()
        $html += @"
        <div class="test-suite">
            <div class="suite-header">
                $($suite.DisplayName)
                <span class="$statusClass" style="float: right;">$($suite.Status)</span>
            </div>
            <div class="suite-content">
                <p><strong>Duration:</strong> $([math]::Round($suite.Duration, 2)) minutes</p>
                <p><strong>Exit Code:</strong> $($suite.ExitCode)</p>
"@
        
        if ($suite.Error) {
            $html += "<p><strong>Error:</strong> <code>$($suite.Error)</code></p>"
        }
        
        $html += @"
            </div>
        </div>
"@
    }

    $html += @"
        
        <div class="environment-info">
            <h3>Environment Information</h3>
            <p><strong>OS:</strong> $($Results.Environment.OSVersion)</p>
            <p><strong>PowerShell:</strong> $($Results.Environment.PowerShellVersion)</p>
            <p><strong>CNG Version:</strong> $($Results.Environment.CNGVersion)</p>
            <p><strong>Machine:</strong> $($Results.Environment.MachineName)</p>
            <p><strong>User:</strong> $($Results.Environment.UserName)</p>
            <p><strong>Test Runner:</strong> $($Results.Environment.TestRunner)</p>
            <p><strong>Total Duration:</strong> $([math]::Round($Results.TotalDuration, 2)) minutes</p>
        </div>
    </div>
</body>
</html>
"@

    Set-Content -Path $OutputFile -Value $html -Encoding UTF8
}

# Main execution
Write-Host "Checking KSP provider availability..." -ForegroundColor Cyan
if (Test-KSPProvider) {
    Write-Host "✅ KSP provider is available" -ForegroundColor Green
} else {
    Write-Host "⚠️ KSP provider check inconclusive" -ForegroundColor Yellow
}

Write-Host "Capturing initial system metrics..." -ForegroundColor Cyan
$masterResults.SystemMetrics.Initial = Get-SystemMetrics

# Determine which test suites to run
$suitesToRun = if ($TestSuite -eq "All") { 
    $testSuites.Keys 
} else { 
    @($TestSuite) 
}

Write-Host "Test suites to run: $($suitesToRun -join ', ')" -ForegroundColor Cyan

# Execute test suites
foreach ($suiteName in $suitesToRun) {
    if ($testSuites.ContainsKey($suiteName)) {
        $suiteResult = Run-TestSuite -SuiteName $suiteName -SuiteConfig $testSuites[$suiteName]
        $masterResults.TestSuites += $suiteResult
        
        # Update counters
        if ($suiteResult.Status -eq "PASSED") {
            $masterResults.TotalTests += 1
            $masterResults.TotalPassed += 1
        } else {
            $masterResults.TotalTests += 1
            $masterResults.TotalFailed += 1
        }
        
        # Stop on failure if not continuing
        if (-not $ContinueOnFailure -and $suiteResult.Status -ne "PASSED") {
            Write-Host "Stopping execution due to test suite failure" -ForegroundColor Red
            break
        }
    } else {
        Write-Host "Unknown test suite: $suiteName" -ForegroundColor Red
    }
}

# Finalize results
$masterResults.EndTime = Get-Date
$masterResults.TotalDuration = ($masterResults.EndTime - $masterResults.StartTime).TotalMinutes
$masterResults.SuccessRate = if ($masterResults.TotalTests -gt 0) { 
    [math]::Round(($masterResults.TotalPassed / $masterResults.TotalTests) * 100, 1) 
} else { 0 }
$masterResults.OverallStatus = if ($masterResults.TotalFailed -eq 0) { "PASSED" } else { "FAILED" }
$masterResults.SystemMetrics.Final = Get-SystemMetrics

# Generate reports
Write-Host "`n=== Generating Reports ===" -ForegroundColor Green

if ($ReportFormat -eq "JSON" -or $ReportFormat -eq "Both") {
    $jsonFile = Join-Path $OutputPath "ksp_integration_test_report.json"
    $masterResults | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonFile -Encoding UTF8
    Write-Host "JSON report saved: $jsonFile" -ForegroundColor Cyan
}

if ($ReportFormat -eq "HTML" -or $ReportFormat -eq "Both") {
    $htmlFile = Join-Path $OutputPath "ksp_integration_test_report.html"
    Generate-HTMLReport -Results $masterResults -OutputFile $htmlFile
    Write-Host "HTML report saved: $htmlFile" -ForegroundColor Cyan
}

# Display summary
Write-Host "`n=== KSP Test Execution Summary ===" -ForegroundColor Green
Write-Host "Overall Status: $($masterResults.OverallStatus)" -ForegroundColor $(if ($masterResults.OverallStatus -eq "PASSED") { "Green" } else { "Red" })
Write-Host "Total Duration: $([math]::Round($masterResults.TotalDuration, 2)) minutes" -ForegroundColor Cyan
Write-Host "Test Suites: $($masterResults.TestSuites.Count)" -ForegroundColor Cyan
Write-Host "Success Rate: $($masterResults.SuccessRate)%" -ForegroundColor Cyan

foreach ($suite in $masterResults.TestSuites) {
    $statusColor = switch ($suite.Status) {
        "PASSED" { "Green" }
        "FAILED" { "Red" }
        "TIMEOUT" { "Yellow" }
        "ERROR" { "Magenta" }
        default { "White" }
    }
    Write-Host "  $($suite.DisplayName): $($suite.Status)" -ForegroundColor $statusColor
}

# Exit with appropriate code
if ($masterResults.OverallStatus -eq "PASSED") {
    Write-Host "`n🎉 All KSP integration tests completed successfully!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n❌ Some KSP integration tests failed!" -ForegroundColor Red
    exit 1
}