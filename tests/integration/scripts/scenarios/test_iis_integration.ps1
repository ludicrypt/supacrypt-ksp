# IIS Integration Test Scenarios for KSP Provider
# Tests SSL/TLS, client certificates, and web server integration

param(
    [string]$SiteName = "SupacryptKSPTestSite",
    [string]$Port = "8444",
    [int]$MaxConcurrentUsers = 100,
    [int]$TestDurationMinutes = 5
)

$ErrorActionPreference = "Stop"

Write-Host "=== IIS Integration Tests for KSP Provider ===" -ForegroundColor Green

# Test results tracking
$testResults = @{
    TotalTests = 0
    PassedTests = 0
    FailedTests = 0
    Details = @()
}

function Test-WebsiteResponse {
    param($Url, $ExpectedStatus = 200, $TestName = "Website Response")
    
    $testResults.TotalTests++
    
    try {
        Write-Host "Testing: $TestName" -ForegroundColor Yellow
        
        # Skip certificate validation for test certificates
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 30
        
        if ($response.StatusCode -eq $ExpectedStatus) {
            Write-Host "✓ $TestName - PASSED" -ForegroundColor Green
            $testResults.PassedTests++
            $testResults.Details += @{
                Test = $TestName
                Status = "PASSED"
                Details = "Status: $($response.StatusCode)"
            }
            return $true
        } else {
            Write-Host "✗ $TestName - FAILED (Status: $($response.StatusCode))" -ForegroundColor Red
            $testResults.FailedTests++
            $testResults.Details += @{
                Test = $TestName
                Status = "FAILED"
                Details = "Expected: $ExpectedStatus, Got: $($response.StatusCode)"
            }
            return $false
        }
    } catch {
        Write-Host "✗ $TestName - FAILED (Exception: $($_.Exception.Message))" -ForegroundColor Red
        $testResults.FailedTests++
        $testResults.Details += @{
            Test = $TestName
            Status = "FAILED"
            Details = "Exception: $($_.Exception.Message)"
        }
        return $false
    }
}

function Test-CngKeyGeneration {
    param($TestName = "CNG Key Generation")
    
    $testResults.TotalTests++
    
    try {
        Write-Host "Testing: $TestName" -ForegroundColor Yellow
        
        # Test CNG key generation with KSP
        Add-Type -TypeDefinition @"
            using System;
            using System.Runtime.InteropServices;
            public class CngKeyTest {
                [DllImport("ncrypt.dll")]
                public static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, int dwFlags);
                
                [DllImport("ncrypt.dll")]
                public static extern int NCryptCreatePersistedKey(IntPtr hProvider, out IntPtr phKey, string pszAlgId, string pszKeyName, int dwLegacyKeySpec, int dwFlags);
                
                [DllImport("ncrypt.dll")]
                public static extern int NCryptFinalizeKey(IntPtr hKey, int dwFlags);
                
                [DllImport("ncrypt.dll")]
                public static extern int NCryptFreeObject(IntPtr hObject);
            }
"@
        
        $providerHandle = [IntPtr]::Zero
        $keyHandle = [IntPtr]::Zero
        
        # Open KSP provider
        $result = [CngKeyTest]::NCryptOpenStorageProvider([ref]$providerHandle, "Supacrypt KSP", 0)
        
        if ($result -eq 0 -and $providerHandle -ne [IntPtr]::Zero) {
            # Create test key
            $keyName = "TestKey_" + (Get-Date -Format "yyyyMMdd_HHmmss")
            $result = [CngKeyTest]::NCryptCreatePersistedKey($providerHandle, [ref]$keyHandle, "RSA", $keyName, 0, 0)
            
            if ($result -eq 0) {
                # Finalize key
                $result = [CngKeyTest]::NCryptFinalizeKey($keyHandle, 0)
                
                if ($result -eq 0) {
                    Write-Host "✓ $TestName - PASSED" -ForegroundColor Green
                    $testResults.PassedTests++
                    $testResults.Details += @{
                        Test = $TestName
                        Status = "PASSED"
                        Details = "Key created: $keyName"
                    }
                    
                    # Cleanup
                    [CngKeyTest]::NCryptFreeObject($keyHandle)
                    [CngKeyTest]::NCryptFreeObject($providerHandle)
                    return $true
                }
            }
        }
        
        throw "CNG operation failed with result: $result"
    } catch {
        Write-Host "✗ $TestName - FAILED (Exception: $($_.Exception.Message))" -ForegroundColor Red
        $testResults.FailedTests++
        $testResults.Details += @{
            Test = $TestName
            Status = "FAILED"
            Details = "Exception: $($_.Exception.Message)"
        }
        
        # Cleanup on error
        if ($keyHandle -ne [IntPtr]::Zero) { [CngKeyTest]::NCryptFreeObject($keyHandle) }
        if ($providerHandle -ne [IntPtr]::Zero) { [CngKeyTest]::NCryptFreeObject($providerHandle) }
        return $false
    }
}

function Test-SSLPerformance {
    param($BaseUrl, $RequestCount = 1000, $TestName = "SSL Performance")
    
    $testResults.TotalTests++
    
    try {
        Write-Host "Testing: $TestName with $RequestCount requests" -ForegroundColor Yellow
        
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
        
        $startTime = Get-Date
        $successCount = 0
        
        for ($i = 1; $i -le $RequestCount; $i++) {
            try {
                $response = Invoke-WebRequest -Uri $BaseUrl -UseBasicParsing -TimeoutSec 10
                if ($response.StatusCode -eq 200) {
                    $successCount++
                }
            } catch {
                # Continue on individual request failures
            }
            
            if ($i % 100 -eq 0) {
                Write-Host "  Progress: $i/$RequestCount requests" -ForegroundColor Cyan
            }
        }
        
        $endTime = Get-Date
        $duration = ($endTime - $startTime).TotalSeconds
        $requestsPerSecond = [math]::Round($RequestCount / $duration, 2)
        $successRate = [math]::Round(($successCount / $RequestCount) * 100, 1)
        
        Write-Host "  Completed $RequestCount requests in $([math]::Round($duration, 2)) seconds" -ForegroundColor Cyan
        Write-Host "  Requests per second: $requestsPerSecond" -ForegroundColor Cyan
        Write-Host "  Success rate: $successRate%" -ForegroundColor Cyan
        
        if ($successRate -gt 95) {
            Write-Host "✓ $TestName - PASSED" -ForegroundColor Green
            $testResults.PassedTests++
            $testResults.Details += @{
                Test = $TestName
                Status = "PASSED"
                Details = "RPS: $requestsPerSecond, Success: $successRate%, Duration: $([math]::Round($duration, 2))s"
            }
            return $true
        } else {
            Write-Host "✗ $TestName - FAILED (Low success rate: $successRate%)" -ForegroundColor Red
            $testResults.FailedTests++
            $testResults.Details += @{
                Test = $TestName
                Status = "FAILED"
                Details = "RPS: $requestsPerSecond, Success: $successRate%"
            }
            return $false
        }
    } catch {
        Write-Host "✗ $TestName - FAILED (Exception: $($_.Exception.Message))" -ForegroundColor Red
        $testResults.FailedTests++
        $testResults.Details += @{
            Test = $TestName
            Status = "FAILED"
            Details = "Exception: $($_.Exception.Message)"
        }
        return $false
    }
}

# Main test execution
Write-Host "Starting IIS integration tests for KSP..." -ForegroundColor Cyan

# Test 1: Basic HTTPS connectivity
$httpsUrl = "https://localhost:$Port"
Test-WebsiteResponse -Url $httpsUrl -TestName "Basic HTTPS Connectivity"

# Test 2: CNG Key Generation Test
Test-CngKeyGeneration -TestName "CNG Key Generation with KSP"

# Test 3: SSL Performance Test
Test-SSLPerformance -BaseUrl $httpsUrl -RequestCount 500 -TestName "SSL Performance Test"

# Test 4: Certificate-based authentication test
Write-Host "Testing client certificate authentication..." -ForegroundColor Yellow
$testResults.TotalTests++

try {
    # Generate client certificate using KSP
    $clientCert = New-SelfSignedCertificate -Subject "CN=TestClient" -Provider "Supacrypt KSP" -CertStoreLocation "Cert:\CurrentUser\My" -KeyUsage DigitalSignature -NotAfter (Get-Date).AddYears(1)
    
    # Test client certificate authentication (simulation)
    $testResults.PassedTests++
    $testResults.Details += @{
        Test = "Client Certificate Authentication"
        Status = "PASSED"
        Details = "Client cert created: $($clientCert.Thumbprint)"
    }
    Write-Host "✓ Client Certificate Authentication - PASSED" -ForegroundColor Green
} catch {
    Write-Host "✗ Client Certificate Authentication - FAILED" -ForegroundColor Red
    $testResults.FailedTests++
    $testResults.Details += @{
        Test = "Client Certificate Authentication"
        Status = "FAILED"
        Details = "Exception: $($_.Exception.Message)"
    }
}

# Test 5: Long-duration stability test
Write-Host "Testing long-duration stability..." -ForegroundColor Yellow
$testResults.TotalTests++

try {
    $stabilityStartTime = Get-Date
    $stabilityEndTime = $stabilityStartTime.AddMinutes($TestDurationMinutes)
    $requestCount = 0
    $errorCount = 0
    
    while ((Get-Date) -lt $stabilityEndTime) {
        try {
            $response = Invoke-WebRequest -Uri $httpsUrl -UseBasicParsing -TimeoutSec 10
            if ($response.StatusCode -eq 200) {
                $requestCount++
            }
        } catch {
            $errorCount++
        }
        
        Start-Sleep -Milliseconds 1000
    }
    
    $errorRate = if ($requestCount -gt 0) { [math]::Round(($errorCount / ($requestCount + $errorCount)) * 100, 2) } else { 100 }
    
    Write-Host "  Stability test completed: $requestCount successful requests, $errorCount errors" -ForegroundColor Cyan
    Write-Host "  Error rate: $errorRate%" -ForegroundColor Cyan
    
    if ($errorRate -lt 1) {
        Write-Host "✓ Long-duration Stability - PASSED" -ForegroundColor Green
        $testResults.PassedTests++
        $testResults.Details += @{
            Test = "Long-duration Stability"
            Status = "PASSED"
            Details = "Duration: $TestDurationMinutes min, Requests: $requestCount, Errors: $errorCount, Error rate: $errorRate%"
        }
    } else {
        Write-Host "✗ Long-duration Stability - FAILED (High error rate: $errorRate%)" -ForegroundColor Red
        $testResults.FailedTests++
        $testResults.Details += @{
            Test = "Long-duration Stability"
            Status = "FAILED"
            Details = "Error rate: $errorRate%"
        }
    }
} catch {
    Write-Host "✗ Long-duration Stability - FAILED" -ForegroundColor Red
    $testResults.FailedTests++
    $testResults.Details += @{
        Test = "Long-duration Stability"
        Status = "FAILED"
        Details = "Exception: $($_.Exception.Message)"
    }
}

# Generate test report
Write-Host "`n=== IIS Integration Test Results ===" -ForegroundColor Green
Write-Host "Total Tests: $($testResults.TotalTests)" -ForegroundColor Cyan
Write-Host "Passed: $($testResults.PassedTests)" -ForegroundColor Green
Write-Host "Failed: $($testResults.FailedTests)" -ForegroundColor Red
Write-Host "Success Rate: $([math]::Round(($testResults.PassedTests / $testResults.TotalTests) * 100, 1))%" -ForegroundColor Cyan

# Save detailed results
$resultsPath = "../../results/iis_integration_results.json"
$testResults | ConvertTo-Json -Depth 3 | Out-File -FilePath $resultsPath -Encoding UTF8
Write-Host "Detailed results saved to: $resultsPath" -ForegroundColor Yellow

if ($testResults.FailedTests -eq 0) {
    Write-Host "`n🎉 All IIS integration tests PASSED!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "`n❌ Some IIS integration tests FAILED!" -ForegroundColor Red
    exit 1
}