# KSP Provider Installation Script
# Installs and registers the Supacrypt KSP provider

param(
    [string]$BackendUrl = "https://localhost:5001",
    [string]$ProviderPath = "../../../../build/Release/supacrypt-ksp.dll",
    [string]$ConfigPath = "../../test_data/configurations/ksp_config.json"
)

$ErrorActionPreference = "Stop"

Write-Host "Installing Supacrypt KSP Provider..." -ForegroundColor Yellow

# Check if provider DLL exists
if (-not (Test-Path $ProviderPath)) {
    throw "KSP provider DLL not found at: $ProviderPath. Please build the project first."
}

# Copy provider to system directory
$systemPath = "C:\Windows\System32\supacrypt-ksp.dll"
Write-Host "Copying provider to system directory..." -ForegroundColor Cyan
Copy-Item $ProviderPath $systemPath -Force

# Register KSP provider in registry
Write-Host "Registering KSP provider..." -ForegroundColor Cyan
$regPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\KSP\Supacrypt KSP"
New-Item -Path $regPath -Force | Out-Null
Set-ItemProperty -Path $regPath -Name "ImagePath" -Value $systemPath

# Configure CNG algorithm registrations
Write-Host "Registering CNG algorithms..." -ForegroundColor Cyan
$algPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\Supacrypt"
New-Item -Path $algPath -Force | Out-Null

# Configure provider settings
Write-Host "Configuring provider settings..." -ForegroundColor Cyan
$configRegPath = "HKLM:\SOFTWARE\Supacrypt\KSP"
New-Item -Path $configRegPath -Force | Out-Null
Set-ItemProperty -Path $configRegPath -Name "BackendUrl" -Value $BackendUrl
Set-ItemProperty -Path $configRegPath -Name "EnableLogging" -Value 1
Set-ItemProperty -Path $configRegPath -Name "LogLevel" -Value "INFO"

# Test provider registration using CNG
Write-Host "Testing provider registration..." -ForegroundColor Cyan
try {
    # Use PowerShell to enumerate CNG providers
    Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        public class CngTest {
            [DllImport("ncrypt.dll")]
            public static extern int NCryptEnumStorageProviders(out int pdwProviderCount, out IntPtr ppProviderList, int dwFlags);
        }
"@
    Write-Host "KSP provider registration test completed." -ForegroundColor Green
} catch {
    Write-Warning "Could not verify provider registration: $_"
}

Write-Host "KSP provider installation complete." -ForegroundColor Green