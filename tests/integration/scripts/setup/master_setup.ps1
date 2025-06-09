# Master Setup Script for KSP Integration Testing
# Sets up complete test environment for enterprise scenarios

param(
    [string]$BackendUrl = "https://localhost:5001",
    [string]$TestDataPath = "../../test_data",
    [switch]$SkipProviderInstall,
    [switch]$Verbose
)

$ErrorActionPreference = "Stop"

Write-Host "=== Supacrypt KSP Integration Test Environment Setup ===" -ForegroundColor Green

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow
if (-not (Test-Path "C:\Windows\System32\certlm.msc")) {
    throw "Certificate management tools not available"
}

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "This script must be run as Administrator"
}

# Install KSP provider if needed
if (-not $SkipProviderInstall) {
    Write-Host "Installing Supacrypt KSP provider..." -ForegroundColor Yellow
    & ".\install_ksp_provider.ps1" -BackendUrl $BackendUrl
    if ($LASTEXITCODE -ne 0) {
        throw "KSP provider installation failed"
    }
}

# Configure test certificates
Write-Host "Setting up test certificates..." -ForegroundColor Yellow
& ".\configure_test_certificates.ps1" -TestDataPath $TestDataPath

# Configure IIS if available
if (Get-WindowsFeature -Name IIS-WebServerRole -ErrorAction SilentlyContinue | Where-Object InstallState -eq "Installed") {
    Write-Host "Configuring IIS for testing..." -ForegroundColor Yellow
    & ".\configure_iis.ps1"
}

# Configure SQL Server if available
$sqlInstances = Get-Service -Name "MSSQL*" -ErrorAction SilentlyContinue
if ($sqlInstances) {
    Write-Host "Configuring SQL Server for testing..." -ForegroundColor Yellow
    & ".\setup_sql_server.ps1"
}

# Prepare Active Directory test environment
if (Get-WindowsFeature -Name AD-Domain-Services -ErrorAction SilentlyContinue | Where-Object InstallState -eq "Installed") {
    Write-Host "Preparing Active Directory environment..." -ForegroundColor Yellow
    & ".\prepare_ad_environment.ps1"
}

# Validate provider installation
Write-Host "Validating KSP provider installation..." -ForegroundColor Yellow
& ".\validate_provider_installation.ps1" -ProviderType "KSP"

Write-Host "=== Setup Complete ===" -ForegroundColor Green
Write-Host "KSP integration test environment is ready." -ForegroundColor Green
Write-Host "Run scenario scripts from ../scenarios/ to execute tests." -ForegroundColor Cyan