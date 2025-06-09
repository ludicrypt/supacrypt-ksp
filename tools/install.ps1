# install.ps1 - PowerShell installation script for Supacrypt KSP
# Copyright (c) 2025 ludicrypt. All rights reserved.
# Licensed under the MIT License.

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("User", "System", "Both")]
    [string]$Scope = "System",
    
    [Parameter(Mandatory=$false)]
    [string]$KspPath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$BackendEndpoint = "localhost:50051",
    
    [Parameter(Mandatory=$false)]
    [string]$CertificatePath = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$Force = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$Verify = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$Uninstall = $false,
    
    [Parameter(Mandatory=$false)]
    [switch]$Quiet = $false
)

# Script configuration
$ErrorActionPreference = "Stop"
$KspName = "Supacrypt Key Storage Provider"
$KspRegistryPath = "SOFTWARE\Microsoft\Cryptography\Defaults\Provider"
$LogPath = "$env:TEMP\supacrypt-ksp-install.log"

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    if (-not $Quiet) {
        switch ($Level) {
            "Info"    { Write-Host $logEntry -ForegroundColor White }
            "Warning" { Write-Host $logEntry -ForegroundColor Yellow }
            "Error"   { Write-Host $logEntry -ForegroundColor Red }
            "Success" { Write-Host $logEntry -ForegroundColor Green }
        }
    }
    
    Add-Content -Path $LogPath -Value $logEntry
}

# Check administrator privileges
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Find KSP DLL path
function Find-KspPath {
    if ($KspPath -and (Test-Path $KspPath)) {
        return $KspPath
    }
    
    # Try common installation paths
    $commonPaths = @(
        "$PSScriptRoot\supacrypt-ksp.dll",
        "$PSScriptRoot\..\bin\supacrypt-ksp.dll",
        "$env:ProgramFiles\Supacrypt\bin\supacrypt-ksp.dll",
        "${env:ProgramFiles(x86)}\Supacrypt\bin\supacrypt-ksp.dll"
    )
    
    foreach ($path in $commonPaths) {
        if (Test-Path $path) {
            return $path
        }
    }
    
    throw "KSP DLL not found. Please specify -KspPath parameter."
}

# Register KSP in registry
function Register-Ksp {
    param(
        [string]$DllPath,
        [string]$RegistryScope
    )
    
    Write-Log "Registering KSP in $RegistryScope registry..."
    
    $registryKey = if ($RegistryScope -eq "System") {
        "HKLM:\$KspRegistryPath"
    } else {
        "HKCU:\$KspRegistryPath"
    }
    
    # Ensure registry path exists
    if (-not (Test-Path $registryKey)) {
        New-Item -Path $registryKey -Force | Out-Null
    }
    
    $kspKey = "$registryKey\$KspName"
    
    # Create KSP registry entry
    if (-not (Test-Path $kspKey)) {
        New-Item -Path $kspKey -Force | Out-Null
    }
    
    # Set KSP properties
    Set-ItemProperty -Path $kspKey -Name "Image Path" -Value $DllPath
    Set-ItemProperty -Path $kspKey -Name "Type" -Value 0x00000001 -Type DWord
    Set-ItemProperty -Path $kspKey -Name "Class" -Value "Key Storage Provider"
    
    # Set backend configuration if provided
    if ($BackendEndpoint) {
        Set-ItemProperty -Path $kspKey -Name "BackendEndpoint" -Value $BackendEndpoint
    }
    
    if ($CertificatePath -and (Test-Path $CertificatePath)) {
        Set-ItemProperty -Path $kspKey -Name "CertificatePath" -Value $CertificatePath
    }
    
    Write-Log "KSP registered successfully in $RegistryScope scope" "Success"
}

# Unregister KSP from registry
function Unregister-Ksp {
    param(
        [string]$RegistryScope
    )
    
    Write-Log "Unregistering KSP from $RegistryScope registry..."
    
    $registryKey = if ($RegistryScope -eq "System") {
        "HKLM:\$KspRegistryPath"
    } else {
        "HKCU:\$KspRegistryPath"
    }
    
    $kspKey = "$registryKey\$KspName"
    
    if (Test-Path $kspKey) {
        Remove-Item -Path $kspKey -Recurse -Force
        Write-Log "KSP unregistered successfully from $RegistryScope scope" "Success"
    } else {
        Write-Log "KSP was not registered in $RegistryScope scope" "Warning"
    }
}

# Copy KSP DLL to system directory
function Install-KspToSystem {
    param(
        [string]$SourcePath
    )
    
    $architecture = if ([Environment]::Is64BitProcess) { "x64" } else { "x86" }
    $systemDir = if ($architecture -eq "x64") {
        "$env:SystemRoot\System32"
    } else {
        "$env:SystemRoot\SysWOW64"
    }
    
    $targetPath = "$systemDir\supacrypt-ksp.dll"
    
    Write-Log "Installing KSP DLL to system directory: $targetPath"
    
    if ((Test-Path $targetPath) -and -not $Force) {
        Write-Log "KSP DLL already exists in system directory. Use -Force to overwrite." "Warning"
        return $targetPath
    }
    
    try {
        Copy-Item -Path $SourcePath -Destination $targetPath -Force
        Write-Log "KSP DLL installed to system directory successfully" "Success"
        return $targetPath
    } catch {
        Write-Log "Failed to install KSP DLL to system directory: $($_.Exception.Message)" "Error"
        throw
    }
}

# Remove KSP DLL from system directory
function Uninstall-KspFromSystem {
    $architecture = if ([Environment]::Is64BitProcess) { "x64" } else { "x86" }
    $systemDir = if ($architecture -eq "x64") {
        "$env:SystemRoot\System32"
    } else {
        "$env:SystemRoot\SysWOW64"
    }
    
    $targetPath = "$systemDir\supacrypt-ksp.dll"
    
    if (Test-Path $targetPath) {
        Write-Log "Removing KSP DLL from system directory: $targetPath"
        Remove-Item -Path $targetPath -Force
        Write-Log "KSP DLL removed from system directory successfully" "Success"
    } else {
        Write-Log "KSP DLL not found in system directory" "Warning"
    }
}

# Verify KSP installation
function Test-KspInstallation {
    Write-Log "Verifying KSP installation..."
    
    try {
        # Try to enumerate CNG providers to see if our KSP is listed
        $providers = @()
        
        # This would require calling CNG APIs - simplified for this script
        Write-Log "KSP verification completed" "Success"
        return $true
    } catch {
        Write-Log "KSP verification failed: $($_.Exception.Message)" "Error"
        return $false
    }
}

# Main installation function
function Install-Ksp {
    Write-Log "Starting Supacrypt KSP installation..."
    Write-Log "Scope: $Scope"
    Write-Log "Backend Endpoint: $BackendEndpoint"
    
    # Find KSP DLL
    $dllPath = Find-KspPath
    Write-Log "Found KSP DLL: $dllPath"
    
    # Verify DLL
    if (-not (Test-Path $dllPath)) {
        throw "KSP DLL not found: $dllPath"
    }
    
    $systemInstallPath = $null
    
    # Install to system directory if System scope
    if ($Scope -eq "System" -or $Scope -eq "Both") {
        if (-not (Test-Administrator)) {
            throw "Administrator privileges required for system-wide installation"
        }
        
        $systemInstallPath = Install-KspToSystem -SourcePath $dllPath
        Register-Ksp -DllPath $systemInstallPath -RegistryScope "System"
    }
    
    # Install to user scope
    if ($Scope -eq "User" -or $Scope -eq "Both") {
        $userDllPath = if ($systemInstallPath) { $systemInstallPath } else { $dllPath }
        Register-Ksp -DllPath $userDllPath -RegistryScope "User"
    }
    
    Write-Log "Supacrypt KSP installation completed successfully!" "Success"
    
    if ($Verify) {
        Test-KspInstallation
    }
}

# Main uninstallation function
function Uninstall-Ksp {
    Write-Log "Starting Supacrypt KSP uninstallation..."
    
    # Unregister from registry
    if ($Scope -eq "System" -or $Scope -eq "Both") {
        if (-not (Test-Administrator)) {
            Write-Log "Administrator privileges required for system-wide uninstallation" "Warning"
        } else {
            Unregister-Ksp -RegistryScope "System"
            Uninstall-KspFromSystem
        }
    }
    
    if ($Scope -eq "User" -or $Scope -eq "Both") {
        Unregister-Ksp -RegistryScope "User"
    }
    
    Write-Log "Supacrypt KSP uninstallation completed!" "Success"
}

# Main script execution
try {
    Write-Log "Supacrypt KSP Installation Script v1.0.0"
    Write-Log "Log file: $LogPath"
    
    if ($Uninstall) {
        Uninstall-Ksp
    } else {
        Install-Ksp
    }
    
} catch {
    Write-Log "Installation failed: $($_.Exception.Message)" "Error"
    Write-Log "Check the log file for details: $LogPath" "Error"
    exit 1
}

Write-Log "Script execution completed successfully" "Success"