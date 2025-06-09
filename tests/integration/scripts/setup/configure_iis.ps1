# IIS Configuration Script for KSP Integration Testing
# Configures IIS with SSL/TLS bindings and client certificate authentication

param(
    [string]$SiteName = "SupacryptKSPTestSite",
    [string]$Port = "8444",
    [string]$CertificateThumbprint = ""
)

$ErrorActionPreference = "Stop"

Write-Host "Configuring IIS for KSP integration testing..." -ForegroundColor Yellow

# Import WebAdministration module
Import-Module WebAdministration -ErrorAction SilentlyContinue

# Check if IIS is installed
if (-not (Get-WindowsFeature -Name IIS-WebServerRole | Where-Object InstallState -eq "Installed")) {
    Write-Warning "IIS is not installed. Installing IIS features..."
    Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole, IIS-WebServer, IIS-CommonHttpFeatures, IIS-HttpErrors, IIS-HttpLogging, IIS-Security, IIS-RequestFiltering, IIS-StaticContent, IIS-DefaultDocument, IIS-DirectoryBrowsing -All
}

# Create test website directory
$siteDirectory = "C:\inetpub\$SiteName"
if (-not (Test-Path $siteDirectory)) {
    New-Item -ItemType Directory -Path $siteDirectory -Force | Out-Null
    Write-Host "Created site directory: $siteDirectory" -ForegroundColor Cyan
}

# Create simple test page
$testPage = @"
<!DOCTYPE html>
<html>
<head>
    <title>Supacrypt KSP SSL Test</title>
</head>
<body>
    <h1>Supacrypt KSP SSL/TLS Test Page</h1>
    <p>Server Time: $(Get-Date)</p>
    <p>Client Certificate: <span id="clientCert">None</span></p>
    <script>
        if (window.crypto && window.crypto.subtle) {
            document.getElementById('clientCert').innerText = 'WebCrypto API Available';
        }
    </script>
</body>
</html>
"@

Set-Content -Path "$siteDirectory\index.html" -Value $testPage

# Remove existing test site if it exists
if (Get-Website -Name $SiteName -ErrorAction SilentlyContinue) {
    Remove-Website -Name $SiteName -Confirm:$false
    Write-Host "Removed existing test site" -ForegroundColor Cyan
}

# Create new website
New-Website -Name $SiteName -Path $siteDirectory -Port 80
Write-Host "Created website: $SiteName" -ForegroundColor Cyan

# Generate test certificate using KSP if no thumbprint provided
if ([string]::IsNullOrEmpty($CertificateThumbprint)) {
    Write-Host "Generating test certificate using Supacrypt KSP..." -ForegroundColor Cyan
    
    try {
        # Use CNG/KSP for certificate generation
        $certParams = @{
            Subject = "CN=$SiteName.test.local"
            KeyAlgorithm = "RSA"
            KeyLength = 2048
            Provider = "Supacrypt KSP"
            KeyUsage = "DigitalSignature,KeyEncipherment"
            CertStoreLocation = "Cert:\LocalMachine\My"
            NotAfter = (Get-Date).AddYears(1)
        }
        
        $cert = New-SelfSignedCertificate @certParams
        $CertificateThumbprint = $cert.Thumbprint
        Write-Host "Generated certificate with thumbprint: $CertificateThumbprint" -ForegroundColor Green
    } catch {
        Write-Warning "Failed to generate certificate with KSP: $_"
        Write-Host "Falling back to default provider..." -ForegroundColor Yellow
        $cert = New-SelfSignedCertificate -Subject "CN=$SiteName.test.local" -CertStoreLocation "Cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(1)
        $CertificateThumbprint = $cert.Thumbprint
    }
}

# Configure HTTPS binding
try {
    New-WebBinding -Name $SiteName -Protocol https -Port $Port -SslFlags 0
    
    # Bind certificate to HTTPS binding
    $binding = Get-WebBinding -Name $SiteName -Protocol https
    $binding.AddSslCertificate($CertificateThumbprint, "my")
    
    Write-Host "Configured HTTPS binding on port $Port with certificate $CertificateThumbprint" -ForegroundColor Green
} catch {
    Write-Warning "Failed to configure HTTPS binding: $_"
}

# Configure client certificate authentication
Write-Host "Configuring client certificate authentication..." -ForegroundColor Cyan
Set-WebConfiguration -Filter "system.webServer/security/access" -Value @{sslFlags="Ssl,SslNegotiateCert,SslRequireCert"} -PSPath "IIS:" -Location "$SiteName"

# Configure certificate trust settings
Set-WebConfiguration -Filter "system.webServer/security/authentication/clientCertificateMappingAuthentication" -Value @{enabled="true"} -PSPath "IIS:" -Location "$SiteName"

# Create web.config for additional SSL settings
$webConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <system.webServer>
        <security>
            <access sslFlags="Ssl,SslNegotiateCert,SslRequireCert" />
            <authentication>
                <clientCertificateMappingAuthentication enabled="true" />
            </authentication>
        </security>
        <defaultDocument>
            <files>
                <add value="index.html" />
            </files>
        </defaultDocument>
    </system.webServer>
</configuration>
"@

Set-Content -Path "$siteDirectory\web.config" -Value $webConfig

Write-Host "IIS configuration complete!" -ForegroundColor Green
Write-Host "Test site available at: https://localhost:$Port" -ForegroundColor Cyan
Write-Host "Certificate thumbprint: $CertificateThumbprint" -ForegroundColor Cyan