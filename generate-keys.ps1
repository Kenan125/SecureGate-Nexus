# PowerShell script to generate RSA 2048-bit key pair for JWT signing (PKCS#8 format)
# Auto-detects OpenSSL from common install locations.
# Usage: .\generate-keys.ps1

$keyDir = "keys"
New-Item -ItemType Directory -Force -Path $keyDir | Out-Null

# --- Find OpenSSL ---
$opensslPaths = @(
    "openssl",                                          # If already in PATH
    "C:\Program Files\Git\usr\bin\openssl.exe",        # Git for Windows
    "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",   # OpenSSL Win64
    "C:\Program Files (x86)\OpenSSL-Win32\bin\openssl.exe",
    "C:\Program Files\Git\mingw64\bin\openssl.exe"      # Git MinGW
)

$openssl = $null
foreach ($p in $opensslPaths) {
    if (Get-Command $p -ErrorAction SilentlyContinue) {
        $openssl = $p
        break
    }
    if (Test-Path $p) {
        $openssl = $p
        break
    }
}

if (-not $openssl) {
    Write-Host "ERROR: OpenSSL not found." -ForegroundColor Red
    Write-Host "Install Git for Windows (https://git-scm.com) or OpenSSL."
    Write-Host ""
    Write-Host "Alternative: generate keys manually with Java keytool:"
    Write-Host "  keytool -genkeypair -alias jwt -keyalg RSA -keysize 2048 -keystore keystore.jks"
    exit 1
}

Write-Host "Using OpenSSL: $openssl"

# Generate private key in PKCS#8 format (required by Java PKCS8EncodedKeySpec)
& $openssl genpkey -algorithm RSA -out "$keyDir\private.pem" -pkeyopt rsa_keygen_bits:2048

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to generate private key." -ForegroundColor Red
    exit 1
}

# Extract public key
& $openssl rsa -in "$keyDir\private.pem" -pubout -out "$keyDir\public.pem"

if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Failed to extract public key." -ForegroundColor Red
    exit 1
}

$privSize = (Get-Item "$keyDir\private.pem").Length
$pubSize = (Get-Item "$keyDir\public.pem").Length

Write-Host ""
Write-Host "Keys generated successfully in .\$keyDir\" -ForegroundColor Green
Write-Host "  private.pem ($privSize bytes) - Keep secret, used by auth-server to sign JWTs"
Write-Host "  public.pem  ($pubSize bytes) - Shared with gateway & internal services to verify JWTs"
