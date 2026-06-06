@echo off
setlocal
echo.
echo ============================================
echo   SecureGate Nexus - Setup ^& Run
echo ============================================
echo.

:: Generate keys if not present
if not exist "keys\private.pem" (
    echo [1/2] Generating RSA keys...
    powershell -ExecutionPolicy Bypass -File generate-keys.ps1
    echo.
)

:: Run the application
echo [2/2] Starting application...
echo.
call mvnw.cmd spring-boot:run
exit /b %ERRORLEVEL%
