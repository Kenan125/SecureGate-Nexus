<#
.SYNOPSIS
    PowerShell Maven wrapper for SecureGate Nexus (Java 25+)
.DESCRIPTION
    Use this instead of mvnw.cmd on Windows. It sets JAVA_HOME to JDK 25
    and invokes Maven through the wrapper JAR.
.EXAMPLE
    .\mvnw.ps1 spring-boot:run
    .\mvnw.ps1 clean compile
    .\mvnw.ps1 --version
#>
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$MavenArgs
)

$JdkHome = "C:\Program Files\Java\jdk-25"
$JavaExe = Join-Path $JdkHome "bin\java.exe"

if (-not (Test-Path $JavaExe)) {
    Write-Error "JDK 25 not found at $JdkHome. Install JDK 25 or edit mvnw.ps1."
    exit 1
}

$env:JAVA_HOME = $JdkHome
$WrapperJar = Join-Path $PSScriptRoot ".mvn\wrapper\maven-wrapper.jar"

if (-not (Test-Path $WrapperJar)) {
    Write-Error "Maven wrapper JAR not found at $WrapperJar"
    exit 1
}

& $JavaExe -classpath $WrapperJar `
    "-Dmaven.multiModuleProjectDirectory=$PSScriptRoot" `
    org.apache.maven.wrapper.MavenWrapperMain @MavenArgs
exit $LASTEXITCODE
