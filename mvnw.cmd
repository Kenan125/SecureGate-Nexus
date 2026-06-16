@echo off
setlocal enabledelayedexpansion

:: Use JAVA_HOME if already set and valid
if defined JAVA_HOME (
    if exist "%JAVA_HOME%\bin\java.exe" goto :found_java
)

:: Search for any JDK 25 installation (accepts jdk-25, jdk-25.0.1, jdk25, etc.)
for /d %%D in ("C:\Program Files\Java\jdk-25*" "C:\Program Files\Java\jdk25*" "C:\Program Files\Java\jdk-25*") do (
    if exist "%%~D\bin\java.exe" (
        set "JAVA_HOME=%%~D"
        goto :found_java
    )
)

:: Fallback: search for any JDK 21 installation (accepts jdk-21, jdk-21.0.5, jdk21, etc.)
for /d %%D in ("C:\Program Files\Java\jdk-21*" "C:\Program Files\Java\jdk21*" "C:\Program Files\Java\jdk-21*") do (
    if exist "%%~D\bin\java.exe" (
        set "JAVA_HOME=%%~D"
        goto :found_java
    )
)

echo ERROR: No JDK 25 or JDK 21 found in "C:\Program Files\Java\"
echo Install JDK 21+ or set JAVA_HOME to point to a valid JDK.
exit /b 1

:found_java
set "JAVA_EXE=%JAVA_HOME%\bin\java.exe"
echo Using Java: %JAVA_HOME%

set "DIRNAME=%~dp0"
set "DIRNAME=%DIRNAME:~0,-1%"
set "WRAPPER_JAR=%DIRNAME%\.mvn\wrapper\maven-wrapper.jar"

if not exist "%WRAPPER_JAR%" (
    echo ERROR: Maven wrapper JAR not found at %WRAPPER_JAR%
    echo Run: powershell -File mvnw.ps1 to use PowerShell wrapper instead.
    exit /b 1
)

"%JAVA_EXE%" -classpath "%WRAPPER_JAR%" "-Dmaven.multiModuleProjectDirectory=%DIRNAME%" org.apache.maven.wrapper.MavenWrapperMain %*
exit /b %ERRORLEVEL%
