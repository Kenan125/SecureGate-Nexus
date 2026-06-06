@echo off
setlocal

set "JAVA_HOME=C:\Program Files\Java\jdk-25"
set "JAVA_EXE=%JAVA_HOME%\bin\java.exe"

if not exist "%JAVA_EXE%" (
    echo ERROR: Java 25 not found at %JAVA_HOME%
    echo Install JDK 25 or edit mvnw.cmd to point to the correct path.
    exit /b 1
)

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
