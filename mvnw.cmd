@echo off
setlocal

if not defined JAVA_HOME (
    echo ERROR: JAVA_HOME is not set.
    echo Please set JAVA_HOME to your JDK installation directory.
    exit /b 1
)

set "JAVA_EXE=%JAVA_HOME%\bin\java.exe"
if not exist "%JAVA_EXE%" (
    echo ERROR: JAVA_HOME is set to an invalid directory: %JAVA_HOME%
    exit /b 1
)

set "DIRNAME=%~dp0"
set "WRAPPER_JAR=%DIRNAME%.mvn\wrapper\maven-wrapper.jar"
set "MAVEN_PROPS=%DIRNAME%.mvn\wrapper\maven-wrapper.properties"

if not exist "%WRAPPER_JAR%" (
    echo Downloading Maven Wrapper...
    powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://repo.maven.apache.org/maven2/org/apache/maven/wrapper/maven-wrapper/3.3.0/maven-wrapper-3.3.0.jar' -OutFile '%WRAPPER_JAR%' -UseBasicParsing"
)

"%JAVA_EXE%" -classpath "%WRAPPER_JAR%" -Dmaven.multiModuleProjectDirectory="%DIRNAME%" org.apache.maven.wrapper.MavenWrapperMain %*
exit /b %ERRORLEVEL%
