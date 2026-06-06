# PowerShell Maven wrapper for Java 25+
$env:JAVA_HOME = "C:\Program Files\Java\jdk-25"
$wrapperJar = "$PSScriptRoot\.mvn\wrapper\maven-wrapper.jar"
$mavenArgs = "-Dmaven.multiModuleProjectDirectory=$PSScriptRoot"

& "$env:JAVA_HOME\bin\java.exe" `
    -classpath $wrapperJar `
    $mavenArgs `
    org.apache.maven.wrapper.MavenWrapperMain @args
exit $LASTEXITCODE
