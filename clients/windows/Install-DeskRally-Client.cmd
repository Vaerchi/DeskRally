@echo off
setlocal
set "PSModulePath=%SystemRoot%\System32\WindowsPowerShell\v1.0\Modules"
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0install-client.ps1"
set "DESKRALLY_INSTALL_RESULT=%ERRORLEVEL%"
if not "%DESKRALLY_INSTALL_RESULT%"=="0" echo Installation failed. See the error above.
pause
exit /b %DESKRALLY_INSTALL_RESULT%
