@echo off
echo Building HeaderAnalyzer for Windows...

REM Clean previous builds
if exist "headeranalyzer.exe" del "headeranalyzer.exe"

REM Check if resource.syso exists
if not exist "resource.syso" (
    echo Warning: resource.syso not found. Building resource file first...
    call build-resource.bat
    if %ERRORLEVEL% NEQ 0 (
        echo Failed to build resource file. Continuing without icon...
    )
)

REM Set environment variables for Windows build
set GOOS=windows
set GOARCH=amd64

REM Build the executable with Windows GUI subsystem (no console window)
echo Building executable...
go build -ldflags="-H=windowsgui -s -w" -o headeranalyzer.exe
if %ERRORLEVEL% NEQ 0 (
    echo Error: Build failed
    pause
    exit /b 1
)

echo Build completed successfully: headeranalyzer.exe
echo The executable includes:
echo - Embedded web assets
echo - Application icon (if resource.syso exists)
echo - No console window
echo - System tray support

REM Check file size
for %%A in (headeranalyzer.exe) do echo File size: %%~zA bytes

pause
