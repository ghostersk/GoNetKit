@echo off
echo Compiling Windows resource file...

REM Check if windres is available (part of MinGW/MSYS2)
where windres >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: windres not found. Please install MinGW-w64 or MSYS2.
    echo Download from: https://www.msys2.org/
    echo After installation, run: pacman -S mingw-w64-x86_64-toolchain
    pause
    exit /b 1
)

REM Check if favicon.ico exists
if not exist "web\favicon.ico" (
    echo Error: web\favicon.ico not found!
    echo Please ensure your favicon.ico file is in the web folder.
    pause
    exit /b 1
)

REM Compile resource file to .syso
windres -i resource.rc -o resource.syso -O coff
if %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to compile resource file
    pause
    exit /b 1
)

echo Resource file compiled successfully: resource.syso
echo Now you can build the executable with: go build -ldflags="-H=windowsgui" -o headeranalyzer.exe

pause
