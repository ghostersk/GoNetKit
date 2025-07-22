@echo off
REM Tailwind CSS Build Script for Header Analyzer (Windows)
REM This script downloads Tailwind CLI and generates CSS for production

setlocal enabledelayedexpansion

set "PROJECT_ROOT=%~dp0.."
set "TAILWIND_CLI=%PROJECT_ROOT%\app_build\tailwindcss-windows-x64.exe"
set "INPUT_CSS=%PROJECT_ROOT%\web\style-custom.css"
set "OUTPUT_CSS=%PROJECT_ROOT%\web\style-compiled.css"
set "CONFIG_FILE=%PROJECT_ROOT%\tailwind.config.js"

echo 🎨 Building Tailwind CSS for Header Analyzer...
echo Project root: %PROJECT_ROOT%

REM Download Tailwind CLI if it doesn't exist
if not exist "%TAILWIND_CLI%" (
    echo 📥 Downloading Tailwind CSS CLI...
    curl -sLO https://github.com/tailwindlabs/tailwindcss/releases/latest/download/tailwindcss-windows-x64.exe
    move tailwindcss-windows-x64.exe "%TAILWIND_CLI%"
    echo ✅ Tailwind CLI downloaded
)

REM Create tailwind.config.js if it doesn't exist
if not exist "%CONFIG_FILE%" (
    echo ⚙️ Creating tailwind.config.js...
    (
        echo /** @type {import('tailwindcss'^).Config} */
        echo module.exports = {
        echo   content: [
        echo     "./web/**/*.html",
        echo     "./web/**/*.js"
        echo   ],
        echo   theme: {
        echo     extend: {
        echo       colors: {
        echo         'header-blue': '#007cba',
        echo         'header-dark': '#1a1a1a'
        echo       }
        echo     },
        echo   },
        echo   plugins: [],
        echo }
    ) > "%CONFIG_FILE%"
    echo ✅ Created tailwind.config.js
)

REM Build CSS
echo 🔨 Building Tailwind CSS...
if "%1"=="--watch" (
    echo 👀 Starting watch mode...
    "%TAILWIND_CLI%" -i "%INPUT_CSS%" -o "%OUTPUT_CSS%" --watch
) else if "%1"=="--dev" (
    echo 🛠️ Building development CSS...
    "%TAILWIND_CLI%" -i "%INPUT_CSS%" -o "%OUTPUT_CSS%"
) else (
    echo 📦 Building production CSS ^(minified^)...
    "%TAILWIND_CLI%" -i "%INPUT_CSS%" -o "%OUTPUT_CSS%" --minify
)

echo ✅ Tailwind CSS build complete!
echo 📍 Output: %OUTPUT_CSS%

REM Show file size
if exist "%OUTPUT_CSS%" (
    for %%F in ("%OUTPUT_CSS%") do (
        echo 📊 Generated CSS size: %%~zF bytes
    )
)

pause
