# GoNetKit
- Go Web App where you can find many usefull IT tools
- These tools should provide simple and nice way for user to get what they need without requiring signing up or sharing details with 3rd parties.

## Building a Single-File Executable (Windows & Linux)

This app uses Go's `embed` package to bundle all static files (web UI, icons, CSS, etc.) into a single executable. You do **not** need to distribute the `web/` folder separately.
- You will need C building package, especially on Windows as this app using SQLITE, if you do not need password pushser, then remove it and you will not need it to make windows built.
- built scripts are in `app_build` folder, but may need fixing as the app is in development still and I built it on few computers when i have time.

### Prerequisites
- [Go 1.24+](https://golang.org/dl/) (required for `embed`)
- (Optional) [Python 3](https://www.python.org/) with Pillow for icon conversion
```go
go mod init gonetkit
go mod tidy
```
### 1. Prepare Icons (custom icon Optional)
- Place your tray icon and favicon in `web/icon.png` and `web/favicon.png`.
- For Windows tray icon, you **must** use a `.ico` file. Use the provided script:

```sh
# Convert PNG to ICO (requires Python Pillow)
python web/convert_icon.py web/icon.png web/icon.ico
# using ImageMagick convertor
magick envelope.jpg -define icon:auto-resize=16,32,48,64 favicon.ico
# https://github.com/ImageMagick/ImageMagick/releases
ImageMagick\magick.exe web\icon.png -define icon:auto-resize=16,32,48,64 web\favicon.ico
ImageMagick\magick.exe identify web\favicon.ico
# App Icon:

ImageMagick\magick.exe web\icon.png -resize 256x256 -define icon:format=bmp icon.ico
go install github.com/akavel/rsrc@latest
rsrc -arch amd64 -ico icon.ico -o icon.syso
go clean -cache
```

- For Linux, PNG is fine for the tray icon.

### 2. Build for Your Platform

#### Windows (from Windows PowerShell or Command Prompt):
```powershell
# PowerShell (set environment variables before the command)
$env:GOOS="windows"; $env:GOARCH="amd64"; go build -ldflags "-H=windowsgui" -o GoNetKit.exe main.go
```
```cmd
REM Command Prompt (set environment variables before the command)
set GOOS=windows
set GOARCH=amd64
go build -ldflags "-H=windowsgui" -o GoNetKit.exe main.go
```

#### Linux/macOS (from Bash):
```sh
# Build 64-bit Linux executable
GOOS=linux GOARCH=amd64 go build -o goNetKit main.go
```

- The resulting executable contains all static files and icons.

### 2.1. Add an Icon to the Windows Executable

By default, Go does not embed an icon in the .exe. To add your tray/web icon as the Windows executable icon:

1. Install the `rsrc` tool (one-time):
   ```powershell
   go install github.com/akavel/rsrc@latest
   ```
2. Generate a Windows resource file with your icon:
   ```powershell
   rsrc -ico web/icon.ico -o icon.syso
   ```
   This creates `icon.syso` in your project root. Go will automatically include it when building for Windows.
3. Build your app for Windows (see below for PowerShell/CMD syntax).

### 2.2. Build for Your Platform

#### Windows (from Windows PowerShell or Command Prompt):
```powershell
# PowerShell (set environment variables before the command)
$env:GOOS="windows"; $env:GOARCH="amd64"; go build -ldflags "-H=windowsgui" -o GoNetKit.exe main.go
```
```cmd
REM Command Prompt (set environment variables before the command)
set GOOS=windows
set GOARCH=amd64
go build -ldflags "-H=windowsgui" -o GoNetKit.exe main.go
```

- The `-ldflags "-H=windowsgui"` flag prevents a console window from opening when you run the app.
- The `icon.syso` file ensures your executable uses the same icon as the tray and web UI.

#### Linux/macOS (from Bash):
```sh
# Build 64-bit Linux executable
GOOS=linux GOARCH=amd64 go build -o goNetKit main.go
```

- The resulting executable contains all static files and icons.

### 3. Run the App

- Double-click or run from terminal:
  - On Windows: `GoNetKit.exe`
  - On Linux: `./goNetKit`
- The app will start a web server (default: http://localhost:5555) and show a system tray icon.
- Use the tray menu to open the web UI or quit the app.

### 4. Usage Notes
- All static files (HTML, CSS, JS, icons) are embedded. No need to copy the `web/` folder.
- For custom icons, always convert to `.ico` for Windows tray compatibility.
- The favicon is served from the embedded files.

### 5. Troubleshooting
- If icons do not appear in the tray, ensure you used a `.ico` file for Windows.
- If you update static files, rebuild the executable to embed the latest changes.

### 5.1. If the Executable Still Has No Icon

If you followed all steps and the icon still does not appear:

- **Check icon.syso location:** It must be in the same folder as `main.go` when you run `go build`.
- **Check for multiple .syso files:** Only one `.syso` file should be present in your project root. Delete any others.
- **Try a different icon:** Some ICO files may be malformed or missing required sizes. Use a simple 32x32 or 64x64 PNG, convert again, and re-run `rsrc`.
- **Clear Windows icon cache:** Sometimes Windows caches icons. Move the `.exe` to a new folder, or restart Explorer.
- **Verify with Resource Hacker:** Download [Resource Hacker](http://www.angusj.com/resourcehacker/) and open your `.exe` to see if the icon is embedded. If not, the build did not pick up `icon.syso`.
- **Try building without cross-compiling:** If you are cross-compiling, try building directly on Windows.
- **Try go build without -ldflags:** Rarely, the `-ldflags` flag can interfere. Try building with and without it:
  ```powershell
  go build -o GoNetKit.exe main.go
  go build -ldflags "-H=windowsgui" -o GoNetKit.exe main.go
  ```
- **Try go generate:** If you use `go generate`, ensure it does not overwrite or remove `icon.syso`.

If none of these work, please report your Go version, OS, and the exact steps you used.

---

## Favicon and Tray Icon Support

- The app uses both `favicon.png` and `icon.ico` for browser and tray compatibility.
- The browser will use `icon.ico` if available (for Windows/Edge/PWA), and `favicon.png` for other platforms.
- The tray icon is loaded from the embedded `icon.ico`.
- If you update icons, place the new files in `web/` and rebuild.

### How to Add or Update Icons

1. Place your PNG icon (32x32 or 64x64 recommended) in `web/favicon.png`.
2. Convert it to ICO for Windows tray support:
   ```sh
   python web/convert_icon.py web/favicon.png web/icon.ico
   ```
3. Both files must be present in `web/` before building.

## License
MIT
