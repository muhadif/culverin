# PowerShell script to install culverin on Windows

Write-Host "Installing culverin for Windows..." -ForegroundColor Green

# Check if Rust is installed
$rustupPath = Get-Command rustup -ErrorAction SilentlyContinue
if (-not $rustupPath) {
    Write-Host "Rust is not installed. Installing Rust and Cargo..." -ForegroundColor Yellow
    
    # Download rustup-init.exe
    Invoke-WebRequest -Uri https://win.rustup.rs/x86_64 -OutFile rustup-init.exe
    
    # Run rustup-init.exe with default settings
    Start-Process -FilePath .\rustup-init.exe -ArgumentList "-y" -Wait
    
    # Remove the installer
    Remove-Item -Path .\rustup-init.exe
    
    # Update PATH for the current session
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "User") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "Machine")
}

# Check if Visual Studio Build Tools are installed
$vsPath = Get-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0" -ErrorAction SilentlyContinue
if (-not $vsPath) {
    Write-Host "Visual Studio Build Tools not found. Please install Visual Studio Build Tools with C++ support." -ForegroundColor Yellow
    Write-Host "You can download it from: https://visualstudio.microsoft.com/visual-cpp-build-tools/" -ForegroundColor Yellow
    Write-Host "After installation, run this script again." -ForegroundColor Yellow
    exit 1
}

# Install culverin
Write-Host "Building and installing culverin..." -ForegroundColor Green
cargo install --path .

Write-Host "culverin has been installed successfully!" -ForegroundColor Green
Write-Host "You can now use it by running 'culverin' from your terminal." -ForegroundColor Green
Write-Host "Run 'culverin --help' to see available commands." -ForegroundColor Green