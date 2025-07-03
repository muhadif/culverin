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
$vsInstalled = $false

# Check for Visual Studio 2022 Build Tools
if (Test-Path "HKLM:\SOFTWARE\Microsoft\VisualStudio\Setup\Instances") {
    $instances = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\VisualStudio\Setup\Instances"
    foreach ($instance in $instances) {
        $installationPath = Get-ItemPropertyValue -Path $instance.PSPath -Name "InstallationPath" -ErrorAction SilentlyContinue
        if ($installationPath) {
            $vcComponentsPath = Join-Path -Path $installationPath -ChildPath "VC\Tools\MSVC"
            if (Test-Path $vcComponentsPath) {
                $vsInstalled = $true
                break
            }
        }
    }
}

# Check for older Visual Studio versions
if (-not $vsInstalled) {
    $vsRegPaths = @(
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\14.0",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\15.0",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\16.0",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualStudio\17.0"
    )

    foreach ($path in $vsRegPaths) {
        if (Test-Path $path) {
            $vsInstalled = $true
            break
        }
    }
}

# Check for Visual C++ Build Tools
if (-not $vsInstalled) {
    $buildToolsPaths = @(
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\VisualCppBuildTools",
        "HKLM:\SOFTWARE\Microsoft\VisualCppBuildTools"
    )

    foreach ($path in $buildToolsPaths) {
        if (Test-Path $path) {
            $vsInstalled = $true
            break
        }
    }
}

if (-not $vsInstalled) {
    Write-Host "Visual Studio Build Tools not found. Please install Visual Studio Build Tools with C++ support." -ForegroundColor Yellow
    Write-Host "You can download it from: https://visualstudio.microsoft.com/visual-cpp-build-tools/" -ForegroundColor Yellow
    Write-Host "During installation, make sure to select 'Desktop development with C++' workload." -ForegroundColor Yellow
    Write-Host "After installation, run this script again." -ForegroundColor Yellow

    # Ask if user wants to download and install automatically
    $installNow = Read-Host "Would you like to download and install Visual Studio Build Tools now? (y/n)"
    if ($installNow -eq 'y' -or $installNow -eq 'Y') {
        Write-Host "Downloading Visual Studio Build Tools installer..." -ForegroundColor Green
        $installerPath = "$env:TEMP\vs_buildtools.exe"
        Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vs_buildtools.exe" -OutFile $installerPath

        Write-Host "Starting installation. Please follow the installer prompts and select 'Desktop development with C++' workload." -ForegroundColor Green
        Start-Process -FilePath $installerPath -ArgumentList "--wait", "--passive", "--norestart", "--includeRecommended", "--add", "Microsoft.VisualStudio.Workload.VCTools" -Wait

        Write-Host "Installation completed. Please restart this script to continue." -ForegroundColor Green
    }

    exit 1
}

# Install culverin
Write-Host "Building and installing culverin..." -ForegroundColor Green
cargo install --path .

Write-Host "culverin has been installed successfully!" -ForegroundColor Green
Write-Host "You can now use it by running 'culverin' from your terminal." -ForegroundColor Green
Write-Host "Run 'culverin --help' to see available commands." -ForegroundColor Green
