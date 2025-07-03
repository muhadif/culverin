#!/bin/bash
set -e

echo "Installing culverin for macOS..."

# Check if cargo is installed
if ! command -v cargo &> /dev/null; then
    echo "Cargo is not installed. Installing Rust and Cargo..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
fi

# Check if Xcode command line tools are installed
if ! xcode-select -p &> /dev/null; then
    echo "Xcode Command Line Tools not found. Installing..."
    xcode-select --install

    echo "Please wait for Xcode Command Line Tools to finish installing, then run this script again."
    exit 1
fi

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    echo "Homebrew not found. Installing..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
fi

# Install fontconfig using Homebrew
echo "Installing system dependencies..."
brew install fontconfig

# Install culverin
cargo install --path .

echo "culverin has been installed successfully!"
echo "You can now use it by running 'culverin' from your terminal."
echo "Run 'culverin --help' to see available commands."
