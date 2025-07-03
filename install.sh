#!/bin/bash
set -e

echo "Installing culverin..."

# Check if cargo is installed
if ! command -v cargo &> /dev/null; then
    echo "Cargo is not installed. Installing Rust and Cargo..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
fi

# Install culverin
cargo install --path .

echo "culverin has been installed successfully!"
echo "You can now use it by running 'culverin' from your terminal."
echo "Run 'culverin --help' to see available commands."