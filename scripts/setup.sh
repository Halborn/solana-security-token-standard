#!/bin/bash

# Security Token Development Setup Script
# This script sets up the development environment for the Security Token Standard

set -e

echo "🔧 Setting up Security Token Standard development environment..."

# Check if Rust is installed
if ! command -v rustc &> /dev/null; then
    echo "❌ Rust is not installed. Please install Rust first: https://rustup.rs/"
    exit 1
fi

# Check if Solana CLI is installed
if ! command -v solana &> /dev/null; then
    echo "📦 Installing Solana CLI..."
    sh -c "$(curl -sSfL https://release.solana.com/stable/install)"
    export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
fi

# Install required Rust components
echo "🦀 Installing Rust components..."
rustup component add rustfmt clippy

# Install cargo tools
echo "🔨 Installing cargo tools..."
cargo install cargo-audit || echo "cargo-audit already installed"
cargo install cargo-deny || echo "cargo-deny already installed"
cargo install cargo-expand || echo "cargo-expand already installed"

# Set Solana to devnet
echo "🌐 Configuring Solana CLI for devnet..."
solana config set --url https://api.devnet.solana.com

# Generate a new keypair if it doesn't exist
if [ ! -f ~/.config/solana/id.json ]; then
    echo "🔑 Generating new Solana keypair..."
    solana-keygen new --no-bip39-passphrase
fi

# Build the program
echo "🏗️  Building Security Token program..."
cargo build-sbf --manifest-path program/Cargo.toml

# Build the client
echo "📚 Building Rust client..."
cargo build --manifest-path client/rust/Cargo.toml

# Run tests
echo "🧪 Running tests..."
cargo test --all

# Request airdrop for development
echo "💰 Requesting SOL airdrop for development..."
solana airdrop 2 || echo "Airdrop failed, you may need to request manually"

echo "✅ Development environment setup complete!"
echo ""
echo "Next steps:"
echo "1. Deploy your program: ./scripts/deploy.sh"
echo "2. Run integration tests: cargo test --manifest-path tests/Cargo.toml"
echo "3. Start developing! 🚀"
