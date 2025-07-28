#!/bin/bash

# Format all Rust code in the project

set -e

echo "🎨 Formatting Security Token Standard code..."

# Format all Rust code
cargo fmt --all

echo "✅ Code formatting complete!"

# Optional: Check if everything is formatted correctly
echo "🔍 Verifying formatting..."
if cargo fmt --all -- --check; then
    echo "✅ All code is properly formatted!"
else
    echo "❌ Some files still need formatting. This shouldn't happen after fmt."
    exit 1
fi
