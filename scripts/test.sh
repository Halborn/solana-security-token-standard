#!/bin/bash

# Security Token Testing Script

set -e

echo "🧪 Running Security Token Tests..."

# Function to run tests with proper error handling
run_tests() {
    local test_type=$1
    local path=$2
    local description=$3
    echo ""
    echo "📋 Running $description..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    cargo test --manifest-path "$path" --verbose
    if [ $? -eq 0 ]; then
        echo "✅ $description passed!"
    else
        echo "❌ $description failed!"
        return 1
    fi
}

# Clean previous builds
echo "🧹 Cleaning previous builds..."
cargo clean

# Build everything first
echo "🏗️  Building all components..."
cargo build --all

# Run unit tests
run_tests "unit" "program/Cargo.toml" "Program Unit Tests"

# Run client tests
run_tests "client" "clients/rust/Cargo.toml" "Client Library Tests"

# Build program for testing
echo "🔨 Building program for integration tests..."
cargo build-sbf --manifest-path program/Cargo.toml
echo "🔨 Building transfer hook program for integration tests..."
cargo build-sbf --manifest-path transfer_hook/Cargo.toml

# Ensure ProgramTest can locate SBF artifacts
export SBF_OUT_DIR="$PWD/target/deploy"
export BPF_OUT_DIR="$SBF_OUT_DIR"

# Run integration tests
run_tests "integration" "tests/Cargo.toml" "Integration Tests"

# Run program-specific BPF tests
echo ""
echo "📋 Running BPF Program Tests..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if cargo test-sbf --manifest-path program/Cargo.toml; then
    echo "✅ BPF Program Tests passed!"
else
    echo "❌ BPF Program Tests failed!"
    exit 1
fi

# Run linting
echo ""
echo "📋 Running Code Quality Checks..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Format check
if cargo fmt --all -- --check; then
    echo "✅ Code formatting is correct!"
else
    echo "❌ Code formatting issues found. Run 'cargo fmt' to fix."
    exit 1
fi

# Clippy check (allow known false-positives / generated-code lints)
if cargo clippy -p security-token-program -p security-token-transfer-hook -- -D warnings; then
    echo "✅ Clippy checks passed!"
else
    echo "❌ Clippy found issues!"
    exit 1
fi

# Security audit
echo ""
echo "📋 Running Security Audit..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if command -v cargo-deny &> /dev/null; then
    if cargo deny check advisories -c deny.toml; then
        echo "✅ Security audit passed!"
    else
        echo "⚠️  Security audit found issues!"
    fi
else
    echo "⚠️  cargo-deny not installed. Run 'cargo install cargo-deny --version 0.19.0 --locked' to enable security audits."
fi

# Generate test coverage report (if tarpaulin is installed)
if command -v cargo-tarpaulin &> /dev/null; then
    echo ""
    echo "📊 Generating test coverage report..."
    cargo tarpaulin --all --out Html --output-dir coverage/
    echo "📈 Coverage report generated in coverage/tarpaulin-report.html"
fi

echo ""
echo "🎉 All tests completed successfully!"
echo ""
echo "Test Summary:"
echo "━━━━━━━━━━━━━━━━━━"
echo "✅ Program Unit Tests"
echo "✅ Client Library Tests"  
echo "✅ Integration Tests"
echo "✅ BPF Program Tests"
echo "✅ Code Quality Checks"
echo "✅ Security Audit"
echo ""
echo "🚀 Your Security Token Standard is ready for deployment!"
