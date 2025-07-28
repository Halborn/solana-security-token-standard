#!/bin/bash

# Security Token Program Deployment Script

set -e

PROGRAM_NAME="security_token_program"
PROGRAM_PATH="program/target/deploy/${PROGRAM_NAME}.so"
KEYPAIR_PATH="program/target/deploy/${PROGRAM_NAME}-keypair.json"

echo "🚀 Deploying Security Token Program..."

# Check if program exists
if [ ! -f "$PROGRAM_PATH" ]; then
    echo "❌ Program not found. Building..."
    cargo build-sbf --manifest-path program/Cargo.toml
fi

# Deploy to devnet by default
CLUSTER=${1:-devnet}
echo "📡 Deploying to $CLUSTER..."

# Set cluster
solana config set --url https://api.$CLUSTER.solana.com

# Request airdrop if needed (only for devnet/testnet)
if [ "$CLUSTER" = "devnet" ] || [ "$CLUSTER" = "testnet" ]; then
    echo "💰 Requesting airdrop..."
    solana airdrop 2 || echo "Airdrop failed, continuing..."
fi

# Deploy the program
echo "📦 Deploying program..."
solana program deploy "$PROGRAM_PATH" --keypair "$KEYPAIR_PATH" --url https://api.$CLUSTER.solana.com

# Get program ID
PROGRAM_ID=$(solana-keygen pubkey "$KEYPAIR_PATH")
echo "✅ Program deployed successfully!"
echo "📋 Program ID: $PROGRAM_ID"
echo "🌐 Cluster: $CLUSTER"

# Save program ID to file
echo "$PROGRAM_ID" > program_id.txt
echo "💾 Program ID saved to program_id.txt"

# Verify deployment
echo "🔍 Verifying deployment..."
solana program show "$PROGRAM_ID" --url https://api.$CLUSTER.solana.com

echo ""
echo "🎉 Deployment complete!"
echo "You can now interact with your program using the following ID:"
echo "$PROGRAM_ID"
