#!/usr/bin/env bash

# Deploy or upgrade the SSTS programs and verify the deployed artifacts.

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SCRIPT_NAME="$(basename "$0")"
SOLANA_CLI_VERSION="2.2.0"
DEFAULT_REPO_URL="https://github.com/Solana-Security-Token-Standard/solana-security-token-standard"

CLUSTER="${CLUSTER:-devnet}"
CLUSTER_EXPLICIT=false
RPC_URL="${RPC_URL:-}"
URL_EXPLICIT=false
MODE="auto"
PROGRAMS="both"
OUT_DIR="${SBF_OUT_DIR:-${BPF_OUT_DIR:-target/deploy}}"
MAIN_PROGRAM_SO="${PROGRAM_PATH:-}"
HOOK_PROGRAM_SO="${TRANSFER_HOOK_PROGRAM_PATH:-}"
MAIN_PROGRAM_KEYPAIR="${PROGRAM_KEYPAIR_PATH:-}"
HOOK_PROGRAM_KEYPAIR="${TRANSFER_HOOK_KEYPAIR_PATH:-}"
MAIN_PROGRAM_ID="${PROGRAM_ID:-}"
HOOK_PROGRAM_ID="${TRANSFER_HOOK_PROGRAM_ID:-}"
DEPLOYER_KEYPAIR="${DEPLOYER_KEYPAIR:-${SOLANA_KEYPAIR:-$HOME/.config/solana/id.json}}"
UPGRADE_AUTHORITY_KEYPAIR="${UPGRADE_AUTHORITY_KEYPAIR:-}"
REPO_URL="${REPO_URL:-$DEFAULT_REPO_URL}"
COMMIT_HASH="${COMMIT_HASH:-}"
AIRDROP_SOL="${AIRDROP_SOL:-2}"

GENERATE_MISSING_KEYPAIRS=false
UPDATE_SOURCE_IDS=false
INSTALL_POLICY="prompt"
YES=false
NON_INTERACTIVE=false
SKIP_AIRDROP=false
SKIP_BUILD=false
SKIP_DEPLOY=false
SKIP_VERIFY_UPLOAD=false
DRY_RUN=false

STEP=0
RESULT_DIR=""

usage() {
    cat <<EOF
Usage:
  $SCRIPT_NAME [devnet|testnet|mainnet|localnet] [options]
  $SCRIPT_NAME --help
  $SCRIPT_NAME -h

Deploys or upgrades the SSTS main program and transfer-hook program, then
verifies that the deployed on-chain executable hashes match the verified local
build artifacts. By default it targets devnet and processes both programs.

Cluster and signing:
  --cluster <name>                  devnet, testnet, mainnet, localnet, or custom
  --url <rpc-url>                   Explicit RPC URL. If passed without --cluster, explorer links are omitted.
  --deployer-keypair <path>         Fee-payer keypair. Default: DEPLOYER_KEYPAIR, SOLANA_KEYPAIR, or ~/.config/solana/id.json
  --upgrade-authority-keypair <p>   Upgrade authority keypair. Default: deployer keypair
  --mode <auto|deploy|upgrade>      auto deploys new programs or upgrades existing ones. Default: auto
  --programs <both|main|hook>       Which programs to process. Default: both
  --program-only                    Shortcut for --programs main
  --hook-only                       Shortcut for --programs hook

Program artifacts and IDs:
  --out-dir <path>                  Build output directory. Default: target/deploy
  --main-program-so <path>          Main program .so path. Default: <out-dir>/security_token_program.so
  --hook-program-so <path>          Transfer hook .so path. Default: <out-dir>/security_token_transfer_hook.so
  --main-program-keypair <path>     Main program keypair. Default: <out-dir>/security_token_program-keypair.json
  --program-keypair <path>          Alias for --main-program-keypair
  --hook-program-keypair <path>     Transfer hook keypair. Default: <out-dir>/security_token_transfer_hook-keypair.json
  --main-program-id <pubkey>        Main program ID for upgrades or --skip-deploy verification without the program keypair
  --program-id <pubkey>             Alias for --main-program-id
  --hook-program-id <pubkey>        Transfer hook program ID for upgrades or --skip-deploy verification without the program keypair
  --generate-missing-keypairs       Generate missing program keypairs with solana-keygen
  --update-source-ids               Update declare_id!/constants/IDL/clients to match the program keypairs

Verification:
  --repo-url <url>                  Repository URL used by solana-verify verify-from-repo
  --commit-hash <sha>               Commit hash used by verify-from-repo. Default: current HEAD
  --skip-build                      Reuse existing .so files instead of running solana-verify build
  --skip-deploy                     Do not deploy; verify existing deployed programs
  --skip-verify-upload              Skip solana-verify verify-from-repo upload, but still compare hashes
  --dry-run                         Check parameters/dependencies and build, but do not deploy or upload verification

Dependency handling:
  --install-missing                 Install supported missing tools without prompting
  --no-install                      Never install missing tools; fail with instructions
  --yes, -y                         Answer yes to interactive install prompts
  --non-interactive                 Never prompt; fail unless --install-missing was provided

Devnet/testnet helpers:
  --skip-airdrop                    Do not request devnet/testnet SOL
  --airdrop-sol <amount>            SOL to request for devnet/testnet. Default: 2

Examples:
  # Autonomous devnet deployment or upgrade using existing keypairs.
  $SCRIPT_NAME --cluster devnet \\
    --deployer-keypair ./deployer.json \\
    --main-program-keypair ./security_token_program-keypair.json \\
    --hook-program-keypair ./security_token_transfer_hook-keypair.json \\
    --install-missing

  # Generate missing program keypairs, update source IDs, then stop if changes need to be committed.
  $SCRIPT_NAME --cluster devnet --generate-missing-keypairs --update-source-ids

  # Mainnet upgrade using a specific already-pushed commit.
  $SCRIPT_NAME --cluster mainnet --mode upgrade \\
    --deployer-keypair ./fee-payer.json \\
    --upgrade-authority-keypair ./upgrade-authority.json \\
    --main-program-id <main-program-id> \\
    --hook-program-id <hook-program-id> \\
    --commit-hash <git-sha>

Important:
  If --update-source-ids changes source files, commit and push those changes
  before running with verification upload enabled. verify-from-repo can only
  verify code that exists at the supplied repository commit.
EOF
}

fail() {
    printf '\nERROR: %s\n' "$*" >&2
    if [[ -n "$RESULT_DIR" ]]; then
        printf 'Logs/results directory: %s\n' "$RESULT_DIR" >&2
    fi
    exit 1
}

on_error() {
    local status="$1"
    local line="$2"
    local command="$3"
    printf '\nERROR: command failed at line %s with exit code %s:\n  %s\n' "$line" "$status" "$command" >&2
    if [[ -n "$RESULT_DIR" ]]; then
        printf 'Logs/results directory: %s\n' "$RESULT_DIR" >&2
    fi
    exit "$status"
}

trap 'on_error "$?" "$LINENO" "$BASH_COMMAND"' ERR

log() {
    printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2
}

step() {
    STEP=$((STEP + 1))
    printf '\n== Step %d: %s ==\n' "$STEP" "$*" >&2
}

ok() {
    printf 'OK: %s\n' "$*" >&2
}

warn() {
    printf 'WARN: %s\n' "$*" >&2
}

need_value() {
    local flag="$1"
    local value="${2:-}"
    if [[ -z "$value" || "$value" == --* ]]; then
        fail "$flag requires a value. Run $SCRIPT_NAME --help for usage."
    fi
}

absolute_path() {
    local path="$1"
    if [[ "$path" = /* ]]; then
        printf '%s\n' "$path"
    else
        printf '%s/%s\n' "$ROOT_DIR" "$path"
    fi
}

confirm() {
    local prompt="$1"

    if [[ "$INSTALL_POLICY" == "install" || "$YES" == true ]]; then
        return 0
    fi

    if [[ "$INSTALL_POLICY" == "fail" || "$NON_INTERACTIVE" == true ]]; then
        return 1
    fi

    read -r -p "$prompt [y/N] " answer
    case "$answer" in
        y|Y|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

run() {
    local description="$1"
    shift
    log "$description"
    "$@"
}

run_stream() {
    local description="$1"
    local logfile="$2"
    shift 2

    log "$description"
    set +e
    "$@" > >(tee "$logfile" >&2) 2>&1
    local status=$?
    set -e
    if [[ "$status" -ne 0 ]]; then
        fail "$description failed with exit code $status. See log: $logfile"
    fi
}

extract_signature() {
    local file="$1"
    grep -Eo '[1-9A-HJ-NP-Za-km-z]{80,100}' "$file" | tail -n 1 || true
}

extract_hash() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    grep -Eo '[a-fA-F0-9]{64}' "$file" | tail -n 1 || true
}

extract_main_source_id() {
    sed -nE 's/.*declare_id!\("([^"]+)".*/\1/p' program/src/lib.rs | head -n 1
}

extract_hook_source_id() {
    sed -nE 's/.*declare_id!\("([^"]+)".*/\1/p' transfer_hook/src/lib.rs | head -n 1
}

extract_hook_main_source_id() {
    awk '
        /SECURITY_TOKEN_PROGRAM_ID/ { seen=1 }
        seen && /pubkey!\("/ {
            sub(/^.*pubkey!\("/, "")
            sub(/".*$/, "")
            print
            exit
        }
    ' transfer_hook/src/lib.rs
}

extract_constants_hook_source_id() {
    awk '
        /TRANSFER_HOOK_PROGRAM_ID/ { seen=1 }
        seen && /pubkey!\("/ {
            sub(/^.*pubkey!\("/, "")
            sub(/".*$/, "")
            print
            exit
        }
    ' program/src/constants.rs
}

extract_idl_main_source_id() {
    sed -nE 's/.*"address": "([^"]+)".*/\1/p' idl/security_token_program.json | tail -n 1
}

want_main() {
    [[ "$PROGRAMS" == "both" || "$PROGRAMS" == "main" ]]
}

want_hook() {
    [[ "$PROGRAMS" == "both" || "$PROGRAMS" == "hook" ]]
}

explorer_address_url() {
    local id="$1"
    case "$CLUSTER" in
        mainnet) printf 'https://explorer.solana.com/address/%s\n' "$id" ;;
        devnet|testnet) printf 'https://explorer.solana.com/address/%s?cluster=%s\n' "$id" "$CLUSTER" ;;
        *) printf 'Explorer link unavailable for custom/local RPC: %s\n' "$RPC_URL" ;;
    esac
}

explorer_tx_url() {
    local sig="$1"
    if [[ -z "$sig" ]]; then
        printf 'not detected in CLI output\n'
        return
    fi
    case "$CLUSTER" in
        mainnet) printf 'https://explorer.solana.com/tx/%s\n' "$sig" ;;
        devnet|testnet) printf 'https://explorer.solana.com/tx/%s?cluster=%s\n' "$sig" "$CLUSTER" ;;
        *) printf 'Explorer link unavailable for custom/local RPC: %s\n' "$RPC_URL" ;;
    esac
}

install_solana_cli() {
    command -v curl >/dev/null 2>&1 || fail "curl is required to install Solana CLI $SOLANA_CLI_VERSION. Install curl or rerun with --no-install."
    run "Installing Solana CLI $SOLANA_CLI_VERSION via Anza installer" \
        sh -c "$(curl -sSfL "https://release.anza.xyz/v${SOLANA_CLI_VERSION}/install")"
    export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
}

ensure_solana_cli() {
    if ! command -v solana >/dev/null 2>&1; then
        if confirm "Solana CLI is missing. Install Solana CLI $SOLANA_CLI_VERSION now?"; then
            install_solana_cli
        else
            fail "Solana CLI is required. Install version $SOLANA_CLI_VERSION or rerun with --install-missing."
        fi
    fi

    local current
    current="$(solana --version | awk '{print $2}')"
    if [[ "$current" != "$SOLANA_CLI_VERSION" ]]; then
        if confirm "Solana CLI version is $current, expected $SOLANA_CLI_VERSION. Install pinned version now?"; then
            install_solana_cli
            current="$(solana --version | awk '{print $2}')"
        fi
    fi

    current="$(solana --version | awk '{print $2}')"
    [[ "$current" == "$SOLANA_CLI_VERSION" ]] || fail "Solana CLI version $SOLANA_CLI_VERSION is required, found $current. Put the pinned Solana binary first in PATH."
    command -v solana-keygen >/dev/null 2>&1 || fail "solana-keygen was not found after checking Solana CLI installation."
}

ensure_basic_command() {
    local command_name="$1"
    local message="$2"
    command -v "$command_name" >/dev/null 2>&1 || fail "$message"
}

ensure_solana_verify() {
    if command -v solana-verify >/dev/null 2>&1; then
        return
    fi

    ensure_basic_command cargo "cargo is required to install solana-verify. Install Rust from https://rustup.rs/."
    if confirm "solana-verify is missing. Install it with cargo install solana-verify --locked now?"; then
        run "Installing solana-verify" cargo install solana-verify --locked
    else
        fail "solana-verify is required. Install it with: cargo install solana-verify --locked"
    fi
}

ensure_pnpm() {
    if command -v pnpm >/dev/null 2>&1; then
        return
    fi

    if command -v corepack >/dev/null 2>&1; then
        if confirm "pnpm is missing. Enable it through corepack now?"; then
            run "Enabling pnpm through corepack" corepack enable pnpm
            command -v pnpm >/dev/null 2>&1 && return
        fi
    fi

    if command -v npm >/dev/null 2>&1; then
        if confirm "pnpm is still missing. Install it globally with npm now?"; then
            run "Installing pnpm through npm" npm install -g pnpm
            command -v pnpm >/dev/null 2>&1 && return
        fi
    fi

    fail "pnpm is required when --update-source-ids is used. Install pnpm or rerun without --update-source-ids."
}

ensure_shank() {
    if command -v shank >/dev/null 2>&1; then
        return
    fi

    ensure_basic_command cargo "cargo is required to install shank-cli. Install Rust from https://rustup.rs/."
    if confirm "shank is missing. Install shank-cli with cargo now?"; then
        run "Installing shank-cli" cargo install shank-cli --locked
    else
        fail "shank is required to regenerate the IDL. Install it with: cargo install shank-cli --locked"
    fi
}

ensure_docker() {
    command -v docker >/dev/null 2>&1 || fail "Docker is required for solana-verify build/verify-from-repo. Install Docker Desktop and start it."
    if ! docker info >/dev/null 2>&1; then
        fail "Docker is installed but the daemon is not reachable. Start Docker Desktop and rerun the script."
    fi
}

parse_args() {
    if [[ "${1:-}" == "help" || "${1:-}" == "h" || "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
        usage
        exit 0
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --help|-h|help|h)
                usage
                exit 0
                ;;
            --cluster)
                need_value "$1" "${2:-}"
                CLUSTER="$2"
                CLUSTER_EXPLICIT=true
                shift 2
                ;;
            --url|-u)
                need_value "$1" "${2:-}"
                RPC_URL="$2"
                URL_EXPLICIT=true
                shift 2
                ;;
            --deployer-keypair)
                need_value "$1" "${2:-}"
                DEPLOYER_KEYPAIR="$2"
                shift 2
                ;;
            --upgrade-authority-keypair)
                need_value "$1" "${2:-}"
                UPGRADE_AUTHORITY_KEYPAIR="$2"
                shift 2
                ;;
            --mode)
                need_value "$1" "${2:-}"
                MODE="$2"
                shift 2
                ;;
            --programs)
                need_value "$1" "${2:-}"
                PROGRAMS="$2"
                shift 2
                ;;
            --program-only)
                PROGRAMS="main"
                shift
                ;;
            --hook-only)
                PROGRAMS="hook"
                shift
                ;;
            --out-dir)
                need_value "$1" "${2:-}"
                OUT_DIR="$2"
                shift 2
                ;;
            --main-program-so)
                need_value "$1" "${2:-}"
                MAIN_PROGRAM_SO="$2"
                shift 2
                ;;
            --hook-program-so)
                need_value "$1" "${2:-}"
                HOOK_PROGRAM_SO="$2"
                shift 2
                ;;
            --main-program-keypair|--program-keypair)
                need_value "$1" "${2:-}"
                MAIN_PROGRAM_KEYPAIR="$2"
                shift 2
                ;;
            --hook-program-keypair)
                need_value "$1" "${2:-}"
                HOOK_PROGRAM_KEYPAIR="$2"
                shift 2
                ;;
            --main-program-id|--program-id)
                need_value "$1" "${2:-}"
                MAIN_PROGRAM_ID="$2"
                shift 2
                ;;
            --hook-program-id)
                need_value "$1" "${2:-}"
                HOOK_PROGRAM_ID="$2"
                shift 2
                ;;
            --generate-missing-keypairs)
                GENERATE_MISSING_KEYPAIRS=true
                shift
                ;;
            --update-source-ids)
                UPDATE_SOURCE_IDS=true
                shift
                ;;
            --repo-url)
                need_value "$1" "${2:-}"
                REPO_URL="$2"
                shift 2
                ;;
            --commit-hash)
                need_value "$1" "${2:-}"
                COMMIT_HASH="$2"
                shift 2
                ;;
            --skip-build)
                SKIP_BUILD=true
                shift
                ;;
            --skip-deploy)
                SKIP_DEPLOY=true
                shift
                ;;
            --skip-verify-upload)
                SKIP_VERIFY_UPLOAD=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                SKIP_DEPLOY=true
                SKIP_VERIFY_UPLOAD=true
                shift
                ;;
            --install-missing)
                INSTALL_POLICY="install"
                shift
                ;;
            --no-install)
                INSTALL_POLICY="fail"
                shift
                ;;
            --yes|-y)
                YES=true
                shift
                ;;
            --non-interactive)
                NON_INTERACTIVE=true
                shift
                ;;
            --skip-airdrop)
                SKIP_AIRDROP=true
                shift
                ;;
            --airdrop-sol)
                need_value "$1" "${2:-}"
                AIRDROP_SOL="$2"
                shift 2
                ;;
            devnet|testnet|mainnet|localnet|localhost)
                CLUSTER="$1"
                CLUSTER_EXPLICIT=true
                shift
                ;;
            *)
                fail "Unknown argument: $1. Run $SCRIPT_NAME --help for usage."
                ;;
        esac
    done
}

normalize_config() {
    [[ "$CLUSTER" == "localhost" ]] && CLUSTER="localnet"

    if [[ "$URL_EXPLICIT" == true && "$CLUSTER_EXPLICIT" == false ]]; then
        CLUSTER="custom"
    fi

    if [[ -z "$RPC_URL" ]]; then
        case "$CLUSTER" in
            devnet) RPC_URL="https://api.devnet.solana.com" ;;
            testnet) RPC_URL="https://api.testnet.solana.com" ;;
            mainnet) RPC_URL="https://api.mainnet.solana.com" ;;
            localnet) RPC_URL="http://127.0.0.1:8899" ;;
            custom) fail "--url is required when --cluster custom is used." ;;
            *) fail "Unsupported cluster: $CLUSTER. Use devnet, testnet, mainnet, localnet, or pass --url." ;;
        esac
    fi

    case "$MODE" in
        auto|deploy|upgrade) ;;
        *) fail "--mode must be one of: auto, deploy, upgrade" ;;
    esac

    case "$PROGRAMS" in
        both|main|hook) ;;
        *) fail "--programs must be one of: both, main, hook" ;;
    esac

    OUT_DIR="$(absolute_path "$OUT_DIR")"
    [[ -n "$MAIN_PROGRAM_SO" ]] || MAIN_PROGRAM_SO="$OUT_DIR/security_token_program.so"
    [[ -n "$HOOK_PROGRAM_SO" ]] || HOOK_PROGRAM_SO="$OUT_DIR/security_token_transfer_hook.so"
    [[ -n "$MAIN_PROGRAM_ID" || -n "$MAIN_PROGRAM_KEYPAIR" ]] || MAIN_PROGRAM_KEYPAIR="$OUT_DIR/security_token_program-keypair.json"
    [[ -n "$HOOK_PROGRAM_ID" || -n "$HOOK_PROGRAM_KEYPAIR" ]] || HOOK_PROGRAM_KEYPAIR="$OUT_DIR/security_token_transfer_hook-keypair.json"

    MAIN_PROGRAM_SO="$(absolute_path "$MAIN_PROGRAM_SO")"
    HOOK_PROGRAM_SO="$(absolute_path "$HOOK_PROGRAM_SO")"
    [[ -z "$MAIN_PROGRAM_KEYPAIR" ]] || MAIN_PROGRAM_KEYPAIR="$(absolute_path "$MAIN_PROGRAM_KEYPAIR")"
    [[ -z "$HOOK_PROGRAM_KEYPAIR" ]] || HOOK_PROGRAM_KEYPAIR="$(absolute_path "$HOOK_PROGRAM_KEYPAIR")"
    DEPLOYER_KEYPAIR="$(absolute_path "$DEPLOYER_KEYPAIR")"
    [[ -n "$UPGRADE_AUTHORITY_KEYPAIR" ]] || UPGRADE_AUTHORITY_KEYPAIR="$DEPLOYER_KEYPAIR"
    UPGRADE_AUTHORITY_KEYPAIR="$(absolute_path "$UPGRADE_AUTHORITY_KEYPAIR")"

    local timestamp
    timestamp="$(date '+%Y%m%d-%H%M%S')"
    RESULT_DIR="$OUT_DIR/deploy-results/$timestamp"
    mkdir -p "$RESULT_DIR"
}

check_dependencies() {
    step "Checking dependencies"
    ensure_basic_command git "git is required."
    ensure_basic_command awk "awk is required."
    ensure_basic_command sed "sed is required."
    ensure_basic_command grep "grep is required."
    ensure_basic_command cargo "cargo is required. Install Rust from https://rustup.rs/."
    ensure_solana_cli
    ensure_solana_verify

    if [[ "$SKIP_BUILD" != true || "$SKIP_VERIFY_UPLOAD" != true ]]; then
        ensure_docker
    fi

    if [[ "$UPDATE_SOURCE_IDS" == true ]]; then
        ensure_basic_command perl "perl is required for --update-source-ids."
        ensure_pnpm
        ensure_shank
    fi

    ok "Dependencies available"
}

prepare_program_keypair() {
    local label="$1"
    local keypair_path="$2"

    if [[ ! -f "$keypair_path" ]]; then
        if [[ "$GENERATE_MISSING_KEYPAIRS" == true ]]; then
            mkdir -p "$(dirname "$keypair_path")"
            run "Generating $label program keypair at $keypair_path" \
                solana-keygen new --no-bip39-passphrase --silent --outfile "$keypair_path"
        else
            fail "$label program keypair not found: $keypair_path. Provide the keypair path or pass --generate-missing-keypairs."
        fi
    fi

    solana-keygen pubkey "$keypair_path"
}

prepare_keypairs() {
    step "Checking keypairs"

    [[ -f "$DEPLOYER_KEYPAIR" ]] || fail "Deployer fee-payer keypair not found: $DEPLOYER_KEYPAIR"
    [[ -f "$UPGRADE_AUTHORITY_KEYPAIR" ]] || fail "Upgrade authority keypair not found: $UPGRADE_AUTHORITY_KEYPAIR"

    DEPLOYER_PUBKEY="$(solana-keygen pubkey "$DEPLOYER_KEYPAIR")"
    UPGRADE_AUTHORITY_PUBKEY="$(solana-keygen pubkey "$UPGRADE_AUTHORITY_KEYPAIR")"

    if want_main; then
        if [[ -n "$MAIN_PROGRAM_ID" ]]; then
            if [[ "$MODE" == "deploy" && "$SKIP_DEPLOY" != true ]]; then
                fail "--main-program-id cannot be used with --mode deploy. Initial deploys require --main-program-keypair because the program account must sign."
            fi
            if [[ "$GENERATE_MISSING_KEYPAIRS" == true || "$UPDATE_SOURCE_IDS" == true ]]; then
                fail "--main-program-id cannot be combined with --generate-missing-keypairs or --update-source-ids. Use a program keypair when changing source IDs."
            fi
        else
            MAIN_PROGRAM_ID="$(prepare_program_keypair "main" "$MAIN_PROGRAM_KEYPAIR")"
        fi
    fi
    if want_hook; then
        if [[ -n "$HOOK_PROGRAM_ID" ]]; then
            if [[ "$MODE" == "deploy" && "$SKIP_DEPLOY" != true ]]; then
                fail "--hook-program-id cannot be used with --mode deploy. Initial deploys require --hook-program-keypair because the program account must sign."
            fi
            if [[ "$GENERATE_MISSING_KEYPAIRS" == true || "$UPDATE_SOURCE_IDS" == true ]]; then
                fail "--hook-program-id cannot be combined with --generate-missing-keypairs or --update-source-ids. Use a program keypair when changing source IDs."
            fi
        else
            HOOK_PROGRAM_ID="$(prepare_program_keypair "transfer hook" "$HOOK_PROGRAM_KEYPAIR")"
        fi
    fi

    ok "Deployer: $DEPLOYER_PUBKEY"
    ok "Upgrade authority: $UPGRADE_AUTHORITY_PUBKEY"
    [[ -z "$MAIN_PROGRAM_ID" ]] || ok "Main program ID: $MAIN_PROGRAM_ID"
    [[ -z "$HOOK_PROGRAM_ID" ]] || ok "Transfer hook program ID: $HOOK_PROGRAM_ID"
}

update_source_ids() {
    step "Updating source program IDs"

    [[ "$PROGRAMS" == "both" ]] || fail "--update-source-ids requires --programs both so cross-program constants stay consistent."
    [[ -n "$MAIN_PROGRAM_ID" && -n "$HOOK_PROGRAM_ID" ]] || fail "Both program IDs are required for --update-source-ids."

    perl -0pi -e "s/declare_id!\\(\"[^\"]+\"\\)/declare_id!(\"$MAIN_PROGRAM_ID\")/s" program/src/lib.rs
    perl -0pi -e "s/pub static SECURITY_TOKEN_PROGRAM_ID: Pubkey =\\s*pubkey!\\(\"[^\"]+\"\\);/pub static SECURITY_TOKEN_PROGRAM_ID: Pubkey =\n    pubkey!(\"$MAIN_PROGRAM_ID\");/s" transfer_hook/src/lib.rs
    perl -0pi -e "s/declare_id!\\(\"[^\"]+\"\\)/declare_id!(\"$HOOK_PROGRAM_ID\")/s" transfer_hook/src/lib.rs
    perl -0pi -e "s/pub const TRANSFER_HOOK_PROGRAM_ID: Pubkey =\\s*pubkey!\\(\"[^\"]+\"\\);/pub const TRANSFER_HOOK_PROGRAM_ID: Pubkey =\n    pubkey!(\"$HOOK_PROGRAM_ID\");/s" program/src/constants.rs
    perl -0pi -e "s/\"address\": \"[^\"]+\"/\"address\": \"$MAIN_PROGRAM_ID\"/s" idl/security_token_program.json

    if [[ ! -d node_modules ]]; then
        run "Installing JS dependencies for IDL/client generation" pnpm install --frozen-lockfile
    fi
    run "Regenerating IDL" pnpm generate-idl
    run "Regenerating clients" pnpm generate-clients

    ok "Source IDs regenerated"
}

validate_source_ids() {
    step "Validating source IDs against keypairs"

    local mismatches=()
    local source_main source_hook hook_main constants_hook idl_main
    source_main="$(extract_main_source_id)"
    source_hook="$(extract_hook_source_id)"
    hook_main="$(extract_hook_main_source_id)"
    constants_hook="$(extract_constants_hook_source_id)"
    idl_main="$(extract_idl_main_source_id)"

    if want_main; then
        [[ "$source_main" == "$MAIN_PROGRAM_ID" ]] || mismatches+=("program/src/lib.rs declare_id is $source_main, expected $MAIN_PROGRAM_ID")
        [[ "$idl_main" == "$MAIN_PROGRAM_ID" ]] || mismatches+=("idl/security_token_program.json address is $idl_main, expected $MAIN_PROGRAM_ID")
    fi

    if [[ "$PROGRAMS" == "both" ]]; then
        [[ "$source_hook" == "$HOOK_PROGRAM_ID" ]] || mismatches+=("transfer_hook/src/lib.rs declare_id is $source_hook, expected $HOOK_PROGRAM_ID")
        [[ "$hook_main" == "$MAIN_PROGRAM_ID" ]] || mismatches+=("transfer_hook/src/lib.rs SECURITY_TOKEN_PROGRAM_ID is $hook_main, expected $MAIN_PROGRAM_ID")
        [[ "$constants_hook" == "$HOOK_PROGRAM_ID" ]] || mismatches+=("program/src/constants.rs TRANSFER_HOOK_PROGRAM_ID is $constants_hook, expected $HOOK_PROGRAM_ID")
    elif want_hook; then
        [[ "$source_hook" == "$HOOK_PROGRAM_ID" ]] || mismatches+=("transfer_hook/src/lib.rs declare_id is $source_hook, expected $HOOK_PROGRAM_ID")
    fi

    if [[ "${#mismatches[@]}" -gt 0 ]]; then
        printf '%s\n' "${mismatches[@]}" > "$RESULT_DIR/source-id-mismatches.txt"
        fail "Program keypairs do not match source IDs. See $RESULT_DIR/source-id-mismatches.txt. Rerun with --update-source-ids if these are intentional new IDs."
    fi

    ok "Source IDs match program IDs"
}

ensure_verifiable_commit() {
    if [[ "$SKIP_VERIFY_UPLOAD" == true ]]; then
        return
    fi

    step "Checking git commit for verify-from-repo"
    git rev-parse --is-inside-work-tree >/dev/null 2>&1 || fail "verify-from-repo requires a git checkout."

    if [[ -z "$COMMIT_HASH" ]]; then
        COMMIT_HASH="$(git rev-parse HEAD)"
    fi

    local head_hash
    head_hash="$(git rev-parse HEAD)"
    if [[ "$COMMIT_HASH" != "$head_hash" ]]; then
        fail "The local build would use HEAD ($head_hash), but verify-from-repo was asked to use $COMMIT_HASH. Check out that commit before deploying, or omit --commit-hash to use HEAD."
    fi

    local checkout_dir checkout_log checkout_status
    checkout_dir="$(mktemp -d "${TMPDIR:-/tmp}/ssts-verify-checkout.XXXXXX")"
    checkout_log="$RESULT_DIR/repo-commit-checkout.log"
    set +e
    git clone --depth 1 "$REPO_URL" "$checkout_dir/repo" > "$checkout_log" 2>&1
    checkout_status=$?
    if [[ "$checkout_status" -eq 0 ]]; then
        git -C "$checkout_dir/repo" checkout "$COMMIT_HASH" >> "$checkout_log" 2>&1
        checkout_status=$?
    fi
    rm -rf "$checkout_dir"
    set -e
    if [[ "$checkout_status" -ne 0 ]]; then
        fail "The repository URL cannot check out commit $COMMIT_HASH with the same shallow clone strategy used by solana-verify. Ensure the commit is merged into the repository default branch, then rerun. See $checkout_log"
    fi

    local dirty_build_inputs
    dirty_build_inputs="$(git status --porcelain --untracked-files=all -- Cargo.toml Cargo.lock rust-toolchain.toml program transfer_hook)"
    if [[ -n "$dirty_build_inputs" ]]; then
        printf '%s\n' "$dirty_build_inputs" > "$RESULT_DIR/git-status-dirty-build-inputs.txt"
        fail "Program build inputs have uncommitted changes, but verify-from-repo uses committed source only. Commit and push those changes, then rerun with --commit-hash $COMMIT_HASH, or pass --skip-verify-upload. See $RESULT_DIR/git-status-dirty-build-inputs.txt"
    fi

    if [[ -n "$(git status --porcelain)" ]]; then
        git status --short > "$RESULT_DIR/git-status-dirty-non-build-inputs.txt"
        warn "Working tree has uncommitted non-program files. Continuing because program build inputs are clean. See $RESULT_DIR/git-status-dirty-non-build-inputs.txt"
    fi

    ok "Verification commit: $COMMIT_HASH"
}

maybe_airdrop() {
    if [[ "$SKIP_AIRDROP" == true ]]; then
        return
    fi

    case "$CLUSTER" in
        devnet|testnet)
            step "Requesting $AIRDROP_SOL SOL airdrop for fee payer"
            if solana airdrop "$AIRDROP_SOL" "$DEPLOYER_PUBKEY" --url "$RPC_URL"; then
                ok "Airdrop request completed"
            else
                warn "Airdrop failed. This is common on public devnet/testnet faucets. Continuing; deployment will fail explicitly if the fee payer has insufficient SOL."
            fi
            ;;
    esac
}

build_verified_artifact() {
    local label="$1"
    local library_name="$2"
    local artifact_path="$3"

    if [[ "$SKIP_BUILD" == true ]]; then
        [[ -f "$artifact_path" ]] || fail "$label artifact not found with --skip-build: $artifact_path"
        ok "Reusing existing $label artifact: $artifact_path"
        return
    fi

    run_stream "Running verified build for $label" \
        "$RESULT_DIR/${library_name}-build.log" \
        solana-verify build --library-name "$library_name"

    [[ -f "$artifact_path" ]] || fail "$label verified build completed but artifact is missing: $artifact_path"
}

hash_local_artifact() {
    local label="$1"
    local library_name="$2"
    local artifact_path="$3"
    local out_file="$RESULT_DIR/${library_name}-local-hash.txt"

    run_stream "Computing local executable hash for $label" \
        "$out_file" \
        solana-verify get-executable-hash "$artifact_path"

    local hash
    hash="$(extract_hash "$out_file")"
    [[ -n "$hash" ]] || fail "Could not parse local executable hash for $label from $out_file"
    printf '%s\n' "$hash"
}

program_show() {
    local program_id="$1"
    local out_file="$2"
    solana program show "$program_id" --url "$RPC_URL" > "$out_file" 2>&1
}

program_authority_from_show_file() {
    local show_file="$1"
    awk -F': ' '/Authority/ { print $2; exit }' "$show_file" | awk '{ print $1 }'
}

deploy_program() {
    local label="$1"
    local library_name="$2"
    local artifact_path="$3"
    local program_id_arg="$4"
    local program_id="$5"

    local show_before="$RESULT_DIR/${library_name}-show-before.txt"
    local exists=false
    if program_show "$program_id" "$show_before"; then
        exists=true
    fi

    if [[ "$exists" == true && "$MODE" == "deploy" ]]; then
        fail "$label program already exists at $program_id, but --mode deploy was requested. Use --mode upgrade or --mode auto."
    fi
    if [[ "$exists" != true && "$MODE" == "upgrade" ]]; then
        fail "$label program does not exist at $program_id, but --mode upgrade was requested. Use --mode deploy or --mode auto."
    fi

    local action="deploy"
    if [[ "$exists" == true ]]; then
        action="upgrade"
        local current_authority
        current_authority="$(program_authority_from_show_file "$show_before")"
        if [[ -z "$current_authority" || "$current_authority" == "none" ]]; then
            fail "$label program is not upgradeable or has no upgrade authority: $program_id"
        fi
        if [[ "$current_authority" != "$UPGRADE_AUTHORITY_PUBKEY" ]]; then
            fail "$label upgrade authority mismatch. On-chain authority is $current_authority, but supplied keypair is $UPGRADE_AUTHORITY_PUBKEY."
        fi
    fi

    if [[ "$SKIP_DEPLOY" == true ]]; then
        [[ "$exists" == true ]] || fail "--skip-deploy was used, but $label program does not exist at $program_id"
        ok "Skipping deploy for existing $label program: $program_id"
        return
    fi

    local action_label="Deploy"
    [[ "$action" == "upgrade" ]] && action_label="Upgrade"

    run_stream "$action_label $label program" \
        "$RESULT_DIR/${library_name}-deploy.log" \
        solana program deploy "$artifact_path" \
            --program-id "$program_id_arg" \
            --keypair "$UPGRADE_AUTHORITY_KEYPAIR" \
            --fee-payer "$DEPLOYER_KEYPAIR" \
            --upgrade-authority "$UPGRADE_AUTHORITY_KEYPAIR" \
            --url "$RPC_URL" \
            --output json

    local sig
    sig="$(extract_signature "$RESULT_DIR/${library_name}-deploy.log")"
    printf '%s\n' "$sig" > "$RESULT_DIR/${library_name}-deploy-signature.txt"
}

hash_onchain_program() {
    local label="$1"
    local library_name="$2"
    local program_id="$3"
    local out_file="$RESULT_DIR/${library_name}-onchain-hash.txt"

    run_stream "Computing on-chain executable hash for $label" \
        "$out_file" \
        solana-verify get-program-hash -u "$RPC_URL" "$program_id"

    local hash
    hash="$(extract_hash "$out_file")"
    [[ -n "$hash" ]] || fail "Could not parse on-chain hash for $label from $out_file"
    printf '%s\n' "$hash"
}

verify_upload() {
    local label="$1"
    local library_name="$2"
    local program_id="$3"

    if [[ "$SKIP_VERIFY_UPLOAD" == true ]]; then
        ok "Skipping verify-from-repo upload for $label"
        return
    fi

    run_stream "Uploading verified-build evidence for $label" \
        "$RESULT_DIR/${library_name}-verify-upload.log" \
        solana-verify verify-from-repo -u "$RPC_URL" \
            --program-id "$program_id" \
            "$REPO_URL" \
            --commit-hash "$COMMIT_HASH" \
            --library-name "$library_name" \
            -y

    local sig
    sig="$(extract_signature "$RESULT_DIR/${library_name}-verify-upload.log")"
    printf '%s\n' "$sig" > "$RESULT_DIR/${library_name}-verify-signature.txt"
}

process_program() {
    local label="$1"
    local library_name="$2"
    local artifact_path="$3"
    local program_id_arg="$4"
    local program_id="$5"

    build_verified_artifact "$label" "$library_name" "$artifact_path"
    local local_hash
    local_hash="$(hash_local_artifact "$label" "$library_name" "$artifact_path")"

    if [[ "$DRY_RUN" == true ]]; then
        ok "Dry run completed for $label after verified build. Local hash: $local_hash"
        return
    fi

    deploy_program "$label" "$library_name" "$artifact_path" "$program_id_arg" "$program_id"

    local onchain_hash
    onchain_hash="$(hash_onchain_program "$label" "$library_name" "$program_id")"

    if [[ "$local_hash" != "$onchain_hash" ]]; then
        fail "$label hash mismatch. Local hash $local_hash does not match on-chain hash $onchain_hash."
    fi
    ok "$label local and on-chain hashes match: $local_hash"

    verify_upload "$label" "$library_name" "$program_id"
}

write_summary() {
    local summary="$RESULT_DIR/summary.txt"
    {
        printf 'SSTS deployment and verification summary\n'
        printf 'Date: %s\n' "$(date '+%Y-%m-%d %H:%M:%S %Z')"
        printf 'Cluster: %s\n' "$CLUSTER"
        printf 'RPC URL: %s\n' "$RPC_URL"
        printf 'Mode: %s\n' "$MODE"
        printf 'Programs: %s\n' "$PROGRAMS"
        printf 'Deployer: %s\n' "$DEPLOYER_PUBKEY"
        printf 'Upgrade authority: %s\n' "$UPGRADE_AUTHORITY_PUBKEY"
        printf 'Repository: %s\n' "$REPO_URL"
        printf 'Commit hash: %s\n' "${COMMIT_HASH:-not used}"
        printf '\n'

        if want_main; then
            local main_deploy_sig main_verify_sig main_local_hash main_onchain_hash
            main_deploy_sig="$(cat "$RESULT_DIR/security_token_program-deploy-signature.txt" 2>/dev/null || true)"
            main_verify_sig="$(cat "$RESULT_DIR/security_token_program-verify-signature.txt" 2>/dev/null || true)"
            main_local_hash="$(extract_hash "$RESULT_DIR/security_token_program-local-hash.txt")"
            main_onchain_hash="$(extract_hash "$RESULT_DIR/security_token_program-onchain-hash.txt")"
            printf 'Main program\n'
            printf '  Program ID: %s\n' "$MAIN_PROGRAM_ID"
            printf '  Explorer: %s\n' "$(explorer_address_url "$MAIN_PROGRAM_ID")"
            printf '  Program ID input: %s\n' "${MAIN_PROGRAM_KEYPAIR:-$MAIN_PROGRAM_ID}"
            printf '  Artifact: %s\n' "$MAIN_PROGRAM_SO"
            printf '  Local hash: %s\n' "$main_local_hash"
            printf '  On-chain hash: %s\n' "$main_onchain_hash"
            printf '  Deploy/upgrade tx: %s\n' "${main_deploy_sig:-not run or not detected}"
            printf '  Deploy/upgrade tx link: %s\n' "$(explorer_tx_url "${main_deploy_sig:-}")"
            printf '  Verify upload tx: %s\n' "${main_verify_sig:-not run or not detected}"
            printf '  Verify upload tx link: %s\n' "$(explorer_tx_url "${main_verify_sig:-}")"
            printf '\n'
        fi

        if want_hook; then
            local hook_deploy_sig hook_verify_sig hook_local_hash hook_onchain_hash
            hook_deploy_sig="$(cat "$RESULT_DIR/security_token_transfer_hook-deploy-signature.txt" 2>/dev/null || true)"
            hook_verify_sig="$(cat "$RESULT_DIR/security_token_transfer_hook-verify-signature.txt" 2>/dev/null || true)"
            hook_local_hash="$(extract_hash "$RESULT_DIR/security_token_transfer_hook-local-hash.txt")"
            hook_onchain_hash="$(extract_hash "$RESULT_DIR/security_token_transfer_hook-onchain-hash.txt")"
            printf 'Transfer hook program\n'
            printf '  Program ID: %s\n' "$HOOK_PROGRAM_ID"
            printf '  Explorer: %s\n' "$(explorer_address_url "$HOOK_PROGRAM_ID")"
            printf '  Program ID input: %s\n' "${HOOK_PROGRAM_KEYPAIR:-$HOOK_PROGRAM_ID}"
            printf '  Artifact: %s\n' "$HOOK_PROGRAM_SO"
            printf '  Local hash: %s\n' "$hook_local_hash"
            printf '  On-chain hash: %s\n' "$hook_onchain_hash"
            printf '  Deploy/upgrade tx: %s\n' "${hook_deploy_sig:-not run or not detected}"
            printf '  Deploy/upgrade tx link: %s\n' "$(explorer_tx_url "${hook_deploy_sig:-}")"
            printf '  Verify upload tx: %s\n' "${hook_verify_sig:-not run or not detected}"
            printf '  Verify upload tx link: %s\n' "$(explorer_tx_url "${hook_verify_sig:-}")"
            printf '\n'
        fi

        printf 'Logs/results directory: %s\n' "$RESULT_DIR"
    } > "$summary"

    printf '\n'
    cat "$summary"
}

main() {
    parse_args "$@"
    normalize_config

    if [[ "$DRY_RUN" == true ]]; then
        log "Dry run enabled: deployment and verification upload will be skipped."
    fi

    check_dependencies
    prepare_keypairs

    if [[ "$UPDATE_SOURCE_IDS" == true ]]; then
        update_source_ids
    fi

    validate_source_ids
    ensure_verifiable_commit
    maybe_airdrop

    step "Deploying/upgrading and verifying selected programs"
    if want_main; then
        process_program "main" "security_token_program" "$MAIN_PROGRAM_SO" "${MAIN_PROGRAM_KEYPAIR:-$MAIN_PROGRAM_ID}" "$MAIN_PROGRAM_ID"
    fi
    if want_hook; then
        process_program "transfer hook" "security_token_transfer_hook" "$HOOK_PROGRAM_SO" "${HOOK_PROGRAM_KEYPAIR:-$HOOK_PROGRAM_ID}" "$HOOK_PROGRAM_ID"
    fi

    step "Writing result summary"
    write_summary
}

main "$@"
