#!/usr/bin/env bash
# ============================================================
# CS Coin Benchmark Daemon — Installer
# Run this on each node server after distributing benchmark.key
#
# Usage:
#   curl -s <url>/install.sh | bash
#   or:
#   bash install.sh
# ============================================================

set -e

RED='\033[1;31m'
GREEN='\033[1;32m'
CYAN='\033[1;36m'
NC='\033[0m'

BENCH_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_DIR="$HOME/.csbenchmark"
KEY_FILE="$KEY_DIR/benchmark.key"

echo -e "${CYAN}CS Coin Benchmark Daemon Installer${NC}"
echo -e "------------------------------------"

# ---- Node.js check ------------------------------------------------
if ! command -v node &>/dev/null; then
    echo -e "${RED}ERROR: Node.js not found. Install Node.js >= 14 first.${NC}"
    exit 1
fi
NODE_VER=$(node -e "process.stdout.write(process.version)")
echo -e "${GREEN}Node.js: $NODE_VER${NC}"

# ---- npm install --------------------------------------------------
echo -e "${CYAN}Installing npm dependencies...${NC}"
cd "$BENCH_DIR"
npm install --omit=dev 2>/dev/null || npm install --production 2>/dev/null || npm install

# ---- Private key check --------------------------------------------
if [[ ! -f "$KEY_FILE" ]]; then
    echo -e "${RED}ERROR: Private key not found at $KEY_FILE${NC}"
    echo -e "${CYAN}Copy the benchmark.key file to $KEY_FILE and re-run.${NC}"
    echo -e "  mkdir -p $KEY_DIR && chmod 700 $KEY_DIR"
    echo -e "  cp benchmark.key $KEY_FILE && chmod 600 $KEY_FILE"
    exit 1
fi
echo -e "${GREEN}Private key found: $KEY_FILE${NC}"

# ---- pm2 ----------------------------------------------------------
if ! command -v pm2 &>/dev/null; then
    echo -e "${CYAN}Installing pm2...${NC}"
    npm install -g pm2 2>/dev/null || {
        mkdir -p "$HOME/.npm-global"
        npm config set prefix "$HOME/.npm-global"
        npm install -g pm2
        export PATH="$HOME/.npm-global/bin:$PATH"
        grep -q "npm-global" "$HOME/.bashrc" || \
            echo 'export PATH="$HOME/.npm-global/bin:$PATH"' >> "$HOME/.bashrc"
    }
fi
PM2=$(command -v pm2 || echo "$HOME/.npm-global/bin/pm2")

# ---- Stop old instance if running ---------------------------------
$PM2 delete csbenchd 2>/dev/null || true

# ---- Start daemon -------------------------------------------------
echo -e "${CYAN}Starting csbenchd...${NC}"
$PM2 start "$BENCH_DIR/daemon.js" --name csbenchd
$PM2 save

# ---- Test ---------------------------------------------------------
sleep 2
STATUS=$(node "$BENCH_DIR/cli.js" getstatus 2>/dev/null | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null || echo "?")

if [[ "$STATUS" == "online" ]]; then
    echo -e "${GREEN}csbenchd is running!${NC}"
    echo -e "${CYAN}Benchmark will complete in a few minutes.${NC}"
    echo -e "${CYAN}Check status: csbench-cli getstatus true${NC}"
else
    echo -e "${RED}WARNING: Could not confirm daemon status. Check: $PM2 logs csbenchd${NC}"
fi

echo -e ""
echo -e "${GREEN}Installation complete.${NC}"
