#!/bin/bash
# ATS-Toolkit Linux/macOS Installation Script
# Requires Python 3.11+ and Poetry

set -e

echo ""
echo "========================================"
echo " ATS-Toolkit v2.0 Installation"
echo "========================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}[ERROR] Python3 not found. Please install Python 3.11+${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "${GREEN}[INFO] Python version: $PYTHON_VERSION${NC}"

# Check Poetry
if ! command -v poetry &> /dev/null; then
    echo -e "${YELLOW}[INFO] Poetry not found. Installing...${NC}"
    curl -sSL https://install.python-poetry.org | python3 -
    export PATH="$HOME/.local/bin:$PATH"
fi

echo ""
echo "[1/4] Installing dependencies..."
poetry install

echo ""
echo "[2/4] Creating configuration..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo -e "${GREEN}[INFO] Created .env from template${NC}"
else
    echo -e "${YELLOW}[INFO] .env already exists${NC}"
fi

echo ""
echo "[3/4] Creating directories..."
mkdir -p logs config

echo ""
echo "[4/4] Verifying installation..."
python3 -c "from src.core import AtsModule; print('Core OK')"

echo ""
echo "========================================"
echo -e "${GREEN} Installation Complete!${NC}"
echo "========================================"
echo ""
echo "Usage:"
echo "  python main.py --api     Start API server"
echo "  python main.py --tui     Start TUI (Phase 1)"
echo "  python main.py list      List modules"
echo ""
