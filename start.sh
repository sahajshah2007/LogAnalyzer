#!/usr/bin/env bash
# Log analyzer - Startup Script
# Checks dependencies, sets up environment, and launches the full stack.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

VENV_DIR="venv"
MIN_PYTHON_MAJOR=3
MIN_PYTHON_MINOR=10
REQUIRED_FILES=("backend/main.py" "backend/monitor.py" "backend/live_monitor.py" "backend/analyzer.py" "backend/alerts.py" "config.yaml" "requirements.txt")

info()  { echo -e "${CYAN}[*]${NC} $1"; }
ok()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
fail()  { echo -e "${RED}[x]${NC} $1"; exit 1; }

# ── Locate Python ────────────────────────────────────────────────
find_python() {
    for cmd in python3 python; do
        if command -v "$cmd" &>/dev/null; then
            echo "$cmd"
            return
        fi
    done
    return 1
}

PYTHON_CMD=$(find_python) || fail "Python is not installed. Please install Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+."

# ── Check Python version ────────────────────────────────────────
info "Checking Python version..."
PY_VERSION=$("$PYTHON_CMD" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}')")
PY_MAJOR=$("$PYTHON_CMD" -c "import sys; print(sys.version_info.major)")
PY_MINOR=$("$PYTHON_CMD" -c "import sys; print(sys.version_info.minor)")

if [[ "$PY_MAJOR" -lt "$MIN_PYTHON_MAJOR" ]] || { [[ "$PY_MAJOR" -eq "$MIN_PYTHON_MAJOR" ]] && [[ "$PY_MINOR" -lt "$MIN_PYTHON_MINOR" ]]; }; then
    fail "Python ${MIN_PYTHON_MAJOR}.${MIN_PYTHON_MINOR}+ is required (found ${PY_VERSION})."
fi
ok "Python ${PY_VERSION} detected."

# ── Verify project files ────────────────────────────────────────
info "Verifying project files..."
MISSING=0
for f in "${REQUIRED_FILES[@]}"; do
    if [[ ! -f "$f" ]]; then
        warn "Missing: $f"
        MISSING=1
    fi
done
[[ "$MISSING" -eq 1 ]] && fail "One or more required files are missing. Re-clone the repository."
ok "All project files present."

# ── Virtual environment ─────────────────────────────────────────
if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtual environment..."
    "$PYTHON_CMD" -m venv "$VENV_DIR" || fail "Failed to create virtual environment. Install python3-venv (e.g. sudo apt install python3-venv)."
    ok "Virtual environment created."
else
    ok "Virtual environment already exists."
fi

# Activate
# shellcheck disable=SC1091

# Activate virtual environment
source "${VENV_DIR}/bin/activate" 2>/dev/null || fail "Could not activate virtual environment."
ok "Virtual environment activated."

# Always use venv's python
PYTHON="${VENV_DIR}/bin/python"

# Ensure pip is usable in the venv (pip launcher scripts can be broken)
if ! "$PYTHON" -m pip --version &>/dev/null; then
    info "pip is not usable in virtual environment. Repairing pip..."
    "$PYTHON" -m ensurepip --upgrade || fail "Failed to install pip in the virtual environment."
    "$PYTHON" -m pip install --upgrade pip || fail "Failed to upgrade pip in the virtual environment."
    ok "pip repaired in virtual environment."
fi

# ── Install / update dependencies ────────────────────────────────

info "Checking dependencies..."
"$PYTHON" -m pip install --quiet --upgrade pip

# Compare installed packages against requirements
NEEDS_INSTALL=0
while IFS= read -r line; do
    # Skip comments and blank lines
    [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
    # Extract package name (before any version specifier)
    pkg=$(echo "$line" | sed 's/[>=<].*//' | tr '[:upper:]' '[:lower:]')
    if ! "$PYTHON" -m pip show "$pkg" &>/dev/null; then
        NEEDS_INSTALL=1
        break
    fi
done < requirements.txt


if [[ "$NEEDS_INSTALL" -eq 1 ]]; then
    info "Installing dependencies..."
    "$PYTHON" -m pip install --quiet -r requirements.txt || fail "Dependency installation failed."
    ok "Dependencies installed."
else
    ok "All dependencies already installed."
fi

# ── Node.js & frontend deps ──────────────────────────────────────
info "Checking Node.js..."
if ! command -v node &>/dev/null; then
    fail "Node.js is not installed. Install it from https://nodejs.org/"
fi
NODE_VER=$(node --version)
ok "Node.js ${NODE_VER} detected."

info "Checking frontend dependencies..."
if [[ ! -d "frontend/node_modules" ]]; then
    info "Installing frontend npm packages..."
    (cd frontend && npm install --silent) || fail "npm install failed."
    ok "Frontend packages installed."
else
    ok "Frontend packages already installed."
fi

# ── Quick syntax check ───────────────────────────────────────────
info "Running syntax check..."
SYNTAX_OK=1

# Use venv's python for syntax check
for pyfile in backend/main.py backend/monitor.py backend/live_monitor.py backend/analyzer.py backend/alerts.py; do
    if ! $PYTHON -m py_compile "$pyfile" 2>/dev/null; then
        warn "Syntax error in $pyfile"
        SYNTAX_OK=0
    fi
done
[[ "$SYNTAX_OK" -eq 1 ]] && ok "Syntax check passed."

# ── Free ports if already in use ────────────────────────────────
for port in 5005 5006; do
    if fuser "$port/tcp" &>/dev/null 2>&1; then
        warn "Port $port in use — killing existing process..."
        fuser -k "$port/tcp" &>/dev/null 2>&1 || true
        sleep 0.5
    fi
done

# ── Launch full stack ────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "${GREEN}   Starting Log analyzer...                ${NC}"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo -e "  ${CYAN}API Server :${NC} http://localhost:5005"
echo -e "  ${CYAN}Dashboard  :${NC} http://localhost:5006"
echo -e "${GREEN}══════════════════════════════════════════${NC}"
echo ""

# Trap Ctrl+C to kill all background processes
cleanup() {
    echo -e "\n${YELLOW}[!] Shutting down...${NC}"
    kill 0
    wait
    echo -e "${GREEN}[+] All processes stopped.${NC}"
}
trap cleanup SIGINT SIGTERM

# Start FastAPI (background)

# Use venv's python to launch FastAPI
$PYTHON -m uvicorn backend.api:app --host 0.0.0.0 --port 5005 --reload &
API_PID=$!

# Start React dev server (background)
(cd frontend && npm run dev -- --host 0.0.0.0 --port 5006) &
FRONTEND_PID=$!

echo -e "${GREEN}[+]${NC} API server PID:      ${API_PID}"
echo -e "${GREEN}[+]${NC} Frontend server PID: ${FRONTEND_PID}"
echo -e "${CYAN}[*]${NC} Press Ctrl+C to stop both servers."
echo ""

wait
