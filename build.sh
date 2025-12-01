#!/bin/bash
# =============================================================================
# FoxEngine Build Script
# =============================================================================
# Usage: ./build.sh [debug|release|clean]
# =============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project directories
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${PROJECT_DIR}/build"
BIN_DIR="${PROJECT_DIR}/bin"

# Build type (default: Release)
BUILD_TYPE="Release"

# Parse arguments
case "${1,,}" in
    debug)
        BUILD_TYPE="Debug"
        echo -e "${YELLOW}>>> Building in DEBUG mode${NC}"
        ;;
    release)
        BUILD_TYPE="Release"
        echo -e "${GREEN}>>> Building in RELEASE mode${NC}"
        ;;
    clean)
        echo -e "${YELLOW}>>> Cleaning build directories...${NC}"
        rm -rf "${BUILD_DIR}" "${BIN_DIR}"
        echo -e "${GREEN}>>> Clean complete!${NC}"
        exit 0
        ;;
    *)
        echo -e "${BLUE}>>> Building in RELEASE mode (default)${NC}"
        ;;
esac

# Check dependencies
echo -e "${BLUE}>>> Checking dependencies...${NC}"

check_dependency() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}ERROR: $1 is not installed!${NC}"
        echo "Please install it with: sudo apt install $2"
        exit 1
    fi
}

check_dependency "cmake" "cmake"
check_dependency "g++" "build-essential"
check_dependency "pkg-config" "pkg-config"

# Check libraries
check_library() {
    if ! pkg-config --exists "$1" 2>/dev/null; then
        echo -e "${YELLOW}WARNING: $1 not found via pkg-config${NC}"
    fi
}

echo -e "${BLUE}>>> Checking libraries...${NC}"
check_library "libnetfilter_queue"

# Create build directory
echo -e "${BLUE}>>> Creating build directory...${NC}"
mkdir -p "${BUILD_DIR}"
cd "${BUILD_DIR}"

# Run CMake
echo -e "${BLUE}>>> Running CMake (${BUILD_TYPE})...${NC}"
cmake -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
      -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
      "${PROJECT_DIR}"

# Get number of CPU cores for parallel build
NPROC=$(nproc 2>/dev/null || echo 4)

# Build
echo -e "${BLUE}>>> Compiling with ${NPROC} threads...${NC}"
make -j"${NPROC}"

# Copy binary to bin directory
echo -e "${BLUE}>>> Installing binary...${NC}"
mkdir -p "${BIN_DIR}"
if [ -f "fox-engine" ]; then
    cp fox-engine "${BIN_DIR}/"
    echo -e "${GREEN}>>> Binary installed to: ${BIN_DIR}/fox-engine${NC}"
fi

# Summary
echo ""
echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}   BUILD SUCCESSFUL!${NC}"
echo -e "${GREEN}=============================================${NC}"
echo -e "Build type: ${BUILD_TYPE}"
echo -e "Binary:     ${BIN_DIR}/fox-engine"
echo ""
echo -e "${YELLOW}To run:${NC}"
echo -e "  sudo ${BIN_DIR}/fox-engine"
echo ""
echo -e "${YELLOW}Setup NFQUEUE (use the dedicated script):${NC}"
echo -e "  sudo ./setup_nfqueue.sh         # Configure iptables"
echo -e "  sudo ./setup_nfqueue.sh clean   # Remove rules"
echo -e "  sudo ./setup_nfqueue.sh status  # Show rules"
echo ""
echo -e "${BLUE}Your topology:${NC}"
echo -e "  [Client 10.10.1.10] <-> [enp66s0f0] FILTREUR [enp4s0f1] <-> [Server 10.10.2.20]"
echo -e "  - Client->Server: Filtered by FoxEngine"
echo -e "  - Server->Client: Accepted (no filtering)"
echo -e "${GREEN}=============================================${NC}"
