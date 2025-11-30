#!/bin/bash
# Script de copie des artefacts depuis l'optimiseur Python vers le moteur C++
# Usage: ./setup_data.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPTIMIZER_OUT="../optimizer/outputs"
DATA_DIR="$SCRIPT_DIR/data"

echo "=== FoxEngine Data Setup ==="
echo "Source: $OPTIMIZER_OUT"
echo "Destination: $DATA_DIR"
echo ""

# Vérification de l'existence des fichiers source
if [ ! -f "$OPTIMIZER_OUT/firewall.sh" ]; then
    echo "[ERROR] firewall.sh not found in $OPTIMIZER_OUT"
    echo "Please run the Python optimizer first:"
    echo "  cd ../optimizer && python main.py --rules snort3-community.rules"
    exit 1
fi

# Copie des fichiers
echo "[*] Copying firewall.sh..."
cp "$OPTIMIZER_OUT/firewall.sh" "$DATA_DIR/"

echo "[*] Copying patterns.txt..."
cp "$OPTIMIZER_OUT/patterns.txt" "$DATA_DIR/"

echo "[*] Copying rules_config.msgpack..."
cp "$OPTIMIZER_OUT/rules_config.msgpack" "$DATA_DIR/"

echo ""
echo "[OK] All artifacts copied successfully!"
echo ""
echo "Next steps:"
echo "  1. mkdir build && cd build"
echo "  2. cmake .."
echo "  3. make -j\$(nproc)"
echo "  4. sudo ./fox-engine"
