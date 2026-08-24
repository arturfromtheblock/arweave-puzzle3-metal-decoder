#!/bin/bash
set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  🔐 Arweave Puzzle #3 Metal-Decoder - Build Script         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# 1. Clean up
if [ -d "target" ]; then
    echo "[*] Old target/directory found - run `cargo clean`..."
    cargo clean
    echo "[+] Clean done"
    echo ""clea
fi

# 2. Build
echo "[*] Compile gpusolver (release mode)..."
cargo build --release
echo "[+] Build successful"
echo ""

# 3. Binary copy
echo "[*] Copy “Binary” to the root directory..."
cp target/release/gpusolver ./gpusolver
chmod +x ./gpusolver
echo "[+] Binary ready: ./gpusolver"
echo ""

# 4. Clean up
echo "[*] Delete temporary files..."
rm -f shaders.metallib
rm -rf target
echo "[+] Cleanup complete"
echo ""

echo "╔════════════════════════════════════════════════════════════╗"
echo "║  ✅ Build successful!                                      ║"
echo "║                                                            ║"
echo "║  Start with:  ./gpusolver                                  ║"
echo "║  Debug-Mode:  GPU_DEBUG=1 ./gpusolver                      ║"
echo "╚════════════════════════════════════════════════════════════╝"