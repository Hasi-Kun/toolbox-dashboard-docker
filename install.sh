#!/usr/bin/env bash
set -e

ZIP_FILE="toolbox-dashboard.zip"

echo "================================="
echo " Toolbox Dashboard Installer"
echo "================================="

if [ -z "$1" ]; then
  echo ""
  echo "Usage:"
  echo "  ./install.sh example.com"
  echo "  ./install.sh example.com toolbox"
  echo ""
  echo "Arguments:"
  echo "  $1 = base domain (example.com)"
  echo "  $2 = subdomain (default: toolbox)"
  exit 1
fi

BASE_DOMAIN="$1"
SUBDOMAIN="${2:-toolbox}"

TOOLBOX_DOMAIN="${SUBDOMAIN}.${BASE_DOMAIN}"

echo ""
echo "Base domain    : $BASE_DOMAIN"
echo "Toolbox domain : $TOOLBOX_DOMAIN"
echo ""

echo "[1/4] Unzipping..."
unzip -o "$ZIP_FILE"

echo "[2/4] Replacing placeholders..."

find . -type f \
  ! -path "*/node_modules/*" \
  ! -path "*/.git/*" \
  ! -path "*/dist/*" \
  ! -path "*/build/*" \
  -print0 | while IFS= read -r -d '' file; do

    # skip binary files
    if file "$file" | grep -qE "binary|image|archive"; then
      continue
    fi

    sed -i \
      -e "s|toolbox.domain.cc|$TOOLBOX_DOMAIN|g" \
      "$file" 2>/dev/null || true

done

echo "[3/4] Creating Docker network (if missing)..."
docker network create webnet 2>/dev/null || true

echo "[4/4] Starting stack..."
docker compose up -d --build

echo ""
echo "================================="
echo " DONE"
echo "================================="
echo "Access: https://$TOOLBOX_DOMAIN"
echo ""