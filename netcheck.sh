#!/usr/bin/env bash
set -euo pipefail

echo "=== /etc/os-release ==="
cat /etc/os-release || true
echo

echo "=== APT sources ==="
cat /etc/apt/sources.list || true
echo

echo "=== HTTPS reachability tests ==="
for URL in \
  "https://deb.debian.org/debian/dists/bookworm/Release" \
  "https://security.debian.org/debian-security/dists/bookworm-security/Release" \
; do
  echo -n "GET $URL ... "
  if curl -fsSL --max-time 10 "$URL" >/dev/null; then
    echo "OK"
  else
    echo "FAILED"
  fi
done
