#!/bin/sh
# Make a self-signed certificate for local development: certs/dev-cert.pem and certs/dev-key.pem.
# It is valid for localhost, 127.0.0.1, ::1 and any extra names or IPs given as arguments,
# e.g. scripts/make_dev_cert.sh 192.168.1.50 scanner.lan
# The VS Code extension trusts it through the vulnScanner.caCertificate setting (point it at dev-cert.pem).
set -eu
cd "$(dirname "$0")/.."
mkdir -p certs
san="DNS:localhost,IP:127.0.0.1,IP:::1"
for name in "$@"; do
  case "$name" in
    *[!0-9.]*) san="$san,DNS:$name" ;;
    *) san="$san,IP:$name" ;;
  esac
done
openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
  -keyout certs/dev-key.pem -out certs/dev-cert.pem \
  -subj "/CN=Vuln Scanner dev" \
  -addext "subjectAltName=$san" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign" \
  -addext "extendedKeyUsage=serverAuth" 2>/dev/null
# The container runs as a non-root user and must read the key. This is a dev-only key.
chmod 644 certs/dev-key.pem certs/dev-cert.pem
echo "Wrote certs/dev-cert.pem and certs/dev-key.pem for: $san"
