#!/usr/bin/env bash
# Construye y firma el paquete de base de datos a mano. Sustituye al flujo db.yml
# mientras GitHub Actions esté desactivado.
#
# Uso: scripts/update-db.sh <clave-privada> [canal]
set -euo pipefail

key="${1:?uso: scripts/update-db.sh <clave-privada> [canal]}"
channel="${2:-stable}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "Descargando el paquete core de YARA Forge..."
curl -sSL https://api.github.com/repos/YARAHQ/yara-forge/releases/latest \
  | grep -o 'https://[^"]*core[^"]*\.zip' | head -1 \
  | xargs -I{} curl -sSL -o "$work/core.zip" {}
unzip -q -o "$work/core.zip" -d "$work"

rules="$(find "$work" -name 'yara-rules-core.yar' -print -quit)"
[ -n "$rules" ] || { echo "no se encontró yara-rules-core.yar" >&2; exit 1; }

cargo run --release -q -p rhino-db -- build \
  --rules "$rules" --out db-package --channel "$channel" --key "$key"
# La verificación usa la clave pública compilada dentro de Rhino: es el mismo
# control que aplicará el usuario final.
cargo run --release -q -p rhino-db -- verify --package db-package
