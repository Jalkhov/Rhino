#!/usr/bin/env bash
# Construye, firma y publica el paquete de base de datos en el sitio local.
#
# Es el sustituto manual del flujo db.yml. Toma las reglas del paquete `core` de
# YARA Forge, les saca los hashes que declaran, las compila, firma el manifiesto
# y deja el resultado en web/public/db/<canal>/.
#
# Uso: web/tools/publish-db.sh <clave-privada> [canal]
set -euo pipefail

raiz="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
clave="${1:?uso: web/tools/publish-db.sh <clave-privada> [canal]}"
canal="${2:-stable}"
destino="$raiz/web/public/db/$canal"
nuevo="$destino.nuevo"
anterior="$destino.anterior"
work="$(mktemp -d)"
trap 'rm -rf "$work" "$nuevo"' EXIT

echo "Descargando el paquete core de YARA Forge..."
curl -sSL https://api.github.com/repos/YARAHQ/yara-forge/releases/latest \
  | grep -o 'https://[^"]*core[^"]*\.zip' | head -1 \
  | xargs -I{} curl -sSL -o "$work/core.zip" {}
unzip -q -o "$work/core.zip" -d "$work"

reglas="$(find "$work" -name 'yara-rules-core.yar' -print -quit)"
[ -n "$reglas" ] || { echo "no se encontró yara-rules-core.yar" >&2; exit 1; }

cd "$raiz"
cargo run --release -q -p rhino-db -- build \
  --rules "$reglas" --out "$nuevo" --channel "$canal" --key "$clave"

# La verificación usa la clave pública compilada dentro de Rhino: es el mismo
# control que aplicará el usuario final.
cargo run --release -q -p rhino-db -- verify --package "$nuevo"

# Publicación atómica: el paquete se arma al lado y se intercambia de una vez,
# para que el sitio nunca sirva una versión a medio escribir.
rm -rf "$anterior"
if [ -d "$destino" ]; then mv "$destino" "$anterior"; fi
mv "$nuevo" "$destino"
rm -rf "$anterior"

echo
echo "publicado en web/public/db/$canal/ ($(du -sh "$destino" | cut -f1))"
echo "para probarlo: cargo run -p rhino-db -- update http://localhost:27182/db/$canal ~/.local/share/Rhino/rhino-db"
