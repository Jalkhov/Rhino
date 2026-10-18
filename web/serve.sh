#!/usr/bin/env bash
# Sirve el sitio de Rhino en local.
#
# Uso: web/serve.sh [puerto]
#
# Escucha solo en 127.0.0.1. Para probar desde una máquina virtual con Windows
# hay que cambiar el --bind a 0.0.0.0 y abrir el puerto mientras dure la prueba.
set -euo pipefail

raiz="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
puerto="${1:-27182}"

# El servidor necesita que las carpetas existan aunque todavía no se haya
# publicado nada; así la página puede decir "no hay paquete" en vez de fallar.
mkdir -p "$raiz/web/public/db/stable" "$raiz/web/public/db/beta" "$raiz/web/public/app"

echo "Rhino: http://localhost:$puerto/"
echo "canal estable: http://localhost:$puerto/db/stable"
exec python3 -m http.server "$puerto" --bind 127.0.0.1 --directory "$raiz/web/public"
