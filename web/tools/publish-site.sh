#!/usr/bin/env bash
# Publica la web en la rama `gh-pages`, que es la que sirve GitHub Pages.
#
# La fuente sigue siendo `web/public/` en `main`. Aquí se publica solo lo que
# debe verse: el paquete de la protección (`db/`) va por releases, firmado y
# verificado, y los ejecutables (`app/`) también. Duplicarlos en la web sería
# servir dos veces lo mismo con dos controles distintos.
set -euo pipefail

raiz=$(cd "$(dirname "$0")/../.." && pwd)
origen="$raiz/web/public"
remoto=$(git -C "$raiz" remote get-url origin)
temporal=$(mktemp -d)
trap 'rm -rf "$temporal"' EXIT

cp -r "$origen/." "$temporal/"
rm -rf "$temporal/db" "$temporal/app"

cd "$temporal"
git init -q -b gh-pages
git remote add origin "$remoto"
git add -A
git -c user.name="Rhino" -c user.email="rhino@localhost" \
  commit -q -m "site: publica la web de Rhino"
git push -q --force origin gh-pages

echo "publicado en gh-pages: https://jalkhov.github.io/Rhino/"
