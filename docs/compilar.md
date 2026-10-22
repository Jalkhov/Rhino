# Compilar, publicar y servir

[← Volver al README](../README.md)
## Compilación cruzada

Desde Ubuntu, con `cargo-xwin` (target MSVC de Microsoft, que Rust mantiene en Tier 1
para 32 bits) más `clang-cl` y `lld-link`:

```sh
XWIN_ARCH=x86 cargo xwin build --release -p rhino-app --target i686-pc-windows-msvc
```

Se compila `-p rhino-app` y no el workspace entero a propósito: `cargo build --release`
también construiría `rhino-db`, cuyo subcomando `keygen` fabrica claves de firma y no
tiene ninguna razón para viajar al equipo del usuario.

`XWIN_ARCH=x86` es obligatorio: el default de `cargo-xwin` no descarga las librerías de
32 bits. Requiere `cargo install cargo-xwin` y un `lld-link` en el PATH (`rust-lld`
sirve, enlazado con ese nombre). La primera compilación descarga el SDK de Windows
(~1 GB) y queda en caché.

## Integración continua (desactivada por ahora)

Los flujos están escritos y listos en `ci/`, pero **no se ejecutan**: la cuenta de GitHub está
bloqueada por una deuda, así que se sacaron de `.github/workflows/` para que nada falle en
cada `push`. Para reactivarlos basta devolverlos a su sitio; las instrucciones están en
`ci/README.md`.

- **`ci/ci.yml`** — formato (`cargo fmt --check`), `clippy` con los avisos como errores y las
  pruebas, más la compilación cruzada a Windows con una matriz de dos entradas (32 y 64 bits)
  y `fail-fast: false`, para que un fallo en una arquitectura no oculte el estado de la otra.
  Cachea el SDK de Windows: sin esa caché, cada ejecución descargaría ~1 GB.
- **`ci/db.yml`** — el paquete semanal (domingos 04:00 UTC): descarga el `core` de YARA Forge,
  lo firma y lo **verifica con la clave pública compilada dentro de Rhino**. Ese paso es el
  importante: impide publicar un paquete que los usuarios no podrían aceptar.

Mientras no haya CI, el paquete de base de datos se construye y publica a mano en el sitio
local:

```sh
web/tools/publish-db.sh ~/.config/rhino/db-key
```

Descarga el último `core`, construye el paquete, lo verifica con la clave pública compilada
—el mismo control que aplicará el usuario final— y lo publica en `web/public/db/<canal>/`.
`rust-toolchain.toml` fija Rust 1.98.1, los componentes y los dos targets de Windows, para que
las compilaciones sigan siendo reproducibles cuando el CI vuelva.

## Sitio

`web/` es el sitio del que Rhino descarga su base de datos firmada y sus ejecutables. Se sirve
en local con `web/serve.sh` (`http://localhost:27182`) y queda permanente como servicio de
usuario (`web/systemd/rhino-web.service`).

Vive dentro del repositorio, y no en uno aparte, porque existe solo para servir lo que produce
el constructor de paquetes: si el formato del manifiesto cambia, el sitio y el formato cambian
en el mismo commit y no pueden desincronizarse. Los paquetes y los ejecutables **no se
versionan**; se regeneran.

Cuando haya dominio, esta carpeta se copia tal cual al servidor: nada está atado a
`localhost`. El detalle está en `web/README.md`.

## Entorno de OpenCode

`opencode.jsonc` declara los MCP útiles para el proyecto: `context-mode`,
`ddg-search` (búsqueda web) y `context7` (documentación de librerías).
