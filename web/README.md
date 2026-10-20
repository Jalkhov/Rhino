# Sitio de Rhino

Es el sitio del que Rhino descarga su base de datos firmada y sus ejecutables.
Por ahora vive dentro del repositorio y se sirve **en local**, porque todavía no
hay dominio ni alojamiento. Cuando lo haya, esta carpeta se copia tal cual al
servidor: no hay nada atado a `localhost`.

Vive aquí, y no en un repositorio aparte, porque existe únicamente para servir
lo que produce el constructor de paquetes: si el formato del manifiesto cambia,
el sitio y el formato cambian en el mismo commit y no pueden desincronizarse.

## Estructura

```
web/
├── public/                 lo que se sirve; es la raíz del sitio
│   ├── index.html          la página
│   ├── estilo.css
│   ├── app/                ejecutables compilados (no se versionan)
│   └── db/
│       ├── stable/         paquete firmado del canal estable (no se versiona)
│       └── beta/
├── tools/
│   └── publish-db.sh       construye, firma y publica un paquete
├── serve.sh                sirve el sitio en local
└── systemd/
    └── rhino-web.service   el servicio que lo mantiene vivo
```

**Los paquetes y los ejecutables no se versionan**: son artefactos de megabytes
que se regeneran. Lo que se versiona es la estructura y los guiones.

## Servirlo

```sh
web/serve.sh              # http://localhost:27182
web/serve.sh 9000         # otro puerto
```

Queda escuchando **solo en `127.0.0.1`**, que es lo correcto para probar en este
equipo. Para probar desde una máquina virtual con Windows hay que cambiar el
`--bind` de `serve.sh` a `0.0.0.0` y abrir el puerto; conviene hacerlo solo
mientras dure la prueba.

### Permanente

```sh
mkdir -p ~/.config/systemd/user
cp web/systemd/rhino-web.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now rhino-web
```

Se levanta solo al iniciar sesión. Para verlo:

```sh
systemctl --user status rhino-web
journalctl --user -u rhino-web -f
```

## Publicar un paquete

```sh
web/tools/publish-db.sh <clave-privada> [canal]
```

Descarga el paquete `core` de YARA Forge, compila las reglas, saca los hashes,
firma el manifiesto, **verifica el resultado con la clave pública compilada
dentro de Rhino** (el mismo control que aplicará el usuario final) y lo publica
en `public/db/<canal>/`.

La publicación es atómica: el paquete se arma al lado y se intercambia de una
vez, así el sitio nunca sirve una versión a medio escribir.

## URLs

| | |
| --- | --- |
| Sitio | `/` |
| Canal estable | `/db/stable` |
| Paquete de un canal | `/db/stable/manifest.json`, `manifest.sig`, `rules.yarc`, `hashes.bin` |
| Descargas | `/app/` |

Un canal es un directorio. Añadir `beta` es crear `public/db/beta/` y publicar
con ese nombre; el manifiesto ya lleva el campo `channel` para que la aplicación
pueda distinguirlos.

## Probarlo de verdad

Con el sitio levantado, cualquier Rhino puede apuntar a él:

```sh
RHINO_DB_URL=http://localhost:27182/db/stable cargo run -p rhino-app
```

O instalar el paquete directamente, sin pasar por la aplicación:

```sh
cargo run -p rhino-db -- update http://localhost:27182/db/stable ~/.local/share/Rhino/rhino-db
```
