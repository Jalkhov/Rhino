# La interfaz

[← Volver al README](../README.md)
## Interfaz gráfica: Slint

Elegida sobre `egui`, `iced` y las alternativas basadas en web:

- Se compila AOT a código nativo: sin intérprete, sin webview y sin recolector de basura.
- Tiene **renderizador por software** (CPU, sin GPU ni OpenGL), ideal para equipos
  modestos o con drivers gráficos malos. Se fuerza con `SLINT_BACKEND=winit-software`.
- Su huella es mínima (el framework está diseñado para embebidos).
- Es gratis para aplicaciones de escritorio (licencia *royalty-free*; también
  disponible bajo GPLv3 o comercial).

Descartadas: `egui` (modo inmediato, redibuja de más y requiere OpenGL), `iced`
(requiere GPU) y Tauri/Electron (meten un motor de navegador en RAM, contra el objetivo
de eficiencia).

La interfaz vive en su propio crate (`rhino-app`), desacoplada del núcleo
(`rhino-core`), para poder cambiarla sin tocar la lógica.

La ventana mide 980x680 en píxeles lógicos y el sistema la escala: al 125 % mide 1222 px
físicos, medidos en Windows. El diseño sale de una captura medida de Avira Free Security, no
de una idea; de ahí vienen la paleta, las superficies planas, un solo acento azul y el verde
de "está bien". La paleta y su porqué están en `ui/theme.slint` y `PRODUCT.md`, y las 18
reglas de layout que costaron una ronda de arreglos cada una están en `AGENTS.md`.

Tres decisiones que no se negocian en pantalla: **ningún botón es rojo** (el rojo solo marca
hallazgos), **cada pantalla dice una cosa y ofrece una acción**, y **el vocabulario es llano**
(nada de "firmas", "cuarentena", "motor", "regla" ni "capa"). El contraste se comprueba con
una prueba, no a ojo.

Capturas del estado actual en `docs/app-*.png`. Las de `docs/maqueta-*.png` son la maqueta
aprobada antes de conectar el núcleo y se conservan como referencia del diseño.
