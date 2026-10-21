# Estado de Rhino

Una página, escrita para que quien llegue nuevo (o una sesión nueva) sepa qué hay de
verdad y qué es decorado. Se actualiza en el mismo commit que el cambio.

Última actualización: 20-10-2026, tras la fase 5c («Ajustes» reales, descarga conectada e
ignorados persistentes).

## Qué funciona de verdad

- **Análisis de archivo, carpeta o equipo.** Hilos de trabajo en segundo plano, recuento de
  archivos mirados, archivo que se está mirando y botón de detener. Comprobado de punta a
  punta con el archivo de prueba EICAR y una regla firmada con la clave de producción.
- **Hallazgos con su origen.** Capa que lo encontró, motivo en llano e identificador, autor
  y dirección de la regla (lo exige la licencia DRL 1.1).
- **Poner a salvo.** «Poner a salvo» mueve el archivo a `<datos>/Rhino/apartados`, guarda su
  ficha y deja la fila fuera de la lista. La pantalla enseña lo apartado, lo recupera a su
  sitio y lo borra solo cuando se pide. Dos copias del mismo contenido no se pisan: la
  segunda se rechaza sin tocar ninguna.
- **Historial.** Cada análisis terminado escribe una línea en
  `<datos>/Rhino/historial.jsonl` y la pantalla enseña los últimos 20, con fecha local
  (`DD-MM-YYYY HH:mm`), alcance, archivos y resultado.
- **Base de datos firmada.** Paquete con manifiesto y firma Ed25519, verificado al cargar;
  actualizador con descarga aparte y cambio por directorio completo.
- **«Actualizar la protección».** El botón de Inicio y el de Ajustes descargan el canal,
  comprueban la firma, cambian el paquete entero y recargan la protección en memoria sin
  reiniciar: el siguiente análisis ya usa la versión nueva. En release, sin
  `RHINO_DB_URL`, lo dice en pantalla en vez de inventar un servidor; en depuración cae en
  el sitio local (`http://localhost:27182/db/stable`).
- **«Ajustes» con datos del disco.** Versión instalada, número de comprobaciones y de
  archivos peligrosos conocidos (del manifiesto cargado), estado de la descarga y lista de
  archivos ignorados. Nada de cifras de ejemplo.
- **«Ignorar» persistente.** `<datos>/Rhino/ignorados.json` guarda la huella SHA-256, no la
  ruta. Un análisis nuevo no lista esos hallazgos; si el contenido cambia, vuelve a
  aparecer. La misma lista se puede deshacer desde Ajustes.
- **Privacidad.** Nada sale del equipo salvo la actualización de la base de datos.

## Qué es maqueta

- La tira **«MAQUETA · ESTADO»** del riel solo aparece en compilaciones de desarrollo. Ya no
  gobierna ninguna pantalla; se conserva como recordatorio de la fase 4.

## Qué está roto o sin probar

- **Ya se ha ejecutado en Windows** (fase 5e): la ventana abre, el teclado funciona y la
  protección se descarga e instala. Las cifras están en el README.
- **El análisis es lento**: 9,3 archivos por segundo en `C:\Program Files` y 1,2 en la raíz
  de `C:` (donde la Papelera guarda archivos enormes). El coste lo pone el contenido, no el
  número de archivos: un análisis completo del equipo tarda horas y la fase 6 ya no es una
  hipótesis. El proceso ocupa **53 MB** durante el análisis; los 1,32 GB que se midieron
  antes eran de la máquina virtual entera, Windows incluido.
- **Falsos positivos sin terminar de medir**: en 5965 archivos de `C:\Program Files` marcó
  4. Uno era la sección `.textbss` del enlazador (corregido); los otros tres están sin
  revisar.
- **El lector de pantalla no se ha probado**: el árbol de accesibilidad compila y existe,
  pero aquí no hay sesión AT-SPI que lo lea.
- **La ventana no cabe al 150 %**: 980x680 lógicos son 1470x1020 físicos y no entran en un
  portátil de 1366x768.
- **Inicio afirmaba «Tu equipo está protegido»** con la base de datos descargada y cero
  análisis (corregido en la fase 5a).
- **La base de datos vivía junto al ejecutable**, donde un usuario estándar no puede
  escribir bajo `C:\Program Files` (corregido en la fase 5a).
- **`rhino-db.exe` se distribuía** con el producto, con la orden de generar claves dentro
  (corregido en la fase 5a: se compila solo `-p rhino-app`).
- **El selector de archivos no se ha probado en vivo**: `rfd` con `xdg-portal` necesita el
  portal del escritorio y el entorno de Xephyr no lo tiene.
- **Nunca se ha ejecutado en Windows.** Los binarios cruzados existen, pero nadie los ha
  abierto en una máquina Windows. La ventana mide 980×680 en píxeles lógicos: a 150 % de
  escala no entra en un portátil de 1366×768.
- **Sin teclado ni lector de pantalla.** Todo se maneja con ratón, no hay foco visible ni
  etiquetas `accessible-*`.
- **Falsos positivos sin medir** sobre programas instalados de verdad.
- **Los mensajes de estado no tienen línea visible.** «Recuperado en…» y «Borrado» van a
  `status`, que ya no se pinta en Ajustes (allí manda el estado de la protección). Los fallos
  de «Ignorar» sí se ven en su panel. Falta un pie en las pantallas que actúan (5d).
- **La descarga solo se ha probado en Linux, en depuración**, contra el sitio local con el
  paquete estable de producción. No se ha ejercido en Windows, ni en release, ni con la
  conexión cortada a mitad de los 9 MB (el núcleo descarta el paquete a medias; no se ha
  visto en pantalla).

## Cómo se comprueba

```bash
cargo test --workspace && cargo clippy --workspace --all-targets
```

La interfaz **se mide, no se mira**: `AGENTS.md` tiene la receta con Xephyr y `import`, y
las filas del riel. El contraste lo comprueba `crates/rhino-app/tests/contraste.rs` leyendo
`ui/theme.slint`.

## Siguiente rebanada

Fase 6: repartir el análisis entre hilos y cortar por tipo de archivo. La medida de la fase
5e (9,3 archivos por segundo con una CPU) la justifica con datos. Queda aparte la ventana a
150 %: pide una referencia de 900x480, recalcular riel, rellenos y columnas y envolver
Ajustes en un `Flickable`. El estado del proyecto, las fases y sus criterios de aceptación
están en el `README.md`.
