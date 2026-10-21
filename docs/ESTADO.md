# Estado de Rhino

Una página, escrita para que quien llegue nuevo (o una sesión nueva) sepa qué hay de
verdad y qué es decorado. Se actualiza en el mismo commit que el cambio.

Última actualización: 21-10-2026, tras la fase 6 (cuatro hilos y corte de las reglas en
imágenes, audio y vídeo).

## Qué funciona de verdad

- **Análisis de archivo, carpeta o equipo.** Hasta cuatro hilos, recuento de archivos
  mirados, archivo que se está mirando y botón de detener. Comprobado de punta a punta con
  el archivo de prueba EICAR y una regla firmada con la clave de producción.
- **Velocidad (fase 6).** 26 s → **11,75 s** sobre `/usr/bin` (2395 archivos) y 59,42 s →
  43,51 s sobre `/usr/share/icons` (80.520 archivos). Las cifras y sus costes están en el
  README. Las reglas se saltan en imágenes, audio y vídeo; nunca en documentos, fuentes ni
  ejecutables, y el hash de la capa 1 se calcula siempre.
- **Hallazgos con su origen.** Capa que lo encontró, motivo en llano e identificador, autor
  y dirección de la regla (lo exige la licencia DRL 1.1).
- **Poner a salvo.** Mueve el archivo a `<datos>/Rhino/apartados`, guarda su ficha y deja la
  fila fuera de la lista. La pantalla enseña lo apartado, lo recupera a su sitio y lo borra
  solo cuando se pide. Dos copias del mismo contenido no se pisan: la segunda se rechaza sin
  tocar ninguna.
- **Historial.** Cada análisis terminado escribe una línea en
  `<datos>/Rhino/historial.jsonl` y la pantalla enseña los últimos 20, con fecha local
  (`DD-MM-YYYY HH:mm`), alcance, archivos y resultado.
- **Base de datos firmada.** Paquete con manifiesto y firma Ed25519, verificado al cargar;
  actualizador con descarga aparte y cambio por directorio completo.
- **«Actualizar la protección».** Los botones de Inicio y de Ajustes descargan el canal,
  comprueban la firma, cambian el paquete entero y recargan la protección en memoria sin
  reiniciar. En release, sin `RHINO_DB_URL`, lo dice en pantalla en vez de inventar un
  servidor; en depuración cae en el sitio local (`http://localhost:27182/db/stable`).
- **«Ajustes» con datos del disco.** Versión instalada, número de comprobaciones y de
  archivos peligrosos conocidos, estado de la descarga y lista de archivos ignorados.
- **«Ignorar» persistente.** `<datos>/Rhino/ignorados.json` guarda la huella SHA-256, no la
  ruta. Un análisis nuevo no lista esos hallazgos; si el contenido cambia, vuelve a
  aparecer. La misma lista se puede deshacer desde Ajustes.
- **Teclado.** Tab y Shift+Tab recorren en orden de lectura, Intro y Espacio activan, y el
  foco se ve con un aro de 2 px. Verificado en Windows con el binario x86.
- **Árbol de accesibilidad.** Los controles declaran papel y nombre (`accessible-*`) y los
  glifos decorativos no se anuncian. `vm/probar-uia.sh` vuelca el árbol por UI Automation y
  lo compara con la base dorada `vm/uia/inicio.txt`.
- **Privacidad.** Nada sale del equipo salvo la actualización de la base de datos.

## Qué es maqueta

- La tira **«MAQUETA · ESTADO»** del riel solo aparece en compilaciones de desarrollo. Ya no
  gobierna ninguna pantalla —sus botones no mueven nada— y su sitio natural es la basura
  cuando se monten las capturas doradas.

## Qué está roto o sin probar

- **Las cifras de Windows son de un solo hilo.** La máquina virtual tiene ahora 4 vCPU, así
  que los 9,3 archivos por segundo del README hay que volver a medirlos con el binario de
  la fase 6, que todavía no se ha compilado para Windows.
- **Falsos positivos sin terminar de medir**: en 5965 archivos de `C:\Program Files` marcó 4.
  Uno era la sección `.textbss` del enlazador (corregido); los otros tres están sin revisar.
- **El lector de pantalla no se ha probado**: el árbol se vuelca y se compara contra la base
  dorada, pero nadie lo ha oído hablar; aquí no hay sesión AT-SPI. El volcado tampoco prueba
  el orden de tabulación ni el aro de foco.
- **La ventana no cabe al 150 %**: 980x680 lógicos son 1470x1020 físicos y no entran en un
  portátil de 1366x768. Pide una referencia de 900x480, recalcular riel, rellenos y columnas,
  y envolver Ajustes en un `Flickable`.
- **El selector de archivos no se ha probado en vivo**: `rfd` con `xdg-portal` necesita el
  portal del escritorio y el entorno de Xephyr no lo tiene.
- **Los mensajes de estado no tienen línea visible.** «Recuperado en…» y «Borrado» van a
  `status`, que ya no se pinta en Ajustes (allí manda el estado de la protección).
- **La descarga solo se ha probado en Linux y en depuración**, contra el sitio local con el
  paquete estable. No se ha ejercido en Windows, ni en release, ni con la conexión cortada a
  mitad de los 9 MB.
- **Deudas menores**: «Borrar» de Poner a salvo no pide confirmación; el aviso de copia
  repetida mide 372 px y se elide en los 320 del encabezado; el análisis de un archivo suelto
  no atiende a Detener; en depuración el arranque con paquete tarda unos 20 s porque compila
  las reglas.

## Cómo se comprueba

```bash
cargo test --workspace && cargo clippy --workspace --all-targets
./vm/probar-uia.sh          # arranca la VM, vuelca el árbol y lo compara
```

La interfaz **se mide, no se mira**: `AGENTS.md` tiene la receta con Xephyr y `import`, y
las filas del riel. El contraste lo comprueba `crates/rhino-app/tests/contraste.rs` leyendo
`ui/theme.slint`.

## Siguiente rebanada

**Capturas doradas** de layout (comparar PNG con `compare -metric AE`) y la galería de
componentes: es lo que habría evitado las seis rondas de la fase 4. Después, medir en Windows
con el binario nuevo (`./vm/probar-uia.sh` ya sirve para la accesibilidad, falta el banco que
analiza una carpeta fija y vuelca tiempo, memoria y hallazgos), y la ventana a 150 %. El
estado del proyecto y las fases están en el `README.md`.
