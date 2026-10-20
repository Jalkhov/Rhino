# Estado de Rhino

Una página, escrita para que quien llegue nuevo (o una sesión nueva) sepa qué hay de
verdad y qué es decorado. Se actualiza en el mismo commit que el cambio.

Última actualización: 20-10-2026, tras la fase 5b («Poner a salvo» e «Historial» reales).

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
- **Privacidad.** Nada sale del equipo salvo la actualización de la base de datos.

## Qué es maqueta

- **«Ajustes»** sigue enseñando datos de ejemplo (`demo` en `ui/app.slint`). La tira
  «MAQUETA · ESTADO» solo aparece en compilaciones de desarrollo y ya solo cambia Ajustes;
  «Poner a salvo» e «Historial» leen del disco.
- **«Ignorar»** quita la fila de la lista, pero no se recuerda al cerrar la app.
- **«Actualizar la protección»** no descarga: no está conectado al actualizador del núcleo.

## Qué está roto o sin probar

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
- **Los mensajes de estado no tienen línea visible.** «Recuperado en…», «Borrado» y los
  errores van a `status`, pero ese texto solo se ve al final de Ajustes: falta un pie en las
  pantallas que actúan (5d).

## Cómo se comprueba

```bash
cargo test --workspace && cargo clippy --workspace --all-targets
```

La interfaz **se mide, no se mira**: `AGENTS.md` tiene la receta con Xephyr y `import`, y
las filas del riel. El contraste lo comprueba `crates/rhino-app/tests/contraste.rs` leyendo
`ui/theme.slint`.

## Siguiente rebanada

Fase 5c («Ajustes» reales y «Actualizar» conectado), 5d (teclado, foco, pie de estado y
ventana que quepa a 150 %). El plan completo, con criterios de aceptación, está en
`REPORT_1017.md`.
