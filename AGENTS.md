# Reglas de la interfaz (Slint 1.18.1)

Léelo antes de tocar `crates/rhino-app/ui/*.slint`. Slint no es HTML: es un lenguaje
declarativo que se compila a código nativo, con un motor de restricciones. Estas reglas salen
de defectos reales medidos en pantalla, no de la teoría; cada una costó una ronda de arreglos.

## Composición

1. **Nada de medidas implícitas.** La ventana mide 980x680 fijos; el riel, `width: 248px`; el
   área de trabajo, `width: parent.width - 248px`. Nunca derives el ancho de un contenedor de
   un hijo que a su vez depende de ese contenedor: la cadena resuelve por contenido y colapsa
   (pasó: el área quedó en 689 px en vez de 780 y el filete del encabezado no llegaba al borde).

2. **`alignment` solo actúa sobre el EJE PRINCIPAL**, y cualquiera distinto de `stretch` hace
   que los hijos usen su tamaño preferido: **un hijo con `horizontal-stretch` deja de
   estirarse**. Por eso ninguna fila que tenga un hijo elástico lleva `alignment`.

3. **El eje cruzado estira, pero a un hijo de tamaño fijo lo pega al INICIO**, no lo centra.
   Todo icono, lámpara, distintivo o botón de una fila va envuelto en
   `component Mid inherits VerticalLayout { alignment: center; @children }`.

4. **`Text` se dibuja pegado arriba por defecto**: `vertical-alignment` es `top` y el `Text`
   ocupa todo el alto que le dé su contenedor. En una fila o dentro de un botón hay que
   escribir `vertical-alignment: center;` a mano. Es la causa de las etiquetas descentradas.

5. **Un hijo de ancho fijo dentro de un `VerticalLayout` se pega a la izquierda.** Para
   centrarlo, envuélvelo en un `HorizontalLayout { alignment: center; }` de un solo hijo.

6. **`alignment: start`** en el layout de una pantalla evita que el sobrante vertical se
   reparta entre las tarjetas y que crezca el hueco interior de cada una.

7. **`vertical-stretch: 0` explícito** en una tarjeta evita que se reparta el sobrante con el
   espaciador final (pasó: los tres textos del panel de progreso quedaron a 50 px unos de otros
   donde el `spacing` marcaba 12 px).

17. **El sobrante de un layout se reparte entre TODOS sus hijos sin `stretch`**, no desaparece:
    un `vertical-stretch: 0` no salva a una tarjeta si comparte el layout con otro hijo que
    tampoco se estira (el pie de pantalla, por ejemplo); los dos crecen. Para que la tarjeta
    abrace su contenido, envuélvela en un `VerticalLayout { vertical-stretch: 1; alignment:
    center; }` que se quede el sobrante (pasó: el estado vacío de «Poner a salvo» medía 321 px
    para dos líneas de texto).

18. **Lo que se mide con el ancho de otros se elide.** La ruta de un hallazgo va en su propia
    fila, a todo el ancho: compartiendo fila con la insignia y dos botones se cortaba (pasó con
    `C:\Usuarios\Ana\Descargas\instalador.exe`).

8. `@children` funciona dentro de un componente que hereda de un layout (así está hecho `Mid`).

## Texto y medidas

9. **Deja holgura en los anchos de texto**: las fuentes de Windows no miden igual que las de
   Linux. El riel está a 264 px porque la etiqueta más larga («Archivos sospechosos») mide
   ≈161 px a 15 px de cuerpo y la aritmética da 246 px: 18 px de sobra para que no se elida
   con la insignia al lado.
16. **El ancho de un botón es explícito y hay que recalcularlo al tocar la escala.** Fórmula:
   ancho ≈ texto + 36 px de relleno, más 24 px si lleva icono. Los botones de una misma fila
   llevan ancho fijo para que queden alineados entre filas; por eso no se puede dejar que el
   ancho sea el del contenido. Pasó: «Recuperar» a 120 px y «Ver la comprobación» a 150 px se
   quedaban cortos tras subir la escala.
10. La escala tipográfica vive en `ui/theme.slint` (`Theme.t-xs`…`t-2xl`). No escribas tamaños
    sueltos: si falta un tamaño, añádelo a la escala.

## Reglas de producto (de `PRODUCT.md`)

11. **Ningún botón es rojo.** El rojo marca hallazgos y solo aparece como punto, filete o
    distintivo. Lo que se pulsa es azul; lo secundario, relleno neutro; lo terciario, texto.
12. **Una pantalla dice una cosa y ofrece una acción.** Todo lo que no ayude a decidir se va a
    la pantalla que le toca.
13. Vocabulario llano: nada de «firmas», «cuarentena», «motor», «regla» ni «capa» en pantalla.

## Verificar, no mirar

14. Toda comprobación visual se hace **midiendo píxeles sobre una captura**, no a ojo:

```
cargo build -p rhino-app
pkill -x rhino-app; pkill -x Xephyr; sleep 1
Xephyr :99 -screen 1100x820 -nolisten tcp &
sleep 2
env -u WAYLAND_DISPLAY DISPLAY=:99 ./target/debug/rhino-app &
sleep 5
DISPLAY=:99 import -window root -crop 980x680+0+0 +repage /tmp/opencode/x.png
```

Usa `pkill -x` por nombre de proceso: `pkill -f '[t]arget/debug/rhino-app'` mata su propio
shell. La ventana queda en +0+0. Filas del riel: x=100 con y=82 Inicio, 121 Analizar,
160 Archivos sospechosos, 199 Poner a salvo, 238 Historial, 277 Ajustes. La tira
**MAQUETA · ESTADO** (solo maqueta): «En orden» ≈(71,623), «Con hallazgos» ≈(176,623),
«Analizando» ≈(71,656), «Sin datos» ≈(176,656).

15. El mensaje de consola `base de datos no cargada: … Not a directory (os error 20)` es el
    fallo conocido de desarrollo (`target/debug/rhino-db` es el constructor, no una carpeta).

## Commits

**Conventional Commits**, en español y en imperativo: `tipo(alcance): asunto`, y el porqué en
el cuerpo.

```
feat(scan): reparte el analisis entre cuatro hilos
fix(update): no instala un paquete mas antiguo
docs: asienta el README en el estado real
test(vm): volcado de accesibilidad reproducible
```

Tipos: `feat`, `fix`, `docs`, `test`, `chore`, `refactor`, `perf`, `build`, `ci`. El alcance es
el módulo o la carpeta (`scan`, `update`, `ui`, `vm`, `db`). El asunto no lleva punto final y
cabe en 72 caracteres. Un cambio incompatible lleva `!` tras el tipo (`feat(api)!:`) o un
`BREAKING CHANGE:` en el pie.

El historial anterior no se reescribe; los commits nuevos se escriben así desde ya, para que
la CI los pueda aprovechar el día que haya CI.
