# Rhino visto por DeepSeek 1017

Análisis del repositorio a 20 de octubre de 2026, con el árbol en `a3abc58` (24 commits,
90 pruebas en verde, clippy limpio).

**Qué es esto.** Una revisión de fuera: qué aguanta, qué se rompe en manos de un usuario,
qué deuda se está acumulando y por qué la interfaz costó tanto. Cada afirmación lleva su
archivo y su línea, o su número medido. Lo que no he podido comprobar lo digo.

**Qué no he hecho.** No he ejecutado nada en Windows. Todo lo que digo del comportamiento
en Windows sale de leer el código y de la documentación de la plataforma, no de haberlo
visto. Las dos cosas que más me preocupan (§5.1 y §5.2) necesitan una máquina Windows
para confirmarse, y son de las primeras que probaría.

---

## 1. Retrato en números

| | |
|---|---|
| Núcleo (`rhino-core`, producción) | 3.468 líneas |
| Núcleo (pruebas y ejemplo) | 317 líneas |
| Aplicación (Rust) | 453 líneas |
| Aplicación (Slint) | 1.585 líneas |
| Constructor del paquete (`rhino-db`) | 338 líneas |
| Pruebas | 90 (78 unidad + 6 propiedades + 5 integración + 1 manifiesto) |
| Commits | 24, todos con mensaje en español y cuerpo explicativo |
| Dependencias directas | 9 (`slint`, `slint-build`, `yara-x`, `ed25519-dalek`, `ureq`, `sha2`, `serde`, `serde_json`, `getrandom`, `rfd`) |

La proporción es sana para un producto así: **más núcleo que interfaz**, y el núcleo con
pruebas de propiedad sobre los parsers. Lo que no es sano es la proporción entre lo que
está probado (la lógica) y lo que no (todo lo que se ve).

---

## 2. Lo que está sólido y no conviene tocar

- **El paquete firmado está bien pensado.** Se verifica la firma Ed25519 del manifiesto
  *antes* de leer nada más, después se comprueba tamaño y SHA-256 de cada archivo
  (`db.rs:168-190`), y el reemplazo del directorio es atómico por staging + swap
  (`update.rs:173-192`). No hay estado intermedio posible.
- **La memoria del análisis está cuidada donde importa.** `scan_file` hashea en streaming
  y la capa de reglas recibe la **ruta**, no los bytes (`scan.rs:137-141`): el motor decide
  entre leer y mapear con tope de 64 MB. El único sitio que reserva 64 MB es el camino de
  pruebas en memoria (`rules.rs:154-169`). Esto es exactamente lo que hay que hacer en un
  equipo de 4 GB.
- **Aislamiento de pánicos por archivo** (`scan.rs:171`, `isolate`): un parser hostil no
  tumba el análisis entero. Con `panic = "unwind"` a propósito en el perfil de release,
  que es una decisión que muchos proyectos toman al revés.
- **Cuarentena e historial** (`quarantine.rs`, `history.rs`): el identificador es el
  sha256 y se valida antes de componer nombres de archivo (`check_id`), el contenido va
  **sin extensión**, se niega a pisar el origen al recuperar y, si la ficha no se puede
  escribir, devuelve el archivo a su sitio. El historial cierra una línea partida antes de
  escribir la siguiente, que es el fallo clásico de los ficheros por línea.
- **Los datos del usuario van al perfil** (`paths.rs`), no junto al ejecutable: `%LOCALAPPDATA%\Rhino`
  en Windows. La razón está escrita y es la correcta.
- **Privacidad como decisión, no como eslogan:** ni telemetría ni red salvo el paquete
  firmado, y el sitio web es local.
- **La documentación es parte del producto.** `PRODUCT.md` con la paleta medida, `AGENTS.md`
  con las trampas de layout y sus números, `README.md` con las fases y los riesgos
  conocidos. Eso es lo que ha permitido que 24 sesiones distintas no repitan los mismos
  errores.

Lo que sigue es lo que yo cambiaría.

---

## 3. Riesgos y defectos por severidad

### S1 — antes de enseñar la aplicación a nadie

#### 3.1 Inicio afirma que el equipo está protegido sin haber mirado nada

`app.slint:1158`:

```
: (!root.has-database ? "Falta actualizar la protección" : "Tu equipo está protegido")
```

`has-database` es lo único que decide. Con el paquete descargado y **cero análisis**, la
pantalla principal dice «Tu equipo está protegido» y ofrece un botón que ya parece
innecesario. Es la peor clase de mentira que puede decir un antivirus: la que tranquiliza.

**Arreglo:** tres estados, no dos.
1. Sin base de datos → lo que ya hace (ámbar, «Actualizar la protección»).
2. Con base de datos y sin análisis → «Protección lista» + «Todavía no hemos mirado tu
   equipo» + «Analizar ahora» como acción principal. El historial ya sabe si ha habido un
   análisis (`History::recent`), y el dato existe desde esta rebanada.
3. Con un análisis reciente y sin hallazgos → «Tu equipo está protegido», y conviene decir
   cuándo fue («Último análisis: hoy a las 21:14»).

#### 3.2 Tres pantallas siguen enseñando datos inventados

`demo` aparece **22 veces** (`app.slint:849-1443`), con valor por defecto `0`
(`app.slint:1134`). Afecta a «Poner a salvo», «Historial» y «Ajustes»: el Historial enseña
«Nada sospechoso» en cinco filas que nunca ocurrieron, y Ajustes dice «18.204 archivos»
como si fuera tuyo. Además, la tira **MAQUETA · ESTADO** (`app.slint:1288-1327`) se
compila en release.

Para un antivirus, un dato falso que parece real es peor que un hueco: si alguien enseña
esa pantalla, está enseñando un historial que no existe.

**Arreglo:** terminar las tres pantallas (rebanadas 3 y 4 del plan) **o** dejar el estado
vacío honesto; y meter la tira de maqueta en `#[cfg(debug_assertions)]` o detrás de una
propiedad que `main.rs` ponga a `false` en release. Antes de eso, no distribuir.

#### 3.3 El análisis del equipo entero oculta lo que no pudo mirar

`walk` (`scan.rs:206-250`) ignora los errores de subcarpeta (`collect_files(&path, …).ok()`)
y solo entrega informes de los archivos que se pudieron abrir. La pantalla suma los
informes y enseña «1.204 archivos mirados». Si 300 no se pudieron abrir, el usuario no se
entera y el recuento miente por omisión.

**Arreglo:** que el callback reciba también el fallo (`on_error: impl FnMut(&Path, io::Error)`)
o que `walk` devuelva un `WalkSummary { scanned, failed }`, y que Analizar enseñe una
segunda línea en llano: «37 archivos no se pudieron abrir (sin permiso)». Es la diferencia
entre un antivirus y un contador.

### S2 — lo que el usuario va a notar el primer día

#### 3.4 La base de datos vive junto al ejecutable

`db.rs:264-267`:

```rust
pub fn default_directory() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    Some(executable.parent()?.join("rhino-db"))
}
```

`paths.rs` ya resuelve lo contrario para los datos del usuario, pero la base de datos se
quedó en la carpeta del programa. Si Rhino se instala donde se instalan las cosas en
Windows (`C:\Program Files\Rhino`), un usuario estándar **no puede escribir ahí**: la
descarga de la protección falla con un error de permisos, y el usuario ve «no se pudo
escribir el paquete» sin saber qué hacer. En una carpeta compartida entre usuarios, además,
lo que actualiza uno lo ven todos.

**Arreglo:** mover la base de datos a `%LOCALAPPDATA%\Rhino\db`, apoyándose en
`paths::data_directory()`. El paquete está firmado, así que una copia por usuario no
compromete nada y elimina el problema de permisos. Dejar la carpeta del ejecutable
estrictamente de solo lectura.

#### 3.5 El ejecutable de firma se distribuye con el producto

`cargo build --release` construye todos los miembros del workspace, así que junto a
`rhino-app.exe` quedan `rhino-db.exe` (9-11 MB) y su subcomando `keygen`. El binario que
fabrica claves de firma no tiene ninguna razón para viajar al equipo del usuario.

**Arreglo:** un artefacto de release que solo contenga `rhino-app`, y `rhino-db` detrás de
una feature o de un crate aparte que no se empaqueta.

#### 3.6 «Ignorar» no se recuerda

El botón quita la fila del modelo en memoria; no se escribe nada. En el siguiente análisis,
el mismo archivo vuelve a salir. Para un usuario doméstico eso es «la aplicación no me
hace caso», y pasa cada vez que analiza.

**Arreglo:** `ignorados.jsonl` junto al historial, con `{ path, sha256, when }`, y filtrar
al construir el modelo. Excluir por **ruta y contenido a la vez**: si el archivo cambia, no
es el mismo archivo y hay que volver a avisar. (Excluir solo por ruta es cómo se acaba
ignorando un troyano porque el nombre coincide.)

#### 3.7 La ventana fija no entra en un portátil a 150 %

`app.slint:1115-1116`: `width: 980px; height: 680px;` en píxeles lógicos. A 150 % de escala
son 1470 × 1020 físicos, y un portátil de 1366 × 768 no los tiene. El requisito declarado
son equipos modestos, justo los que suelen venir con Windows al 125-150 %.

**Arreglo:** al arrancar, comparar el tamaño de la pantalla y ajustar `width`/`height` (o
permitir redimensionar con mínimo 980 × 680 y que las pantallas largas se desplacen con un
`Flickable`, que la lista de hallazgos ya usa). Verificarlo en una VM a 150 %.

#### 3.8 «Actualizar la protección» no descarga

`rhino_core::update::update(base, destination)` existe, está probado contra un servidor
local (`update.rs:210-448`) y **nadie lo llama desde la aplicación**. Tampoco hay URL por
defecto: solo la variable `RHINO_DB_URL` (`update.rs:28`), que un usuario doméstico no va a
poner nunca.

**Arreglo:** URL compilada por defecto, comprobación al arrancar en un hilo con tiempo
límite, botón conectado de verdad, y un aviso cuando el paquete tenga más de N días
(«La protección tiene 9 días; conviene actualizarla»).

### S3 — deuda que se paga sola

| Qué | Dónde | Por qué importa |
|---|---|---|
| Cuarentena sin pantalla | `quarantine.rs` completo, sin llamadas en la app | El usuario no puede recuperar lo que se apartó: funcionalidad a medias visible |
| Historial sin pantalla | `history.rs`, sin llamadas en la app | Ídem |
| Análisis en un solo hilo | un `thread::spawn` (`main.rs:230`) | Un disco entero tarda mucho más de lo necesario (§4) |
| Un archivo suelto no atiende «Detener» | `scan_file` sin bandera | Se queda el botón sin efecto |
| Modelo y `rows` en paralelo | `main.rs`, dos `Vec` que hay que mantener sincronizados | Dos fuentes de verdad; el subagente ya documentó el riesgo al borrar |
| Colores literales | `#414A53`, `#242E35`, `#2A343A`, `#141A1E`, `#FFFFFF` en `app.slint` | Se saltan la escala; el próximo cambio de paleta los olvida |
| `installed_version` lee sin verificar | `db.rs:226` | Solo decide «¿descargo?», pero un manifiesto corrupto puede fingir estar al día |
| El historial nunca se poda | `history.rs` (documentado como `shortcut:`) | Correcto hoy; hay que decidir cuándo se recorta |
| `cargo fmt --check` imposible | repo entero | Nadie puede exigirlo mientras el árbol no esté formateado; un commit de `cargo fmt` y se acaba la discusión |
| CI desactivada | `.github/` | Nada impide que la próxima rebanada rompa las 90 pruebas |
| Numeración de `AGENTS.md` | reglas 17 y 18 entre la 7 y la 8 | Menor, pero es el archivo que más se lee |

---

## 4. Rendimiento y RAM

El requisito duro es un equipo de 4 GB. Hoy el análisis es **secuencial**: un hilo recorre
el árbol y cada archivo pasa por hash → cabecera PE → reglas. En un disco mecánico eso es
lo más lento que se puede hacer, porque se pasa la vida esperando E/S sin pedir nada más.

**Lo que yo mediría antes de tocar nada** (y anotaría en el README, que ya tiene una tabla
de referencias):

1. Archivos por segundo sobre `C:\Windows\System32` en frío y en caliente.
2. RAM máxima (RSS) durante un análisis del equipo entero.
3. Tiempo de `Database::load` (compilar las reglas al arrancar) y su coste en memoria.

**Lo que haría después, por orden de rentabilidad:**

- **Tres o cuatro hilos de análisis**, no más: `min(4, available_parallelism())`. Un
  `Scanner` de YARA por hilo compartiendo las `Rules` ya compiladas, y los informes
  enviados por un canal al hilo de interfaz. En disco mecánico se gana sobre todo por
  solapar esperas. El tope de 64 MB por archivo debe quedarse en **un archivo en vuelo por
  hilo**, no más.
- **Cortar por tipo de archivo.** Hoy se hashea todo, incluidas fotos y vídeos. Un
  `.jpg` de 8 MB no necesita pasar por la capa de reglas. El hash sí (es barato y es la
  capa 1), pero el resto se puede saltar por extensión y cabecera.
- **No compilar reglas en el hilo de interfaz.** Si `Database::load` tarda 300 ms, el
  arranque se siente roto; cargarla en el hilo de análisis y enseñar «Preparando…» mientras
  tanto (la pantalla ya tiene ese texto).

---

## 5. Seguridad, privacidad y despliegue

### 5.1 Dos fallos concretos que conviene confirmar en Windows

**(a) Conflicto de identificadores en la cuarentena.** `store` mueve el archivo a
`<sha256>.bin` **sin comprobar si ya existe** (`quarantine.rs`, `store`). Dos copias del
mismo archivo (el mismo malware en Descargas y en Escritorio) tienen el mismo sha256:

- En Linux, `fs::rename` **reemplaza** el destino: la copia anterior desaparece y su ficha
  se sobrescribe con el nuevo origen. El primer archivo ya no está en su sitio y su copia
  tampoco: **pérdida de datos silenciosa**.
- En Windows, `fs::rename` falla si el destino existe: el segundo «Poner a salvo» da un
  error de E/S sin explicación.

**Arreglo:** si `<sha256>.bin` existe, devolver `Occupied` con un mensaje en llano («Ese
archivo ya está apartado») o guardar una ficha por origen (`<sha256>-<n>.json`). Lo primero
es más simple y suficiente.

**(b) La cuarentena está en claro.** Se decidió no cifrar (y me parece bien: una clave
guardada junto a los datos no protege de nada, y un usuario doméstico no puede custodiar
una). Lo que sí conviene es que la carpeta tenga permisos solo para el usuario actual y que
quede escrito en `PRODUCT.md` con esa justificación, para que no parezca un olvido.

### 5.2 Lo que ya está bien y no hay que tocar

Firma antes de leer, verificación de tamaño y hash por archivo, sin `unwrap` en el camino
de producción (los 127 `unwrap`/`expect` que hay están en pruebas), sin `unsafe`, HTTP con
raíces de Mozilla incrustadas, tiempo límite y tope de tamaño en la descarga, y el sitio
local sin TLS pero solo en desarrollo (documentado).

---

## 6. La interfaz: por qué costó tanto y cómo dejar de pagarlo

Esta es la parte que pediste. He mirado el resultado, las 1.585 líneas de Slint, las
16 + 2 reglas de `AGENTS.md` y la secuencia de commits. El diagnóstico, sin paños calientes:

### 6.1 Se diseñó sin referencia, y sin referencia todo juicio es gusto

La primera maqueta inventó un mundo visual (una radio de válvulas de baquelita). No estaba
mal hecha: estaba **sin ancla**. Con un mundo inventado no hay contra qué medir un espacio,
un tamaño de letra ni un contraste, así que cada ronda se convirtió en una discusión de
gusto, y el gusto no se puede medir, así que ninguna ronda cerraba nada.

Lo que funcionó fue exactamente lo contrario: **medir una interfaz que ya existe** (Avira
Free Security), sacar su paleta a una tabla y adoptar su gramática. A partir de ahí las
discusiones se volvieron comprobables («este gris da 4.49, hace falta 4.5»).

**Regla para lo que queda:** ninguna pantalla nueva sin su referencia medida. Si no hay
referencia, se elige una antes de escribir la primera línea de `.slint`.

### 6.2 Slint no es HTML, y las intuiciones de layout no se transfieren

De las 18 reglas de `AGENTS.md`, **once** son trampas de Slint que un diseñador con
experiencia en CSS no esperaría:

- `alignment` actúa **solo sobre el eje principal** y cualquier valor distinto de `stretch`
  hace que los hijos usen su tamaño preferido (un hijo con `horizontal-stretch` deja de
  estirarse).
- En el eje cruzado, un hijo de tamaño fijo se pega al **inicio**, no al centro. De ahí el
  envoltorio `Mid`.
- `Text` se dibuja pegado **arriba** y ocupa todo el alto que le den: hay que pedir el
  centrado a mano.
- Un hijo de ancho fijo en un `VerticalLayout` se pega a la izquierda.
- Nunca derives el ancho de un contenedor de un hijo que depende de ese contenedor: la
  cadena resuelve por contenido y colapsa (la ventana quedó en 689 px en vez de 780).
- El sobrante de un layout se reparte entre **todos** los hijos sin `stretch`, no
  desaparece (la tarjeta de 321 px para dos líneas).

Cada una de esas costó una ronda de arreglos. Lo que funcionó fue escribir la trampa con
su número medido, para que no vuelva. **Eso hay que mantenerlo**, y añadiría una regla más:
*si el mismo arreglo se repite en tres sitios, se convierte en un componente con nombre*
(es lo que ya pasó con `Mid`).

### 6.3 Se verificaba mirando, y mirar no es verificar

Hubo un momento en que dijiste «el botón no tiene el texto centrado» y yo había concluido
que sí. La medición dio 1,5 px de desviación en un botón y 0 px en el otro. Los dos teníamos
razón y ninguno la tenía: sin número no hay discusión posible.

Medir funcionó, y mucho. Pero se midió **a mano, después de cada queja**. Eso es el
problema: el coste lo pagas en cada ronda, para siempre.

### 6.4 El remedio: convertir la medición en una prueba

Esta es la recomendación que más cambiaría el proyecto:

- **Capturas doradas.** Un pequeño binario o script (`xtask`) que arranca la app en Xephyr,
  navega por las pantallas y los estados, guarda PNG en `docs/maqueta/` y los compara con
  los aprobados con `compare -metric AE` y una tolerancia. Un cambio de layout que rompa
  algo se ve en el diff del pull request, no en la siguiente queja. Todas las trampas de
  esta sesión (el área de 689 px, el borde que no llega, la etiqueta descentrada, la tarjeta
  enorme) son exactamente lo que esa prueba detecta.
- **Una prueba de contraste.** Leer `ui/theme.slint` con una expresión regular, sacar los
  pares documentados y comprobar 4,5:1 y 3:1 en `cargo test`. Hoy la auditoría de
  accesibilidad es un informe; así sería una barrera.
- **Una galería de componentes.** Una pantalla (`ui/gallery.slint`, solo en debug) con
  cada componente en cada estado: botón primario/secundario/terciario/deshabilitado, insignia
  en sus tres tonos, tarjeta de alcance elegida y no elegida, fila de hallazgo normal y
  desplegada, estado vacío. El fallo del botón terciario que salía azul (la cadena de fondos
  comprobaba `primary` antes que `quiet`) se habría visto en la galería **el primer día**,
  no en la sexta ronda. Es media tarde de trabajo y ahorra rondas enteras.

### 6.5 Un componente, ocho anchos a mano

La regla 16 dice cómo calcular el ancho de un botón (texto + 36 px, +24 si lleva icono), pero
el cálculo se hace a mano, en cada llamada, y hay ocho anchos distintos. Cada vez que subió
la escala tipográfica hubo que rehacer la aritmética, y dos veces se quedó corta («Recuperar»
a 120 px, «Ver la comprobación» a 150 px).

**Arreglo:** dos o tres variantes cerradas (`compact` 32 px de alto, `normal` 38 px,
`primary`/`secondary`/`quiet`), cada una con **una tabla de anchos revisada una vez**, y las
llamadas eligen variante, no píxeles. Si un texto nuevo no cabe en la tabla, se añade una
fila a la tabla, no un número suelto en una pantalla.

### 6.6 Una pantalla no es una imagen: es una matriz

La maqueta se revisó pantalla a pantalla, y cada pantalla es en realidad cinco o seis
estados: vacía, cargando, con un elemento, con muchos, sin base de datos, con error. De ahí
salieron los tres defectos que quedaron abiertos al final de la fase: el estado vacío
enorme, las columnas con hueco y el hueco antes de un botón eran todos **estados** que
nadie había mirado.

**Regla:** antes de dibujar una pantalla, escribir su matriz de estados (filas = pantallas,
columnas = estados) y dibujar todos. La galería de §6.4 la hace literal.

### 6.7 Lo que ya está bien en la interfaz

No todo es crítica. Estas decisiones están por encima de la media y hay que defenderlas
cuando apriete el calendario:

- **Vocabulario llano** y comprobado: nada de «firmas», «cuarentena», «motor», «regla» ni
  «capa» en pantalla (en `app.slint` esas palabras solo aparecen en comentarios). Eso se
  puede automatizar con una prueba de una línea y debería estar.
- **Una pantalla dice una cosa y ofrece una acción.** Es la regla que impide que esto se
  convierta en el panel de Avira con venta cruzada.
- **El rojo nunca es un botón.** Regla simple, fácil de auditar visualmente y la que más
  «sospecha de antivirus gratis» elimina.
- **La tipografía va incrustada.** Inter resuelve de golpe el problema de que Windows y Linux
  midan distinto; sin eso, cada ajuste de ancho habría sido a ciegas.
- **La medición por píxeles** como forma de zanjar una discusión. Es el hábito más valioso
  que ha salido de esta fase.

---

## 7. Verificación: de mirar a medir

| Qué | Hoy | Qué falta |
|---|---|---|
| Lógica | 90 pruebas, incluidas propiedades sobre parsers | Nada urgente |
| Contraste | Medido a mano una vez | Prueba que lea `theme.slint` |
| Layout | Medido a mano tras cada queja | Capturas doradas |
| Accesibilidad | Sin nada | Teclado, foco visible, etiquetas `accessible-*` |
| Windows | Nunca ejecutado | VM 1366×768 a 150 %, análisis real, RAM |
| Falsos positivos | Sin medir | Analizar una carpeta de programas instalados y contar |

El punto de accesibilidad merece un párrafo aparte porque es el único que **no** es estético.
Hoy toda la interacción son `TouchArea` sobre `Rectangle`: no hay foco, no hay Tab, no hay
Enter, y un lector de pantalla no ve nada. En Slint se resuelve con `FocusScope`/`focusable`,
un anillo de foco con token propio, y las propiedades `accessible-role` / `accessible-label`
en cada control. No es un rediseño: es una pasada por los controles, y como toda la interfaz
está hecha de tres componentes (`AppButton`, `ScopeCard`, `NavRow`), la mayor parte se
arregla en esos tres.

---

## 8. Cómo ha trabajado esta versión del modelo (1017)

Veinticuatro rebanadas de este proyecto se hicieron con la versión anterior y las últimas
con esta. Comparando los commits, los informes y los defectos que se colaron, esto es lo
que un modelo de esta clase aporta, dónde falla y qué guardarraíles conviene mantener.

**Donde rinde de verdad**

- **Trabajo acotado con criterio de aceptación.** La rebanada 2 (423 líneas de `main.rs`,
  cambios en el núcleo, 90 pruebas, compilación cruzada) salió en una pasada porque el
  encargo traía alcance, firmas esperadas y forma de verificar. Con un encargo vago
  («conecta la interfaz») pasa lo contrario: entrega algo plausible que hay que rehacer.
- **Inventariar un repositorio ajeno.** Sacar firmas, campos y rutas de un núcleo que no
  ha escrito es donde más tiempo ahorra y donde el riesgo de invención es bajo, siempre que
  se le pida `archivo:línea`.
- **Leer código con intención.** Las dos cosas más útiles de esta revisión (la base de datos
  junto al ejecutable y el choque de sha256 en la cuarentena) no salen de ejecutar nada:
  salen de leer dos funciones y preguntarse qué pasa en Windows.
- **Medir en vez de opinar.** Cuando se le pide un número, lo da, y zanja la discusión.

**Donde falla, y de qué manera**

- **Inventa seguridad.** La primera maqueta inventó un mundo visual entero y lo presentó
  como una decisión de diseño. No fue un error de ejecución: fue confundir «puedo
  construirlo» con «esto es lo que hace falta». Esta clase de modelo es muy buena
  produciendo coherencia interna y muy mala juzgando si esa coherencia apunta a algo.
- **Da por bueno lo que no ha probado.** «Compila y las pruebas pasan» se presenta como
  «funciona». El selector de archivos de la rebanada 2 no se ha probado en vivo y eso hay
  que arrancárselo explícitamente, no esperarlo.
- **Toma decisiones de producto sin avisar.** La insignia «9+», el `Flickable`, ocultar las
  tarjetas de alcance durante el análisis: las tres son defendibles y las tres se tomaron
  sin preguntar. Todas están en el informe del commit, que es el mínimo exigible.
- **Corrige lo que le señalan y no lo que no.** Los tres defectos que quedaron abiertos al
  cerrar la fase 4 eran estados que nadie había mirado. Un modelo no recorre la matriz de
  estados por su cuenta salvo que se le pida.
- **Pierde el hilo cuando la sesión se comprime.** El estado del proyecto se degrada con el
  contexto; lo único que sobrevive es lo que está escrito en el repositorio.

**Los tres guardarraíles que han funcionado**

1. **`AGENTS.md` con la trampa, el caso y el número.** Una regla sin el caso que la originó
   se ignora; con él se obedece.
2. **La verificación medida:** captura y píxeles, nunca «se ve bien».
3. **Encargos con alcance, firmas y criterio de aceptación.** Todo lo que se delegue sin eso
   vuelve con otra cosa.

Y dos cosas que hay que cambiar en cómo se trabaja con él:

- **Que el estado del proyecto viva en el repositorio, no en la conversación.** La sesión se
  comprime; la verdad tiene que estar en disco. Falta un `docs/ESTADO.md` de una página: qué
  funciona de verdad, qué es maqueta, qué está roto y cuál es la siguiente rebanada,
  actualizado en el mismo commit que el cambio. Es el documento que lee primero quien llega
  nuevo, y hoy no existe.
- **No encadenar cuatro verificaciones al cerrar una fase** (build + tests + clippy +
  compilación cruzada): cada una cuesta minutos y la cruzada cinco. Alternar: pruebas en
  cada rebanada, cruzada al cerrar la fase.

---

## 9. Plan propuesto

| Fase | Contenido | Criterio de aceptación |
|---|---|---|
| **5a. Que no mienta** | Inicio con tres estados · `demo` fuera o gated · contador de fallos por archivo · base de datos en `%LOCALAPPDATA%` · `rhino-db` fuera del artefacto | Ninguna pantalla enseña un dato que no venga del disco; el binario no incluye el firmador |
| **5b. Las dos pantallas que ya tienen núcleo** | Poner a salvo (listar, recuperar, borrar) · Historial (escribir en cada análisis y enseñarlo) · arreglo del sha repetido en `store` | Se puede apartar, recuperar y borrar; el historial sobrevive al reinicio; dos copias del mismo archivo no se pisan |
| **5c. Ajustes de verdad** | Estado real de la protección · descarga conectada · ignorados persistentes | «Actualizar» descarga e instala; «Ignorar» sobrevive a cerrar la app |
| **5d. Accesible** | Teclado, foco visible, etiquetas `accessible-*` en los tres componentes de control · ventana que quepa a 150 % | Se recorre toda la app solo con Tab y Enter; en 1366×768 al 150 % entra |
| **5e. Windows de verdad** | VM con Windows 10 x86 · análisis del equipo completo · RAM y tiempo · falsos positivos sobre programas instalados | Números en el README, no impresiones |
| **6. Rendimiento** | Hilos, corte por tipo de archivo, carga de reglas fuera del hilo de interfaz (solo si 5e lo pide) | Archivos por segundo y RSS medidos antes y después |

Y dos tareas transversales que no son fases porque se hacen una vez:

1. **Capturas doradas + prueba de contraste + galería** (§6.4). Es la inversión que evita
   repetir la fase 4 entera en cada pantalla nueva.
2. **`docs/ESTADO.md`** (§8), actualizado por commit.

---

## 10. Anexo: comprobaciones que repetiría

```bash
# Lógica
cargo test --workspace && cargo clippy --workspace --all-targets

# Interfaz, medida (nunca a ojo)
cargo build -p rhino-app
pkill -x rhino-app; pkill -x Xephyr; sleep 1
Xephyr :99 -screen 1100x820 -nolisten tcp &
sleep 2
env -u WAYLAND_DISPLAY DISPLAY=:99 ./target/debug/rhino-app &
sleep 5
DISPLAY=:99 import -window root -crop 980x680+0+0 +repage /tmp/opencode/x.png

# Contraste de un par concreto (WCAG 2.x)
python3 - <<'PY'
def lum(h):
    h=h.lstrip('#'); r,g,b=[int(h[i:i+2],16)/255 for i in (0,2,4)]
    f=lambda c: c/12.92 if c<=0.03928 else ((c+0.055)/1.055)**2.4
    r,g,b=f(r),f(g),f(b); return 0.2126*r+0.7152*g+0.0722*b
def cr(a,b):
    la,lb=lum(a),lum(b); hi,lo=max(la,lb),min(la,lb)
    return round((hi+0.05)/(lo+0.05), 2)
print(cr('#A7B0B9', '#3A434B'))
PY

# Windows (x86 y x64)
XWIN_ARCH=x86_64 cargo xwin build --release --target x86_64-pc-windows-msvc
XWIN_ARCH=x86    cargo xwin build --release --target i686-pc-windows-msvc
```

---

## Cierre

El proyecto está mejor de lo que su historia sugiere. El núcleo tiene una forma que cuesta
más de lo que parece conseguir: firmado, con topes, con aislamiento de pánicos, sin `unsafe`,
con pruebas de propiedad y con la memoria cuidada donde duele. Las 90 pruebas y los 24
commits explican por qué.

Lo que falta no es más código: es **dejar de fingir** (los datos de ejemplo y el «estás
protegido» sin haber mirado), **cerrar las dos pantallas cuyo núcleo ya existe**, y
**convertir la medición en prueba** para no volver a pagar la fase 4 en cada pantalla.

Si tuviera que elegir una sola cosa para la próxima sesión: la 5a completa, y no distribuir
un binario hasta que Inicio deje de afirmar algo que no ha comprobado.
