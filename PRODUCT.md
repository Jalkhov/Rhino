# Product

<!-- impeccable:product-schema 1 -->

## Platform

adaptive

Aplicación nativa de escritorio (Slint). El objetivo de publicación es Windows de 32 y 64
bits. El arranque de Impeccable no contempla "escritorio Windows" entre sus valores, así que
se registra `adaptive`: un solo código nativo que puede compilarse para varios sistemas, y que
hoy se distribuye solo en Windows.

## Users

**Usuario común, poco técnico** (confirmado por el usuario, octubre de 2026). Usa un equipo
Windows modesto —32 bits, 4 GB de RAM— de forma doméstica. Quiere estar protegido y enterarse
solo si hay un problema real. No sabe qué es un falso positivo y no le interesa saberlo. No va
a cambiar de hábitos ni a aprender un programa nuevo: si Rhino le obliga a decidir algo que no
entiende, se equivocará o lo desinstalará.

No hay más audiencias confirmadas. Los usuarios técnicos quedaron fuera del alcance explícito
de esta primera versión.

## Product Purpose

Rhino existe porque los antivirus comerciales convierten un equipo modesto en un equipo
inservible: consumen la memoria y el procesador que el usuario necesita para trabajar. Rhino
quiere proteger esos equipos **sin que se note**.

El éxito no es detectar más que nadie. El éxito es que el usuario esté protegido y no tenga que
pensar en Rhino.

## Positioning

Cuatro cosas que un antivirus vecino no podría decir con honestidad:

1. **Bajo consumo medido, no prometido.** ~63 MB con las 5137 reglas del paquete real cargado,
   y ~7 ms por archivo en la capa de reglas. Las cifras están en el README con su método.
2. **Nada sale del equipo.** Ni rutas, ni nombres de archivo, ni contenido, ni telemetría, ni
   siquiera anónima. Lo único que cruza la red es la descarga del paquete de firmas.
3. **Gratis de verdad.** Sin versión pro, sin venta cruzada, sin funciones retenidas.
4. **Funciona en 32 bits.** La industria abandonó esos equipos. Rhino se diseñó al revés: los
   límites de 32 bits son la línea base.

## Operating Context

- Plataforma: Windows 10/11, x86 y x64. Desarrollo en Ubuntu con compilación cruzada.
- **Rhino es un escáner estático: nunca ejecuta lo que analiza.** Es la ventaja de seguridad
  que hay que conservar en cualquier decisión futura.
- No hay detección sin base de datos. El paquete de firmas se descarga del sitio (firmado con
  Ed25519) y sin él Rhino no detecta nada, y **lo dice**: no finge haber mirado lo que no pudo.
- El sitio que sirve los paquetes vive en `web/` dentro del mismo repositorio.
- No hay telemetría, así que no existe ninguna señal de uso real. Todo juicio sobre la interfaz
  es razonamiento, no dato.
- Verificación visual en este equipo: `Xephyr` + `xdotool` + ImageMagick. No hay `Xvfb`.

## Capabilities and Constraints

**Confirmadas para esta primera versión de la interfaz** (todas elegidas por el usuario):
analizar un archivo o una carpeta; analizar todo el equipo; cuarentena; actualizar la
protección; historial; exclusiones.

**Vocabulario confirmado: llano, sin palabras de antivirus.** Se dice "Analizar", "Actualizar
protección", "Archivos sospechosos", "Poner a salvo". No se dice "firmas", "cuarentena",
"motor", "regla" ni "capa" en la superficie visible.

**Restricciones técnicas que la interfaz debe respetar:**

- Slint con **renderizador por software**: sin GPU y sin OpenGL. Animaciones costosas y efectos
  de desenfoque quedan descartados por diseño, no por gusto.
- Equipos de 4 GB. La ventana actual mide 480x320; la interfaz puede crecer, pero no debe
  asumir una pantalla grande.
- Sin driver de kernel. En tiempo real Rhino vigila y reacciona, no bloquea.
- El motor entrega, por cada detección, la capa que la produjo y el autor y la URL de la regla.
  **Mostrar la autoría es una obligación de la licencia DRL 1.1**, no una opción de diseño.
- La capa de reglas solo mira los primeros 64 MB de un archivo.

**Explícitamente indeciso:** si la cuarentena cifra lo que guarda; si el análisis se puede
programar; y todo lo relativo a la protección en tiempo real (Fase 5), que no está en esta
versión.

## Brand Commitments

- **Nombre:** Rhino.
- **Pedido vinculante del usuario** (cita literal): "algo limpio, bonito, modo oscuro, la
  paleta de colores de Avira me gusta, podríamos derivarla, quiero todo muy iconizado, se me
  ocurre Lucide icons, tiene una licencia muy permisiva, quiero una interfaz muy intuitiva,
  nada de confusa, con términos amigables para todo tipo de usuarios".
- **Paleta:** conviene no confundir dos cosas de Avira que no son la misma. **La marca** (el
  logotipo) es roja: medido `#DB0D15` sobre la captura; las fuentes públicas discrepan
  (`#E11F27`, `#E21E25` según LogoLabs, `#D40000` según brandcolor.dev). **La interfaz del
  producto no es roja**: es azul naval con verde, azul y ámbar. Esa referencia está medida
  más abajo, medida y **es la que usa la maqueta vigente**.
- **Iconografía:** Lucide, licencia ISC (es un fork de Feather Icons, MIT). Al empaquetar los
  archivos hay que arrastrar **ambos** avisos de licencia.
- **Voz:** tranquila y directa. Nunca alarmista, nunca condescendiente, nunca técnica.
- **Conflicto rojo de marca / rojo de peligro:** sigue abierto aquí. La referencia de Avira
  enseña cómo lo resuelve Avira: el rojo vive en el logotipo y **en ningún otro sitio** de la
  interfaz. Queda registrado como observación, no adoptado.

### Referencia medida: la interfaz de Avira Free Security

Captura de la aplicación en Windows (1180x833) en `docs/referencias/avira-free-security.png`,
analizada en octubre de 2026. Los valores están **medidos sobre los píxeles de la captura**,
no tomados de una guía de marca; los bordes de 1 px y las muestras sobre texto llevan
antialiasing y son aproximados.

| Papel | Valor medido |
|---|---|
| Riel lateral | `#1B2428` |
| Fondo de contenido | `#313940` |
| Tarjeta / superficie elevada | `#3A434B` |
| Separador riel–contenido (1 px) | `#232B30` |
| Acento azul (acción y fila activa) | `#1767E2`, degradado a `#145DCD` |
| Texto principal | `#FFFFFF` |
| Texto de navegación | `#F6F7F7` |
| Texto secundario y rótulos de grupo | `#949CA5`–`#99A1AB` |
| Texto "Register" del riel | `#CFD8E1` |
| Iconos | blancos, dos tonos (`#DDDDDD` + `#848484`) |
| Correcto (círculo verde) | `#168900` |
| Ámbar (aviso / venta) | texto `#F2B95A`, borde de 1 px ≈ `#D48808` |
| Rojo | solo el logotipo: `#DB0D15` |

**Gramática observada** (por si algún día se aplica):

- El rojo **no aparece en la interfaz**: vive únicamente en el logotipo.
- El verde dice "está bien" en una tarjeta de estado a todo el ancho: título en blanco y
  subtítulo gris.
- Un solo botón azul por pantalla, centrado.
- Riel de 196 px, plano, sin tarjeta; la fila activa se rellena de azul a todo el ancho y mide
  unos 35 px de alto.
- Los rótulos de grupo van en gris apagado y **en minúsculas** ("Security", "Privacy",
  "Performance"); el texto y los iconos de navegación, en blanco.
- Los círculos grandes de categoría casi no tienen relleno: un anillo apenas más oscuro que el
  fondo (`#2C343A` sobre `#313940`). Todo el peso está en el icono.
- Esquinas de radio pequeño (≈4-5 px). Sin sombras ni desenfoques.
- La caja ámbar del riel ("Get Prime") es la única venta cruzada visible, en un producto que
  se declara gratis. Rhino no hace esto (Posicionamiento, punto 3).

**Estado: aplicada.** La primera maqueta derivaba de un mundo visual inventado (una radio de
válvulas de baquelita) y se descartó por eso: el usuario no la reconoció como limpia ni
familiar. La maqueta vigente parte de esta referencia medida. De lo medido se adoptó todo
menos la venta cruzada ámbar, y los grises de texto se subieron a `#A7B0B9` porque los de
Avira no llegan a 4.5 de contraste sobre la tarjeta `#3A434B`.

## Evidence on Hand

- `README.md`: la carta del proyecto, con las decisiones, las mediciones de consumo y las
  pruebas de falsos positivos, cada una con su método.
- Seis `docs/app-*.png`: la interfaz actual, ya conectada al núcleo (inicio, analizar,
  archivos, poner-a-salvo, historial, ajustes), capturadas con el paquete real instalado.
  Son la referencia contra la que se mide cualquier cambio de diseño.
- `docs/referencias/avira-free-security.png`: la captura de la que salió la tabla de la paleta
  de Avira. Es la prueba de esa tabla; si se borra, los números quedan sin verificar.
- Las 9 `docs/maqueta-*.png`: la maqueta de la Fase 4, aprobada y ya sustituida por la
  interfaz real. Se conservan como historia del diseño: seis pantallas (`inicio`, `analizar`,
  `hallazgos`, `poner-a-salvo`, `historial`, `ajustes`) y tres estados más (`analizando`,
  `comprobacion`, `inicio-sin-datos`).
- Corpus sintético en `rhino_core::corpus` (inofensivo, generado en memoria).
- Los textos reales del producto, que son el mejor material de terminología: los mensajes del
  motor ya están escritos en lenguaje llano.

**Ausencias que el trabajo futuro NO debe fabricar:** no hay usuarios reales, ni testimonios, ni
casos de éxito, ni prensa, ni logotipo, ni capturas de un producto terminado, ni cifras de
detección propias. Cualquier maqueta que los necesite los estaría inventando.

## Product Principles

1. **Proteger sin que se note.** El consumo y la interrupción son el producto. Un antivirus que
   molesta termina desinstalado, y desinstalado protege menos que ninguno.
2. **Decir la verdad, sobre todo cuando es incómoda.** Si no se pudo mirar un archivo, no está
   limpio. Si falta la base de datos, se dice. Un antivirus que falla hacia "todo bien" es peor
   que no tener antivirus, porque el usuario se confía.
3. **Nunca asustar.** Ni para vender, ni para justificar la propia existencia. Un susto tiene
   que corresponder a un peligro real y comprobado.
4. **El usuario no debería aprender nada nuevo.** Si una pantalla necesita explicación, la
   pantalla está mal.
5. **Nada sale del equipo.**
