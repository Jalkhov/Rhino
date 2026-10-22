# Rhino

[![Licencia](https://img.shields.io/badge/licencia-GPL--3.0-blue.svg)](LICENSE)
[![Windows](https://img.shields.io/badge/Windows-10%20%7C%2011%20%C2%B7%20x86%20%7C%20x64-0078D6?logo=windows)](README.md#plataforma-objetivo)
[![Rust](https://img.shields.io/badge/Rust-1.98.1-CE412B?logo=rust)](https://www.rust-lang.org)
[![Slint](https://img.shields.io/badge/Slint-1.18.1-2379F4)](https://slint.dev)
[![Estado](https://img.shields.io/badge/estado-beta%20cerrada-yellow)](https://github.com/Jalkhov/Rhino/releases)
[![Beta](https://img.shields.io/github/v/release/Jalkhov/Rhino?include_prereleases&label=beta&color=yellow)](https://github.com/Jalkhov/Rhino/releases)

Antivirus ligero, rápido y de bajo consumo para Windows, con interfaz intuitiva y gratuito.
En beta cerrada: ya analiza, aparta archivos, guarda historial y actualiza su protección.

Funciona en Windows 10 y 11, de 32 y 64 bits. El **mínimo exigido es Windows 10 de 32 bits
con 4 GB de RAM**, que es el equipo al que apunta el diseño; no es un límite de
compatibilidad. Se compila para las dos arquitecturas.

## Principio rector

La eficiencia es la característica principal, no una optimización posterior. Rhino debe
ser prácticamente imperceptible en un equipo modesto: **la restricción dura es el consumo
de memoria y de CPU**, no el tamaño. Sin picos de CPU, sin consumo excesivo de RAM y sin
ralentizar el sistema. La funcionalidad se inspira en lo mejor de los antivirus
reconocidos, pero sin su peso.

**El tamaño de los binarios y del paquete de datos no es una restricción.** Un antivirus
potente y de bajo consumo no cabe en 3 MB, y recortar peso a costa de capacidad de
detección sería el error contrario. Lo que no se cruza es la memoria en uso y el tiempo de
CPU; el consumo medido se anota en "Motor de detección y base de datos".

## Plataforma objetivo

- **Mínimo:** Windows 10 de 32 bits (x86) con **4 GB de RAM**.
- **También soportado:** Windows 10/11 de 64 bits (x64).
- **Desarrollo:** Ubuntu, con compilación cruzada hacia Windows.

Los 4 GB son la base de desarrollo (provisional, octubre de 2026). Son el suelo, no un
techo: el punto está en no apuntar cada decisión a equipos de 1 GB, que ya no corresponden a
las máquinas reales y estrangularían el antivirus.

El consumo de **100 a 200 MB** es solo una referencia de trabajo, no un límite: se irá
ajustando a medida que el software crezca, con las mediciones de la sección "Consumo medido"
como punto de partida. Ninguna decisión de diseño se descarta por no caber en esa cifra.

En 32 bits conviene recordar que el sistema operativo solo ve unos 3,2 GB de esos 4 GB y
que **un proceso de 32 bits dispone de ~2 GB de espacio de direcciones**, del que también
sale el archivo mapeado.

### Política de arquitectura

Se diseña **32 bits primero**. Los límites de x86 (espacio de direcciones de 2-3 GB,
`usize` de 32 bits, archivos que no se pueden mapear completos en memoria) son la
línea base, y x64 es un superconjunto de esos límites.

Todo el código específico de arquitectura o de Windows vive en un único módulo
`platform`; el núcleo (motor de firmas, hashes, lógica de escaneo) es agnóstico. La
base de firmas es neutral respecto a la arquitectura y está versionada.

Así, abandonar x86 en una versión futura (planificado para una eventual 2.0, dejando
la última compilación de 32 bits funcionando sin actualizaciones) se reduce a: quitar
el target i686 de la CI, congelar el canal de actualización de 32 bits y borrar el
módulo `platform`. Sin tocar el núcleo.

## Alcance

**Solo modo usuario (user-mode).** Nada de kernel por ahora: ni minifiltros, ni
drivers. Es delicado, requiere firma de drivers y su propio ciclo de desarrollo, y
no aporta al objetivo de eficiencia en esta etapa. Es un tema que podría tocarse muy
a futuro, pero no condiciona ninguna decisión actual.

La protección en tiempo real (Fase 7) se plantea con las capacidades de modo usuario
disponibles, sin driver.

## Privacidad

**Nada sale del equipo.** Rhino no envía rutas, nombres de archivo, contenido ni
telemetría, ni siquiera anónima. Lo único que cruza la red es la descarga del paquete
de firmas; de todo lo que Rhino conoce, lo único que expone es lo que ese paquete
identifica (su versión y su canal).

Un antivirus que reporta lo que el usuario tiene en su disco es justo lo que este
proyecto no quiere ser, y es también la razón por la que muchos usuarios desconfían
de los antivirus comerciales.

## Estado

**Fase 1 (investigación) — completada.** Lenguaje: Rust. Interfaz: Slint.

**Fase 2 (entorno y esqueleto) — completada.** Workspace con `rhino-core` (núcleo
agnóstico), `rhino-app` (interfaz) y `rhino-db` (constructor del paquete). Compilación
cruzada a x86 y x64 de Windows, operativa y verificada.

**Fase 3 (motor de escaneo) — completada.** Las tres capas, el paquete firmado y el
actualizador funcionan y están probados contra el paquete real de 5137 reglas.

**Fase 4 (interfaz) — completada.** Seis pantallas ancladas en una captura medida de Avira,
vocabulario llano, tipografía incrustada y medidas verificadas sobre capturas.

**Fase 5 (interfaz honesta y completa) — completada**, en cinco rebanadas. La aplicación ya
no enseña ningún dato de ejemplo:

- **Inicio** dice lo que sabe. Sin paquete pide actualizar; con paquete y sin análisis dice
  que todavía no se ha mirado nada; con un análisis hecho, verde o rojo según lo encontrado.
  Nunca afirma "protegido" sin una revisión que lo sostenga.
- **Analizar** un archivo, una carpeta o todo el equipo, con el recuento en vivo, el archivo
  que está mirando y un botón para detenerlo. El selector de archivo y carpeta es el nativo
  de Windows (`rfd`). Los archivos que no se pudieron leer se cuentan y se enseñan.
- **Archivos sospechosos** enseña los hallazgos reales con la capa que los encontró y, si
  vino de una regla, su identificador, autor y origen: la atribución que exige DRL 1.1.
- **Poner a salvo** mueve el archivo a `%LOCALAPPDATA%\Rhino\apartados` con su ficha, sin
  extensión, y permite recuperarlo o borrarlo. Nunca sobrescribe una copia existente.
- **Historial** apunta cada revisión terminada en `historial.jsonl` y sobrevive al reinicio.
  Un análisis detenido o fallido no se apunta, porque no es una revisión.
- **Ajustes** enseña la protección instalada, la descarga (firmada, verificada y con relevo
  atómico, sin reiniciar) y la lista de archivos ignorados, que persiste por SHA-256.
- **Teclado y accesibilidad**: se recorre todo con Tab y Shift+Tab, se activa con Intro y
  Espacio, el foco se ve con un aro de 2 px y cada control declara su papel y su etiqueta
  (`accessible-*`). Verificado en Windows con el binario de 32 bits.

La única maqueta que queda es la tira **MAQUETA · ESTADO**, que solo existe en las
compilaciones de depuración.

### La primera beta

`v0.1.0-beta1` está publicada con los dos binarios (x86 y x64) y su `SHA256SUMS`. Se probó en
Windows: el `.exe` de la release **descargó e instaló la protección sin configurar nada**, y
la base quedó en `%LOCALAPPDATA%\Rhino\rhino-db` con la versión `2026.10.18`, 5137
comprobaciones y 1939 archivos peligrosos conocidos. Ese es el circuito que va a recorrer quien
la pruebe, y funciona.

Lo que sigue sin probar: el desinstalador, el lector de pantalla de verdad (el árbol de
accesibilidad sí existe) y el aspecto a 150 % de escala.

## Probar la beta

<https://github.com/Jalkhov/Rhino/releases>

El ejecutable **no está firmado**, así que SmartScreen dirá «Windows protegió tu PC»:
«Más información» y después «Ejecutar de todas formas». El archivo no está modificado; el
SHA-256 publicado en la release sirve para comprobarlo:

```powershell
Get-FileHash .\rhino-0.1.0-beta1-x86.exe -Algorithm SHA256
```

Al abrirlo, la tarjeta de Inicio pide actualizar la protección: eso descarga el paquete
firmado desde la release `db-latest` y lo verifica antes de instalarlo. Después, «Analizar
todo el equipo».

## Desinstalar

Son dos pasos, porque Rhino es un `.exe` suelto y no tiene instalador:

1. En **Ajustes**, baja hasta **Quitar Rhino** y pulsa el botón. Borra la protección
   instalada, el historial, lo que hayas ignorado y los archivos apartados; después la
   ventana se cierra.
2. Borra el `.exe` que descargaste.

## Documentación

- [`docs/motor.md`](docs/motor.md) — las capas de detección, de dónde salen las reglas, el
  paquete firmado, el actualizador, la robustez y las cifras de memoria y velocidad.
- [`docs/interfaz.md`](docs/interfaz.md) — por qué Slint, las decisiones de diseño y la
  accesibilidad.
- [`docs/pruebas.md`](docs/pruebas.md) — qué se prueba y cómo, del contraste al banco de la
  máquina virtual.
- [`docs/compilar.md`](docs/compilar.md) — compilación cruzada, integración continua, sitio y
  herramientas.
- [`docs/fases.md`](docs/fases.md) — método de trabajo, fases y lo que queda.

## Licencia

Rhino se publica bajo la **GNU General Public License, versión 3** (ver `LICENSE`). Se eligió
porque es la que encaja sin matices con Slint —que se usa bajo su opción GPLv3— y la que
aceptan los programas de firma gratuita para proyectos de código abierto. Quien lo modifique
y lo distribuya tiene que publicar sus cambios.

Las piezas de terceros conservan su licencia: YARA-X (BSD-3-Clause), las reglas de YARA Forge
(DRL 1.1, BSD y Apache 2.0, con la atribución de autor que se enseña en cada hallazgo), Inter
(SIL OFL 1.1) y Lucide (ISC), con sus avisos en `crates/rhino-app/ui/fonts/`.

## Riesgos conocidos

- **El ejecutable no está firmado.** SmartScreen avisa en el primer arranque y hay que pasar
  por «Más información» → «Ejecutar de todas formas». Se publica el SHA-256 de cada binario y,
  cuando el proyecto pueda acogerse a un programa de firma para código abierto, se firmará.

- **La clave privada de firma vive solo en este equipo**, en `~/.config/rhino/db-key`
  (permisos 600) y sin respaldo remoto. Si se pierde, no se pueden firmar más paquetes y habría
  que publicar una versión nueva con otra clave pública. Conviene copiarla a un gestor de
  contraseñas o a un medio aparte.
- **El aislamiento del escaneo no repara el motor.** El perfil de release ya no usa
  `panic = "abort"` y cada archivo se analiza dentro de `scan::isolate`, así que uno que haga
  caer al lector o a YARA-X se reporta como *no analizado* (y por tanto *sospechoso*) en lugar
  de tumbar el proceso. El límite es que el pánico pudo dejar el motor en un estado
  inconsistente: si aparece uno reproducible, habrá que mover el análisis a un proceso aparte.
- **La base de datos no se puede corregir por partes.** Si una regla publicada empieza a dar
  falsos positivos, hoy solo se arregla reconstruyendo y firmando el paquete completo. ClamAV
  permite silenciar una firma concreta con un archivo de texto; sería barato de añadir y
  evitaría publicar 8,5 MB nuevos para tapar una sola regla. Ya nos pasó con la regla de
  *hacktool* que marca `socat`.
- **No se avisa de una base de datos vieja.** Un antivirus desactualizado da falsa confianza,
  porque el usuario no puede saber que su protección tiene meses. Conviene mostrar los días
  transcurridos desde la fecha del paquete.
- **El conjunto de reglas cargado cuesta unos 52 MB de RAM**, y crece con el número de
  reglas que se empaqueten. Es hoy el mayor consumidor de memoria de Rhino: cada ampliación
  de la base de datos mueve esa cifra y conviene volver a medirla.
- **Windows 10 de 32 bits está al final de su vida (EOL desde octubre de 2025).** Es la
  plataforma mínima pedida, así que se soporta, pero conviene saberlo.
- **Rust está degradando los objetivos i686:** desde Rust 1.100 solo se distribuye la
  *std*, no las herramientas de compilación en 32 bits. Los binarios de 32 bits se
  siguen construyendo, pero hay que **compilar cruzado desde Linux/64 bits** (que es
  justo el plan de desarrollo definido).
- **Cualquiera puede compilar y publicar un fork** con el mismo nombre: el código es libre,
  así que el vector ya no es revertir el binario sino confundir al usuario. La defensa es que
  las releases sean identificables: SHA-256 publicado en cada una, descarga solo desde este
  repositorio y, cuando se pueda, el ejecutable firmado.

- **Un análisis del equipo entero tarda.** A 77,5 archivos por segundo medidos en Windows,
  medio millón de archivos son casi dos horas, y el coste lo pone el contenido. Se puede usar
  el equipo mientras tanto y se puede detener, pero conviene no prometer «unos minutos» para
  un disco lleno.
- **La ventana no entra a 150 %.** 980x680 lógicos son 1470x1020 físicos; en un portátil de
  1366x768 con esa escala pide una referencia de unos 900x480, recalcular riel, rellenos y
  columnas del historial, y envolver Ajustes en un `Flickable`.
- **El lector de pantalla no se ha probado.** El árbol de accesibilidad compila, los papeles
  y las etiquetas están puestos y el teclado está verificado, pero en el equipo de desarrollo
  no hay sesión AT-SPI: nadie lo ha oído hablar.
- **Deudas menores de la interfaz:** «Borrar» de Poner a salvo no pide confirmación; el aviso
  de copia repetida mide 372 px y se elide en los 320 del encabezado; el análisis de un
  archivo suelto no atiende a Detener; y en depuración el arranque con paquete tarda unos
  20 s porque compila las reglas.
