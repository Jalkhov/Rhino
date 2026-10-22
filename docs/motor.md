# El motor: capas, reglas y paquete

[← Volver al README](../README.md)
## Lenguaje: Rust

Elegido sobre Go por tres razones que atacan directo los objetivos del proyecto:

1. **Eficiencia y seguridad de memoria a la vez:** memoria segura sin recolector de basura.
   No hay pausas *stop-the-world*, lo que importa en un servicio que escanea archivos en
   tiempo real, y ninguna de las clases de fallo de memoria que dominan los CVE de los
   antivirus (casi todos, parsers de formatos). Huella y latencia predecibles.
2. **Ecosistema de seguridad nativo:** [YARA-X](https://github.com/VirusTotal/yara-x)
   (reescritura de YARA hecha en Rust por VirusTotal, madura y en producción) es el
   motor de firmas de facto y ya está en Rust. Con Go habría que usar CGo, que complica
   la compilación cruzada.
3. **Acceso a Windows:** [`windows-rs`](https://github.com/microsoft/windows-rs), de
   Microsoft, da bindings seguros a toda la API Win32. Y a diferencia de Go, Rust puede
   escribir drivers de kernel (minifiltros) si una fase futura lo requiere.

## Motor de detección y base de datos

**El motor de patrones no se escribe desde cero.** Es
[YARA-X](https://github.com/VirusTotal/yara-x) (licencia BSD-3-Clause), la reescritura
de YARA en Rust que VirusTotal tiene en producción escaneando miles de millones de
archivos. Lo propio de Rhino es el orquestador de escaneo, el formato del paquete de
base de datos, el actualizador, la heurística propia y la interfaz.

### Capas de detección

Las firmas son solo una de varias capas:

| Capa | Qué detecta | Coste | Depende de |
| --- | --- | --- | --- |
| 1. Hash exacto | Malware ya conocido (IOC) | Muy bajo | Listas de hashes |
| 2. Firmas YARA-X | Familias, herramientas de ataque, webshells, exploits | Bajo | YARA Forge |
| 3. Heurística propia | PE anómalo, packers, entropía alta, macros sospechosas | Medio | Solo Rhino |
| 4. Comportamiento (futuro) | Acciones en ejecución, en modo usuario | — | Solo Rhino |
| 5. ML / reputación (futuro) | — | — | — |

La capa 3 es la diferencia real: es la única donde Rhino aporta detección propia y no
depende de terceros.

### De dónde salen las firmas

De **YARA Forge** ([`YARAHQ/yara-forge`](https://github.com/YARAHQ/yara-forge)), un
proyecto que recolecta reglas de más de 45 repositorios de seguridad, las normaliza, las
prueba contra falsos positivos, las puntúa (0–100) y publica **paquetes semanales** en
tres niveles: `core` (alta calidad, bajo falso positivo), `extended` y `full`. Es lo que
usan productos comerciales como THOR.

Un trabajo automático en la CI haría el resto: descargar el release semanal, filtrar las
reglas con licencia copyleft, compilar con `yr compile`, armar el paquete, firmarlo y
publicarlo. Sin trabajo manual y sin laboratorio de malware propio.

### Licencias

Se consumen **solo fuentes permisivas**: YARA Forge `core` (mezcla de DRL 1.1, BSD y
Apache 2.0), y repositorios como Signature Base y SEKOIA.IO (DRL 1.1, que permite el uso
comercial con atribución). Quedan descartadas las reglas GPL (Yara-Rules/rules, CAPE
Sandbox) y la base de datos de ClamAV (GPL), que obligarían a que todo Rhino fuese GPL y
enredarían la compatibilidad con Slint (GPLv3 o comercial).

Esto mantiene a Rhino libre para ser abierto o cerrado cuando se decida.

**Consecuencia obligatoria:** la licencia DRL 1.1 exige que el mensaje de detección
nombre al autor de la regla. La interfaz debe poder mostrar *"Detectado por la regla X,
autor Y, fuente Z"*.

### Paquete de base de datos

```
rhino-db-AAAA.MM.DD/
  manifest.json   versión, fecha, canal, conteos y hash de cada archivo
  rules.yarc      reglas YARA-X precompiladas
  hashes.bin      hashes conocido-malo (capa 1)
  manifest.sig    firma Ed25519 del manifest
```

No hay `meta.json` a propósito: los metadatos por regla (autor, `source_url`) viajan dentro
de las reglas compiladas y el motor los devuelve con cada coincidencia, así que la
atribución que exige DRL 1.1 ya queda satisfecha sin duplicarlos en un archivo aparte.

`hashes.bin` tampoco depende de un feed externo: las reglas de YARA Forge declaran en su
metadato `hash` los hashes de las muestras contra las que se escribieron, y de ahí se extrae
la lista (más el EICAR).

Las reglas se compilan **una sola vez, en la CI**, nunca en el equipo del usuario: compilar
miles de reglas al arrancar cuesta segundos y unos 180 MB de memoria en una máquina modesta,
mientras que cargar el archivo precompilado cuesta unos 52 MB. El paquete va firmado con
Ed25519 (clave pública dentro de Rhino, privada solo en los secretos de la CI): sin esa
firma, quien intercepte una actualización podría apagar el antivirus. Además de la firma,
`load()` comprueba el tamaño y el SHA-256 de cada archivo antes de usarlo.

El paquete es neutral respecto a la arquitectura; el manifiesto ya lleva el campo `channel`,
para que los canales por arquitectura solo necesiten transporte.

**Cómo se construye y se verifica.** El crate `rhino-db` es la herramienta del workspace:

```sh
cargo run -p rhino-db -- keygen <clave-privada>    # una sola vez; la privada nunca va al repositorio
cargo run -p rhino-db -- build --rules <yara-rules-core.yar> --out <dir> \
                              --channel stable --key <clave-privada>
cargo run -p rhino-db -- verify --package <dir> [--public-key <hex>]
```

`build` compila, firma y **verifica su propia firma antes de escribir nada**.

Medición real del paquete `core` (octubre de 2026): **5137 reglas y 1939 hashes**: compilar
tarda unos 34 s (una vez por semana, en la CI) y el paquete ocupa 8,5 MB de reglas más 0,1 MB
de hashes.

La clave de producción ya está puesta: `DB_PUBLIC_KEY` en `db.rs` lleva la real, y su mitad
privada vive en `~/.config/rhino/db-key` (fuera del repositorio, con permisos 600). Es el
único secreto del proyecto: quien la tenga puede emitir un paquete que apague Rhino en todos
los equipos.

### Consumo medido

Ruta de producción (`.yarc`, `RuleSet::from_compiled`), con el paquete `core` completo,
medido con `/usr/bin/time -v`:

| Escenario | RAM máxima |
| --- | --- |
| Capas 1 y 3, sin reglas | 11 MB |
| Con las 5137 reglas cargadas | 63 MB |
| Más un archivo de 512 MB | 115 MB |
| Compilando esas reglas en el equipo del usuario | 238 MB |

El conjunto cargado ocupa unos **52 MB**, y ahí está el argumento definitivo para
precompilar en la CI: hacerlo en el equipo del usuario no solo cuesta segundos, cuesta
unos 180 MB más de RAM. Los archivos grandes se leen con memoria mapeada (por encima de
32 MB), que es paginada del sistema de archivos y el sistema operativo puede reclamar: no
presiona la memoria como lo haría un `Vec`.

Escanear `/usr/bin` (2394 archivos) tarda 26 s con reglas y 9 s sin ellas.

### Medido en Windows

Banco del núcleo en la máquina virtual (Windows 10, **4 GB de RAM, 4 vCPU**), con el binario
x86 de 32 bits en release (bajo WoW64, porque el Windows de la máquina virtual es de 64 bits)
y el paquete real de 5137 reglas, sobre `C:\Program Files`:

| Dato | Medido |
| --- | --- |
| Archivos | 4413 (1088 ejecutables PE) en 56,96 s |
| Velocidad | **77,5 archivos por segundo** |
| Memoria de pico durante el análisis | **225 MB** |
| Resultado | 0 maliciosos, **3 sospechosos**, 4410 limpios |
| Escala del sistema | respetada: al 125 % la ventana mide 1222 px físicos |

Las cifras que había antes en esta tabla (9,3 archivos por segundo y 53 MB) eran de la misma
máquina con **una sola CPU y un solo hilo**, así que no son comparables: al pasar a 4 vCPU y
4 hilos cambiaron las dos cosas a la vez. La ganancia del código, aislada, está en la sección
siguiente.

La protección se descargó e instaló desde el sitio sin reiniciar la aplicación, y el teclado
(Tab, Shift+Tab e Intro con el foco visible) funciona en el invitado.

El coste lo pone el contenido, no el número de archivos: esta pasada va a 77,5 por segundo en
`C:\Program Files`, y otra que empezó por la raíz de `C:` y se topó con lo borrado de la
Papelera de reciclaje bajó a 1,2. Cuatro archivos de varios gigabytes tardan más que diez mil
ejecutables pequeños.

**Falsos positivos: 3 de 4413** (0,07 %). No fue siempre así: la primera pasada con la
heurística anterior marcaba **65**, y no eran 65 archivos raros sino dos reglas mal
calibradas:

- El **nombre de una sección de empaquetador** marcaba por sí solo. AIDA64, GPU-Z, el
  instalador de Partition Wizard y el propio Detect It Easy están empaquetados con UPX,
  MPRESS o Enigma, y que un binario esté comprimido no dice nada del contenido. Ahora ese
  nombre solo no marca.
- La heurística de **secciones ejecutables y escribibles** contaba la `INIT` de los
  controladores (28 de los 65), que Windows hace W+X a propósito para usarla al arrancar y
  descartarla, y las secciones propias de UPX. Ahora se excluyen las que son W+X por
  construcción: las del enlazador (`.textbss`), las de un empaquetador y `INIT`.

Los tres que quedan son otro asunto y se explican: `version.dll` y `UninstallToolHelper.exe`
llevan la sección de código W+X, y el segundo además tiene secciones de nombre aleatorio
(`z0tyg8go`, `oc7esfle`), que es la huella de un instalador protegido; `bdcam.exe` (Bandicam)
lleva una sección propia W+X. Dos son software legítimo protegido y uno es una DLL con el
código modificable: el tipo de archivo que la heurística debe seguir enseñando.

### Reparto entre hilos y corte por tipo

El análisis era secuencial: un hilo recorría el árbol y cada archivo pasaba por hash,
cabecera PE y reglas. Ahora son hasta cuatro hilos (`available_parallelism()` acotado a
cuatro, porque más se pelean por el disco y cada archivo en vuelo puede mapear 64 MB) y las
reglas se saltan en imágenes, audio y vídeo.

Medido en este equipo (4 núcleos), binario release y el paquete real de 5137 reglas:

| Árbol | Antes | Ahora |
| --- | --- | --- |
| `/usr/bin` (2395 archivos), con reglas | 26 s | **11,75 s** |
| `/usr/bin`, sin reglas | 9 s | **3,62 s** |
| `/usr/share/icons` (80.520 archivos, 19.485 imágenes) | 59,42 s | **43,51 s** |
| `/usr/bin` con el corte, de control | 11,75 s | 11,99 s |

El control importa: `/usr/bin` no tiene imágenes, así que el corte no debe moverlo, y no lo
mueve. En el árbol de iconos el corte quita el 27 % del tiempo; el resto son 60.587 SVG, que
sí pasan por las reglas porque las reglas detectan webshells y documentos. Nunca se cortan
documentos (PDF, Office, SVG), fuentes ni ejecutables, y el hash de la capa 1 se calcula
siempre.

Dos costes que conviene saber. El CPU total **sube** (de 28,5 s a 40 s en `/usr/bin`): el
mismo trabajo en menos tiempo de pared, con cuatro archivos en vuelo, más presión de caché y
hasta cuatro mapeos a la vez. Y la memoria con reglas sube de unos 130 MB a 180-200 MB; sin
reglas son 12 MB. En un equipo de 4 GB sigue siendo un 5 %, pero es la cifra nueva.

Cargar el paquete real cuesta 1,1 s en release, así que la carga no se mueve al hilo de
análisis: los 20 s del arranque en depuración son de compilar las reglas en ese perfil.

Confirmado en Windows: el banco de arriba corrió con cuatro hilos y el corte, y de ahí sale
la cifra de 77,5 archivos por segundo.

### Actualizador

`rhino_core::update` descarga un paquete publicado y lo instala:

```sh
cargo run -p rhino-db -- update <url> <directorio>
```

La aplicación lee la base de datos del perfil del usuario, no de la carpeta del
programa: `%LOCALAPPDATA%\Rhino\rhino-db` en Windows y
`~/.local/share/Rhino/rhino-db` (o `$XDG_DATA_HOME/Rhino/rhino-db`) en el resto. Para
probar contra el sitio local:

```sh
cargo run -p rhino-db -- update http://localhost:27182/db/stable ~/.local/share/Rhino/rhino-db
```

El módulo **solo descarga**: quien tiene autoridad para aceptar un paquete es `db::Package`
con la firma Ed25519, no el código que habla por la red. De ahí el reparto: `update` baja
primero `manifest.json` y `manifest.sig`, comprueba la firma, y **solo si la versión es
distinta** se molesta en bajar los 8,5 MB de reglas.

El reemplazo es por directorio completo, nunca archivo a archivo. El paquete nuevo se arma en
`rhino-db.nuevo` y se verifica entero (firma más SHA-256 de cada archivo); solo entonces se
intercambia con el instalado, que queda como `rhino-db.anterior` y se borra. Si el intercambio
falla a mitad, el paquete viejo vuelve a su sitio. Nunca existe un estado intermedio.

La URL base vive compilada en `update::DEFAULT_URL`
(`https://github.com/Jalkhov/Rhino/releases/download/db-latest`): una etiqueta fija que se
sobrescribe cada semana con el paquete del día. No se usa `latest` porque apunta a la release
más nueva de todas, y el programa también publica. `RHINO_DB_URL` la anula, que es lo que
sirve para probar contra el sitio local de `web/`.

### Robustez

El motor come archivos que el usuario no escribió, y la historia de ClamAV lo dice con
claridad: casi todos sus CVE críticos son parsers de formato y descompresores que caen o se
salen de los límites con una entrada manipulada, no fallos del motor de firmas. Rust cierra la
corrupción de memoria, que es la mayoría de esos casos, pero no el pánico, el desbordamiento
silencioso ni el bucle infinito.

Tres defensas, de dentro hacia fuera:

- **Lecturas acotadas.** El lector PE lee solo cabeceras y como mucho 96 secciones, aunque la
  cabecera declare otra cosa. Ninguna capa carga el archivo entero en memoria.
- **Pruebas de propiedad** (`proptest`, solo como dependencia de desarrollo, así que no entra
  en el binario): bytes arbitrarios y ejecutables válidos mutados no pueden hacer entrar en
  pánico al lector, y el veredicto nunca puede decir «limpio» mientras un hallazgo diga otra
  cosa.
- **Aislamiento del pánico.** El perfil de release usa `unwind` a propósito y cada archivo se
  analiza dentro de `scan::isolate`: uno que haga caer al motor se reporta como *no analizado*
  (sospechoso) en vez de llevarse por delante el escaneo entero. Un archivo que no se pudo
  mirar nunca se reporta como limpio.
