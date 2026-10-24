# Cambios

Lo que cambia entre versiones, en seco. Para saber qué puedes probar y qué se sabe que
falla, lee las notas de la entrega; para el relato, la web.

## Sin publicar

### Añadido

- Ajustes estrena «Qué hay de nuevo»: las novedades contadas en llano dentro del programa.
  Las notas tecnicas siguen en este archivo, que no va a abrir quien usa el programa.
  (`d807fe7`)
- «Borrar» de Poner a salvo pide confirmacion en la propia fila («¿Seguro? Es para
  siempre.»). Antes borraba para siempre con un clic. (`d807fe7`)

### Corregido

- La fila de Poner a salvo repartia el sobrante vertical entre sus dos textos, asi que el
  nombre salia pegado arriba y el dato al fondo, con 29 px de hueco donde el espaciado decia
  3. Alturas explicitas y ramas `if` en vez de `visible`: en un layout un elemento invisible
  sigue ocupando su hueco. (`d807fe7`)

## 0.1.0-beta3 — 21-10-2026

### Corregido

- El análisis de todo el equipo recorría los datos propios de Rhino y marcaba su propio
  paquete de reglas como malware (`rules.yarc`, siete reglas). `walk_files` se salta
  `%LOCALAPPDATA%\Rhino`, lo que cubre la base y lo apartado. (`99484bb`)
- Los archivos `.yar`, `.yara` y `.yarc` ya no pasan por la capa de reglas: llevan sus
  propios literales como datos y coincidían consigo mismos (`malware_analisys.yar`,
  veintidós reglas). El hash y la heurística PE se siguen calculando. (`dd7f64f`)

### Medido

- Análisis completo de `C:\` en la máquina de pruebas: 67.192 archivos (13.871 PE), unos
  15 minutos, 2 maliciosos y 6 sospechosos, todos explicables.

## 0.1.0-beta2 — 21-10-2026

### Añadido

- Ajustes → «Quitar Rhino»: borra la protección instalada, el historial, los ignorados y
  lo apartado, y cierra la aplicación. El ejecutable lo borra el usuario. (`086f393`)

### Cambiado

- Ajustes se desplaza con `Flickable`: con cuatro paneles medía unos 675 px en 624 y el
  botón quedaba cortado.

## 0.1.0-beta1 — 21-10-2026

Primera entrega para probadores. Analiza un archivo, una carpeta o el equipo entero, con
recuento en vivo y detener; enseña cada hallazgo con la capa que lo encontró y, si viene
de una regla, su identificador, autor y origen; aparta archivos sin borrarlos y los
devuelve; guarda el historial; descarga e instala la protección firmada sin reiniciar; se
maneja con teclado. Sin vigilancia en tiempo real y sin firma de código.
