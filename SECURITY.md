# Seguridad

Rhino analiza archivos que el usuario no escribió, y verifica un paquete que llega por la
red. Un fallo en cualquiera de las dos cosas puede ser grave. Si encuentras uno, **no abras
una incidencia pública**: usa un aviso privado en
<https://github.com/Jalkhov/Rhino/security/advisories/new>.

Ayuda muchísimo: la versión (Ajustes → Acerca de Rhino), qué archivo o paquete lo provoca y
los pasos para reproducirlo. Una muestra **inofensiva** (un PE truncado, una cabecera
manipulada) es bienvenida; el proyecto no almacena malware real, porque nunca ejecuta lo que
analiza.

Se considera grave:

- que un archivo analizado tumbe el proceso o el equipo, o agote la memoria;
- que la verificación acepte un paquete sin firma válida o con el contenido cambiado;
- que Rhino escriba fuera de `%LOCALAPPDATA%\Rhino`;
- que diga «limpio» sobre algo que no pudo mirar.

No son avisos de seguridad: los falsos positivos (abre una incidencia normal con el nombre
del archivo y la regla que lo marcó) ni un falso negativo que dependa de la base de datos de
YARA Forge.
