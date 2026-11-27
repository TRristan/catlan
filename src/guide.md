*catlan es la web de sistemas e inventario de tu equipo de IT: wiki, inventario, esquemas, racks, monitor, salud, incidencias y dashboard, todo enlazado entre sí.* Esta página la creó catlan al instalarse: es tuya, edítala o bórrala cuando quieras.

## Primeros pasos
1. Cambia la contraseña de **admin** (te la pide al entrar) y da de alta a tu equipo en **Opciones → Usuarios y grupos**.
2. Configura los avisos (correo, Telegram o un webhook de Slack, Teams o Discord) en **Opciones → Avisos** y pulsa «Enviar aviso de prueba».
3. Mete tus equipos en **Inventario**: uno a uno, **En serie** o con **Descubrir red**.
4. Vigila lo que no puede caerse en **Monitor**: ping, puertos, webs, certificados y DNS.
5. Lee temperaturas, discos, ventiladores y puertos de NAS y switches en **Salud** (por SNMP).
6. ¿Te pierdes? **Ajustes → Ver el tutorial** lo repite cuando quieras.

## Qué hace cada sección
- **Dashboard**: tu tablero. En «Personalizar» eliges las tarjetas, las arrastras y las agrandas.
- **Wiki**: procedimientos y documentación en Markdown, con editor visual. Enlaza un equipo con `[[#id]]`, una incidencia con `[[INC-n]]` (sale en su ficha, en «Enlazada desde») y otra página con `[[Nombre de la página]]`.
- **Inventario**: cada equipo con su IP, nº de serie, ubicación, estado, fin de garantía y notas. Filtra, exporta a CSV y, desde la ficha, copia la IP, haz ping o abre su web. Las garantías que caducan salen arriba y avisan 30 días antes; en **Caducidades**, lo mismo para licencias, dominios, certificados y contratos. Si un equipo envía su **syslog** a catlan (UDP 514), sale en su ficha.
- **Esquemas**: diagramas de red con iconos y conexiones. **Topología automática** lo dibuja solo leyendo LLDP, CDP y la tabla MAC de un switch.
- **Racks**: armarios montados U a U, con bocas de switch, patch panel y PDU.
- **Redes**: tus subredes con las IPs libres y en uso, y los conflictos: una IP en dos equipos del inventario o un equipo que responde sin estar en él.
- **Monitor**: comprueba cada pocos segundos lo que elijas y avisa en pantalla, con el sonido de cada dispositivo y por tus canales. Si cae un switch, avisa de él y no de todo lo que cuelga de él.
- **Salud**: SNMP v2c y v3 (Synology, QNAP, Cisco, HP, Ubiquiti, MikroTik…), grabadores Hikvision y los PCs con Kitty, con gráficos de hasta 90 días.
- **Incidencias**: tickets con prioridad, estado, persona o grupo asignado, seguimiento e incidencias hijas.
- **Actividad**: quién cambió qué y cuándo, con una foto de cada versión.
- **Opciones** (administradores): usuarios y grupos, avisos, Kitty, copia de seguridad, **Salud de catlan** (base de datos, copias diarias, estado del monitor) y la zona de peligro.

## Trucos
- **Alt+C** o **/** abre el buscador: busca en todo. Empieza por `W:` para la wiki, `U:` para equipos y `T:` para incidencias.
- **Silenciar** un dispositivo, o **Mantenimiento** para todos, evita avisos mientras trabajas.
- Si dos personas editan lo mismo, catlan avisa en vez de pisar los cambios del otro.
- ¿Contraseña olvidada? Un administrador te pone una nueva en Opciones → Usuarios. Si eres el único administrador, en el servidor: `catlan restablecer tu-usuario`.
- ¿Borraste algo sin querer? **Ctrl+Z** (o «Deshacer» en el aviso) en los 10 segundos siguientes; después, en Actividad sigue la foto de lo borrado.
- En el inventario, marca varios equipos para **cambiarles** la ubicación o el estado de una vez, o programarles un **mantenimiento** (también desde un rack: menú ⋯).
- Kitty en Windows y Linux: **Inventario → Añadir con Kitty** da una línea para pegar en PowerShell o en la terminal. En Windows deja un gato en la bandeja para que cada usuario avise a IT: sus avisos llegan como incidencias de su equipo.

## Tus datos: todo se queda en tu servidor
- catlan funciona entero en la máquina donde lo instalas, con una base de datos SQLite en `data/catlan.db`. Sin nube, sin cuentas externas, sin analítica, sin telemetría y sin publicidad.
- La web no carga nada de Internet: ni fuentes, ni scripts, ni imágenes de terceros.
- catlan solo se conecta a:
  - los equipos y direcciones que tú le pidas vigilar o leer (ping, puertos, webs, certificados, DNS, SNMP, Hikvision) y las redes que le pidas descubrir o escanear;
- catlan escucha syslog en UDP 514 (`CATLAN_SYSLOG_PORT`) y solo guarda lo que llega de IPs del inventario, 30 días.
  - los canales de aviso que configures: tu servidor de correo, la API de Telegram (`api.telegram.org`) si pones un bot, y tu webhook.
- Kitty solo envía nombre del equipo, sistema, modelo, CPU, memoria, discos, IPs, tiempo encendido, nº de serie y los errores y críticos del Visor de eventos o del journal de Linux (con las rutas de usuario tapadas), más los avisos que escriba el usuario en su ventana, y solo después de que un administrador lo acepte. Nada de usuarios, programas, archivos ni lo que se hace en el equipo.
- Las contraseñas de los usuarios se guardan con PBKDF2: no se pueden leer. Las de SNMP, correo y Telegram se guardan en la base de datos y nunca salen por la web. La copia de seguridad las incluye, por eso **va cifrada con la contraseña que elijas**: sin ella no se puede abrir.
- Verificación en dos pasos: menú de tu usuario → «Verificación en dos pasos», con cualquier app de autenticación.
- Lo que borras queda en Actividad hasta que borras la base de datos (Opciones → zona de peligro, con contraseña y copia previa).

## Qué no hace
- No es un antivirus ni un EDR: no vigila lo que hacen los usuarios ni controla los equipos a distancia.
- No hace copias de tus servidores: solo de su propia base de datos (**Opciones → Descargar copia de seguridad**).
- No envía nada a nadie que no hayas configurado tú.
- No necesita Internet para funcionar.
- HTTPS siempre: con tu certificado (`CATLAN_CERT` y `CATLAN_KEY`) o con uno autofirmado que catlan crea al arrancar; su huella está en Salud de catlan. Detrás de un proxy, pon su IP en `CATLAN_PROXIES`.
