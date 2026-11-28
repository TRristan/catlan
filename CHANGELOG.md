# Cambios

Cada versión, lo que cambia para quien usa catlan. Sigue [SemVer](https://semver.org/lang/es/): el primer número sube
cuando hay que hacer algo a mano al actualizar.

## Sin publicar

### Nuevo
- **Copia de la configuración de switches y routers** (Cisco, HP/Aruba y MikroTik). En el equipo de Hardware, pon un
  usuario SSH en **Editar**: catlan guarda su configuración una vez al día y solo crea una versión nueva cuando algo
  cambia. En la tarjeta **Configuración** se ven las versiones, los cambios línea a línea y **Copiar ahora**. Si cambia,
  avisa por tus canales, pero solo de cuántas líneas cambiaron: el texto lleva contraseñas. La clave SSH del equipo se
  fija la primera vez, y si otro equipo se hace pasar por él, no se le manda la contraseña. Ver y descargar las copias
  es solo para administradores.

## 2.2.2

### Arreglado
- **Diálogos con casillas** (Nuevo aviso, Añadir usuarios…): cada casilla, de su tamaño y con su texto al lado; se
  estiraban a todo el ancho y el texto quedaba lejos.
- **Kitty, chat**: la conversación es un panel alineado con las pestañas, con aire alrededor.
- **Kitty, Este PC**: en «Red», el tiempo encendido, las IP y la dirección de catlan ya no se salen de la tarjeta; las
  direcciones van a todo el ancho y cada IPv6 cabe en una línea.

## 2.2.1

### Cambia
- **catlan.exe y kitty.exe tienen icono**: el gato de catlan y el de Kitty, en el Explorador, la barra de tareas y el
  Administrador de tareas. Los PCs reciben la Kitty nueva solos.

## 2.2.0

### Nuevo
- **Fotos de perfil.** En **Mi cuenta → Foto de perfil** cada uno sube la suya (se recorta a 256 px, sin datos de la
  cámara). Sale junto a lo que hace cada técnico en Actividad e historiales; lo que hace Kitty sale con su gato.
- **Imágenes en la wiki** y en las notas: botón de imagen, pegar o arrastrar (JPEG, PNG, GIF o WebP, hasta 8 MB).
- **El chat de Kitty parece un chat**: burbujas por persona, días, hora y caja de escribir abajo (Intro envía).
- **Tarjeta del equipo en las incidencias**: si está conectado, CPU, memoria, disco, sistema, IP, seguridad, parches y
  acceso a control remoto, ficha y estado.

### Arreglado
- Actividad decía «ejecutar» en vez de «ejecutó un script en», y no tenía verbo para encender un PC.

## 2.1.1

### Arreglado
- **La ventana de Kitty no se abría al iniciar sesión** (el gato no salía en la bandeja; abriéndola a mano, Edge decía
  que no podía escribir en su directorio de datos). WebView2 guardaba sus datos junto a `kitty.exe`, en Program Files,
  donde el usuario no puede escribir. Ahora van en `%LOCALAPPDATA%\Kitty`. Los PCs se actualizan solos.

## 2.1.0

### Nuevo
- **Inventario de programas.** Si lo activas en **PCs (Kitty) → Programas**, Kitty cuenta qué hay instalado en cada PC
  (nombre, versión y editor). Se ve en la ficha del PC y se busca con **Alt+C**: «anydesk» dice qué PCs lo tienen y con
  qué versión. Viene apagado y, al apagarlo, se borra lo recogido. Hace falta la Kitty nueva.
- **Parches y seguridad de los PCs.** Kitty cuenta el último parche, los pendientes y si espera un reinicio; un PC con
  más de 30 días sin parchear avisa. Un semáforo en cada PC resume antivirus, firewall, BitLocker y la cuenta
  Administrador de serie.
- **Avisos a los PCs** (PCs (Kitty) → Avisos): un mensaje en la ventana de Kitty de todos los PCs o de unos cuantos.
- **Conversación con el usuario del PC.** En una incidencia abierta desde Kitty, «Que la vea … en Kitty» manda la nota
  a su ventana, y el usuario contesta desde «Mis avisos».
- **Captura al avisar** y **autoayuda**: Kitty adjunta una captura si se pide y sugiere las páginas de la wiki marcadas
  con «Sugerir en Kitty».
- **Scripts de PowerShell** (PCs (Kitty) → Scripts, solo administradores) en uno o varios PCs, con la salida en la
  ficha del equipo.
- **Archivos en el control remoto**: enviar uno al PC o pedir uno, hasta 20 MB.
- **Encender un PC** desde su ficha (Wake-on-LAN).

### Cambia
- **Barra lateral por grupos** que se pliegan (y se recuerdan): Vigilancia, Servicio, Infraestructura, Conocimiento y
  Ajustes. Todo lo que tenía ruta propia tiene ahora su entrada o su pestaña: **Syslog** de todos los equipos,
  **Caducidades**, **Mis tareas**, **PCs (Kitty)** (con los que piden entrar y los programas) y
  **Monitor → Mantenimientos**, la lista de todo lo silenciado o programado.
- **Salud** se llama **Hardware** y solo lleva lo de SNMP; los PCs con Kitty van en **PCs (Kitty)**, con su propio aviso.
- **Opciones** pasa a ser **Administración** (General · Usuarios y grupos · Sistema); el cajón de Ajustes y el menú de la
  cuenta se juntan en **Mi cuenta**. Las direcciones de antes (`#/opts`, `#/cad`, `#/tablero`…) siguen funcionando.
- «Nuevo» sigue el orden de la barra y añade comprobación, equipo por SNMP, caducidad, red y PC con Kitty.

## 2.0.0

**Hay que reinstalar Kitty en los PCs** (el mismo comando de Inventario → Añadir con Kitty). Las Kitty de antes siguen
enviando el estado, pero sin control remoto ni actualizaciones hasta que se reinstalan.

### Nuevo
- **Usuarios del dominio**: login con Active Directory (LDAPS, bind con el propio usuario) y con OIDC (Entra ID, Google
  Workspace, Keycloak) con PKCE. Sus grupos del dominio dan el admin y los grupos de catlan. Se configura en
  **Opciones → Inicio de sesión con el dominio**; los usuarios locales, `admin` incluido, siguen entrando siempre.

### Por dentro
- **Servidor nuevo** (tokio + hyper + axum): las conexiones se reutilizan (keep-alive) y ya no hay un hilo por conexión.
  Lo de seguridad sigue igual: HTTPS y HTTP en el mismo puerto, lo que se sirve en claro, cabeceras, proxies de
  confianza, 503 y 64 conexiones por IP, y 10 s para mandar cada petición.
- **Control remoto por WebSocket**: la pantalla llega en cuanto cambia y el ratón y el teclado van al PC sin esperar al
  siguiente fotograma. Las Kitty de antes siguen funcionando por HTTP.
- **Salud se refresca sola** al llegar lecturas nuevas (como mucho cada 5 s), en vez de preguntar cada 15 s.
- Por dentro: las rutas de la API son tablas con el permiso de cada una, comprobado en un solo sitio y con una prueba
  por ruta.
- La web, partida en archivos HTML, CSS y JS en `src/ui/`; se sigue sirviendo como una sola página dentro del
  ejecutable.

### Seguridad
- **HTTPS siempre.** Sin `CATLAN_CERT`, catlan crea un certificado autofirmado en `data/tls.pem` y enseña su huella al
  arrancar y en Salud de catlan. En claro (HTTP) solo responde al propio equipo, a los proxies de `CATLAN_PROXIES` y a
  la telemetría de las Kitty antiguas; la web redirige a https.
- **Kitty anclado a catlan.** El comando de instalación lleva la huella del certificado: PowerShell, curl y Kitty solo
  hablan con ese. El instalador comprueba el SHA-256 de `kitty.exe` antes de ponerlo.
- **Control remoto, login y actualizaciones de Kitty, solo cifrados.**
- Cabeceras contra clickjacking (CSP con `frame-ancestors 'none'`, `X-Frame-Options`) y HSTS con certificado propio.
- Detrás de un proxy, la IP del cliente sale de `X-Forwarded-For` solo si el proxy está en `CATLAN_PROXIES`.
- Límite de intentos de login también por usuario, no solo por IP.
- Escrituras desde otra web bloqueadas también cuando el navegador no manda `Origin` (`Sec-Fetch-Site`).
- El syslog se marca «sin verificar» en la ficha: llega por UDP sin firma.
- En Docker, catlan corre como un usuario sin privilegios.

### Robustez
- Conexiones lentas (slowloris): 10 s para mandar la petición y 64 conexiones como mucho por IP. Si está lleno, responde
  503 y lo cuenta en Salud de catlan.
- Ping: sin el comando `ping` o sin permiso para ICMP, prueba por TCP en vez de dar el equipo por caído.
- El monitor se vuelve a arrancar solo si su hilo se para.
- **Cuánto se guarda**, en Opciones → Salud de catlan: días de pings y lecturas en bruto, de syslog y de resúmenes por hora.
- Prueba de carga (`tests/carga.py`): 3.000 Kitty cada 15 s sin errores (ver «Requisitos y límites» en el README).

### Desarrollo
- CI con `cargo fmt --check`, `cargo clippy -D warnings`, `cargo audit` y tests de la web en un navegador (Playwright).
- Rust 1.88 como mínimo.
- `SECURITY.md` con cómo avisar de fallos y el modelo de amenazas.

## 1.x

- **Programas en los PCs.** En **Opciones → Programas en los PCs** eliges programas por su id de winget (Chrome,
  7-Zip, Firefox…). Kitty los **instala** en todos los PCs y los **mantiene actualizados** cada hora. En cada programa
  ves en cuántos PCs está bien o ha fallado, y en la ficha de Salud de cada PC, cómo le fue.
- **Kitty se actualiza solo.** Cuando pones un `kitty.exe` nuevo junto a catlan, cada PC lo detecta en unos minutos, lo
  descarga, comprueba que llega entero (sha256) y se reemplaza. Ya no hace falta volver a pegar la línea de instalación.
- **catlan se actualiza solo** (opcional). En **Opciones → Salud de catlan → Actualizaciones**: buscar la versión nueva
  en GitHub, «Actualizar ahora» o activar «Actualizar solo» (una vez al día). Descarga, comprueba el sha256, se reemplaza
  y se reinicia. Si reparte `kitty.exe`, también lo actualiza, y con él a todos los PCs.
- **Control remoto con Kitty.** Desde la ficha del equipo o desde Salud, un técnico pide conectarse a un PC, y la
  persona que lo usa lo **acepta o lo rechaza** en su pantalla. El técnico ve la pantalla en el navegador y usa el ratón y el
  teclado. El PC no abre ningún puerto, porque todo pasa por catlan. El usuario puede cortar cuando quiera, y en el historial
  del equipo queda quién se conectó, cuándo y cuánto tiempo.
- **Kitty casi en directo.** Cada PC envía su estado **cada 15 segundos** y Salud se refresca sola cada 15 s. La
  ventana de Kitty comprueba la conexión cada 3 s y ya no dice «sin conexión» por un corte suelto.
- **Cerrar Kitty requiere un administrador.** «Salir de Kitty» pide usuario y contraseña de un **admin de catlan**,
  y el código de la verificación en dos pasos si la tiene. El cierre queda anotado en el historial.
- **Kitty como servicio.** `kitty servicio` se queda en marcha como SYSTEM desde que arranca el PC, aunque no haya nadie
  con la sesión iniciada. El gato de la bandeja se abre solo al iniciar sesión.
- **Mis tareas y notas.** En Incidencias, un tablero personal (solo lo ves tú) con columnas que se arrastran, junto a las
  incidencias de tus grupos.
- **Enlaces a incidencias en la wiki.** `[[INC-n]]` enlaza una incidencia, y en su ficha aparece en «Enlazada desde».
- **`catlan restablecer` más seguro.** Si no encuentra la base de datos, no crea una nueva y te dice cómo indicar la
  carpeta correcta.
- **Nuevo logo** de catlan y de Kitty, con kit de iconos y guía de uso en [`docs/logo/`](docs/logo/README.md).
