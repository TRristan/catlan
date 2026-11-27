# Cambios

Cada versión, lo que cambia para quien usa catlan. Sigue [SemVer](https://semver.org/lang/es/): el primer número sube
cuando hay que hacer algo a mano al actualizar.

## Sin publicar

### Nuevo
- **Usuarios del dominio**: login con Active Directory (LDAPS, bind con el propio usuario) y con OIDC (Entra ID, Google
  Workspace, Keycloak) con PKCE. Sus grupos del dominio dan el admin y los grupos de catlan. Se configura en
  **Opciones → Inicio de sesión con el dominio**; los usuarios locales, `admin` incluido, siguen entrando siempre.

## 2.0.0

**Hay que reinstalar Kitty en los PCs** (el mismo comando de Inventario → Añadir con Kitty). Las Kitty de antes siguen
enviando el estado, pero sin control remoto ni actualizaciones hasta que se reinstalan.

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
- CI con `cargo fmt --check`, `cargo clippy -D warnings` y `cargo audit`.
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
