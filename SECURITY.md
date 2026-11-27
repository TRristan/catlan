# Seguridad

## Avisar de un fallo

catlan maneja contraseñas y control remoto de PCs: si encuentras un fallo de seguridad, **no abras una incidencia
pública**. Avísalo en privado desde la pestaña **Security → Report a vulnerability** de este repositorio en GitHub, con
la versión de catlan, qué has hecho y qué pasa. Respondo en cuanto pueda; cuando haya arreglo, sale en una versión nueva
y en el [CHANGELOG](CHANGELOG.md).

Solo se arregla la última versión publicada.

## Qué protege catlan y qué no

catlan está pensado para la **red local de una empresa pequeña**, con unos pocos técnicos que se conocen. Esto es lo que
da por hecho y lo que hace cada parte.

### Lo que protege

- **Conexiones.** Todo va por HTTPS. Sin certificado propio, catlan usa uno autofirmado y su huella va dentro del
  comando que instala Kitty: los PCs solo hablan con ese catlan, aunque alguien en la red se haga pasar por él. En
  claro solo responde al propio equipo, a los proxies que tú digas y a la telemetría de las Kitty de antes de la 2.0.
- **Kitty.** Cada PC tiene su clave, solo legible por SYSTEM y administradores. El instalador comprueba el SHA-256 de
  `kitty.exe`, y las actualizaciones de Kitty solo llegan por HTTPS y con el sha256 que anuncia catlan.
- **Control remoto.** Solo cifrado. La persona del PC tiene que aceptarlo, puede cortarlo cuando quiera, y queda en el
  historial quién se conectó y cuánto tiempo.
- **Usuarios.** Contraseñas con PBKDF2 (600.000 vueltas), verificación en dos pasos opcional, límite de intentos por IP
  y por usuario, cookie de sesión `HttpOnly` y `SameSite=Lax`, y escrituras desde otras webs bloqueadas (CSRF).
- **Navegador.** CSP sin código de fuera, sin meter catlan en marcos de otras webs (clickjacking) y HSTS con
  certificado propio.
- **Usuarios del dominio.** LDAP solo por LDAPS (certificado del sistema o anclado por su huella), nunca con contraseña
  vacía (sería un bind anónimo) y buscando al usuario por lo que dice el dominio («¿quién soy?»), no por lo que se
  escribió. OIDC con PKCE (S256), `state` en una cookie de este navegador (contra el login CSRF) y `nonce`; el id_token
  llega directo del proveedor por TLS y se comprueban emisor, destinatario, caducidad y nonce. Los motivos de un fallo
  van por código, no como texto en la dirección. Un usuario del dominio nunca toma un usuario local con el mismo nombre.
- **Secretos** (SNMP, SMTP, webhooks, el secreto del cliente OIDC): nunca salen por la API. La copia que se descarga de la web va cifrada.

### Lo que no protege

- **Syslog.** Llega por UDP sin firma. catlan solo acepta lo que viene de IPs del inventario, pero cualquiera en la red
  puede mandar mensajes con la IP de otro equipo. En la ficha sale «sin verificar».
- **SNMP v1/v2c.** La comunidad viaja en claro: usa v3 cuando el equipo lo permita.
- **Un administrador de catlan** lo puede todo, incluido conectarse a cualquier PC con Kitty (con permiso de su usuario)
  e instalar programas en todos. Da ese rol a pocas personas y con verificación en dos pasos.
- **El dominio.** Quien administra el AD o el proveedor OIDC decide quién entra y quién es admin en catlan (con los
  grupos que pongas en Opciones). La firma del id_token no se comprueba: confía en el TLS con el proveedor, como permite
  OIDC para el flujo de código.
- **Quien sale de la empresa** sigue dentro hasta que caduca su sesión (12 horas) o un administrador lo borra; por Basic,
  hasta 10 minutos.
- **Un administrador del PC** puede leer la clave de Kitty y hacerse pasar por ese equipo ante catlan (no por otros).
- **Kitty instalados antes de la 2.0**: siguen enviando el estado por HTTP en claro, sin anclaje. Reinstálalos.
- **La primera vez** que pulsas «Conectar este PC» en un Kitty descargado, este se fía de quien conteste en la red
  (como SSH la primera vez). El comando copiado de la web no tiene ese problema: lleva la huella dentro.
- **El servidor de catlan.** Quien entre en la máquina o en `data/` tiene la base de datos, la clave del certificado y
  las copias diarias.

### Lo que tiene que hacer quien lo instala

1. Cambiar la contraseña de `admin` al entrar la primera vez y activar la verificación en dos pasos.
2. Comprobar que la huella del certificado que enseña el navegador es la que escribe catlan al arrancar (y en
   **Opciones → Salud de catlan**).
3. Si catlan sale de la red local, ponerlo detrás de un proxy con un certificado de verdad, con su IP en
   `CATLAN_PROXIES`, o darle uno propio con `CATLAN_CERT` y `CATLAN_KEY`.
4. Proteger la carpeta `data/` y sus copias como cualquier otra base de datos con contraseñas.
5. Reinstalar Kitty en los PCs que lo tenían de antes de la 2.0.
6. Con usuarios del dominio: dar acceso solo a grupos concretos (no a «Usuarios del dominio») y mantener `admin` local
   con contraseña larga y verificación en dos pasos para cuando el dominio no conteste.
