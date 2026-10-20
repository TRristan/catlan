#!/usr/bin/env python3
"""catlan: el gato amigo de los IT. Wiki + inventario + esquemas + racks + monitor. Solo stdlib de Python."""
import base64, hashlib, hmac, json, os, random, re, secrets, smtplib, socket, sqlite3, ssl, subprocess, threading, time, urllib.error, urllib.request
from datetime import datetime, timezone
import ipaddress
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from http.cookies import SimpleCookie
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse, parse_qs

VERSION = "1.0"
HERE = Path(__file__).parent
DATA = Path(os.environ.get("CATLAN_DATA", HERE / "data"))
PORT = int(os.environ.get("CATLAN_PORT", "8080"))
PASSWORD = os.environ.get("CATLAN_PASSWORD", "")  # contraseña del usuario admin inicial; vacío = «admin», a cambiar al entrar
MAX_BODY = 20 * 1024 * 1024
IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp", "image/svg+xml"}
AUDIO_TYPES = {"audio/mpeg", "audio/wav", "audio/x-wav", "audio/wave", "audio/ogg", "audio/webm", "audio/mp4", "audio/aac", "audio/x-m4a"}
HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.:\-]{0,252}")  # sin espacios ni guion inicial: no se cuela como opción de ping
# Correo: por variables de entorno, así la contraseña no vive en la base de datos ni pasa por la web
SMTP = {k: os.environ.get("CATLAN_" + k, "") for k in ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "MAIL_FROM", "MAIL_TO")}
HOOKS = {k: os.environ.get("CATLAN_" + k, "") for k in ("TELEGRAM_TOKEN", "TELEGRAM_CHAT", "WEBHOOK_URL")}  # igual que el correo
RACK_TYPES = {"server", "switch", "patch", "router", "firewall", "nas", "ups", "pdu", "kvm", "tray", "blank", "other"}

# Columnas editables por tabla: whitelist contra inyección SQL
TABLES = {
    "pages": ["title", "body"],
    "items": ["name", "kind", "ip", "serial", "location", "status", "notes", "warranty"],
    "checks": ["host", "label", "item", "every", "kind", "port", "url", "expect", "warn_days", "sound"],
    "sources": ["host", "label", "item", "kind", "community", "port", "user", "pass", "every", "temp_max", "disk_max",
                "v3", "auth", "priv", "priv_pass"],
}
SECRET = ("community", "pass", "priv_pass")  # nunca salen por la API ni al historial
AGENT_FACTS = ("name", "ip", "serial", "os", "kind")  # lo que Kitty cuenta de su equipo

DATA.mkdir(parents=True, exist_ok=True)
db = sqlite3.connect(DATA / "catlan.db", check_same_thread=False)
db.row_factory = sqlite3.Row
lock = threading.Lock()


def backup_to(path):
    """Copia completa y consistente de la BD a path."""
    bak = sqlite3.connect(path)
    try:
        db.backup(bak)
    finally:
        bak.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS pages(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL DEFAULT '', body TEXT NOT NULL DEFAULT '',
  updated TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL DEFAULT '', kind TEXT DEFAULT '', ip TEXT DEFAULT '',
  serial TEXT DEFAULT '', location TEXT DEFAULT '', status TEXT DEFAULT '', notes TEXT DEFAULT '',
  updated TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS maps(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, mime TEXT NOT NULL, image BLOB NOT NULL,
  data TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS log(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT DEFAULT CURRENT_TIMESTAMP, who TEXT, action TEXT,
  kind TEXT, ref INTEGER, name TEXT, data TEXT);
CREATE INDEX IF NOT EXISTS log_ref ON log(kind, ref);
CREATE TABLE IF NOT EXISTS checks(id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL DEFAULT '', label TEXT DEFAULT '', item INTEGER,
  every INTEGER DEFAULT 30, state TEXT, fails INTEGER DEFAULT 0, rtt REAL, last TEXT, since TEXT, updated TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS pings(check_id INTEGER, ts TEXT DEFAULT CURRENT_TIMESTAMP, up INTEGER, rtt REAL);
CREATE INDEX IF NOT EXISTS pings_c ON pings(check_id, ts);
CREATE TABLE IF NOT EXISTS sounds(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, mime TEXT NOT NULL, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sources(id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL DEFAULT '', label TEXT DEFAULT '', item INTEGER,
  kind TEXT DEFAULT 'generic', community TEXT DEFAULT 'public', port INTEGER DEFAULT 161, user TEXT DEFAULT '', pass TEXT DEFAULT '',
  every INTEGER DEFAULT 300, temp_max REAL DEFAULT 65, disk_max REAL DEFAULT 90,
  v3 INTEGER DEFAULT 0, auth TEXT DEFAULT 'sha', priv TEXT DEFAULT 'aes', priv_pass TEXT DEFAULT '',
  state TEXT, problems TEXT, error TEXT, info TEXT, last TEXT, since TEXT, updated TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS metrics(source_id INTEGER, ts TEXT DEFAULT CURRENT_TIMESTAMP, key TEXT, label TEXT, value REAL, unit TEXT);
CREATE INDEX IF NOT EXISTS metrics_s ON metrics(source_id, ts);
CREATE TABLE IF NOT EXISTS pings_h(check_id INTEGER, hour TEXT, n INTEGER, up INTEGER, rtt REAL, rtt_min REAL, rtt_max REAL,
  PRIMARY KEY(check_id, hour));
CREATE TABLE IF NOT EXISTS metrics_h(source_id INTEGER, key TEXT, hour TEXT, label TEXT, unit TEXT, v REAL, v_min REAL, v_max REAL,
  PRIMARY KEY(source_id, key, hour));
CREATE TABLE IF NOT EXISTS dash(id INTEGER PRIMARY KEY CHECK(id = 1), data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE, hash TEXT NOT NULL,
  admin INTEGER DEFAULT 0, must_change INTEGER DEFAULT 0, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS groups(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE, role TEXT NOT NULL DEFAULT 'edit');
CREATE TABLE IF NOT EXISTS members(group_id INTEGER NOT NULL, user_id INTEGER NOT NULL, PRIMARY KEY(group_id, user_id));
CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT DEFAULT '', status TEXT DEFAULT 'abierta',
  priority TEXT DEFAULT 'media', assignee INTEGER, grp INTEGER, item INTEGER, author INTEGER,
  created TEXT DEFAULT CURRENT_TIMESTAMP, updated TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY AUTOINCREMENT, incident INTEGER NOT NULL, who TEXT, ts TEXT DEFAULT CURRENT_TIMESTAMP,
  text TEXT NOT NULL, change INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS agents(id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL UNIQUE /*sha256 de la clave de Kitty*/, name TEXT, ip TEXT,
  serial TEXT, os TEXT, kind TEXT, state TEXT NOT NULL DEFAULT 'pendiente', item INTEGER, seen TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
"""
db.executescript(SCHEMA)
KIND = {"pages": "page", "items": "item", "checks": "check", "sources": "source"}
try:  # BDs creadas antes del montador de esquemas
    db.execute("ALTER TABLE maps ADD COLUMN data TEXT NOT NULL DEFAULT '{}'")
except sqlite3.OperationalError:
    pass
for col in ("sources v3 INTEGER DEFAULT 0", "sources auth TEXT DEFAULT 'sha'", "sources priv TEXT DEFAULT 'aes'", "sources priv_pass TEXT DEFAULT ''",
            "sources alerted TEXT", "sources mute_until TEXT", "checks kind TEXT DEFAULT 'ping'", "checks port INTEGER", "checks url TEXT DEFAULT ''",
            "checks expect TEXT DEFAULT ''", "checks warn_days INTEGER DEFAULT 30", "checks detail TEXT", "checks alerted TEXT", "checks mute_until TEXT",
            "incidents parent INTEGER", "agents source INTEGER", "items warranty TEXT DEFAULT ''", "checks sound TEXT DEFAULT ''"):
    try:  # BDs creadas antes de SNMPv3, de las comprobaciones TCP/HTTP/SSL/DNS y del silencio
        db.execute("ALTER TABLE %s ADD COLUMN %s" % tuple(col.split(" ", 1)))
    except sqlite3.OperationalError:
        pass
# Ids que nunca se reutilizan. Sin AUTOINCREMENT, SQLite da a lo nuevo el id del último borrado, y lo nuevo heredaba
# su historial en Actividad y sus enlaces ([[#id]], esquemas, racks, incidencias). Las BDs de antes se reconstruyen una vez.
LOG_KINDS = {"pages": ("page",), "items": ("item",), "maps": ("map", "rack"), "checks": ("check",), "sources": ("source",),
             "users": ("user",), "groups": ("group",), "incidents": ("incident",), "agents": ("agent",)}
old_ids = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND sql LIKE '%(id INTEGER PRIMARY KEY,%'")]
if old_ids:
    backup_to(DATA / f"catlan-antes-de-ids-{time.strftime('%Y%m%d-%H%M%S')}.db")  # copia completa antes de tocar nada
    db.execute("BEGIN")
    try:
        for t in old_ids:
            sql = db.execute("SELECT sql FROM sqlite_master WHERE name=?", [t]).fetchone()[0]
            db.execute(re.sub(r'^CREATE TABLE (?:IF NOT EXISTS )?"?\w+"?', f"CREATE TABLE {t}_new", sql)
                       .replace("(id INTEGER PRIMARY KEY,", "(id INTEGER PRIMARY KEY AUTOINCREMENT,", 1))
            db.execute(f"INSERT INTO {t}_new SELECT * FROM {t}")
            db.execute(f"DROP TABLE {t}")
            db.execute(f"ALTER TABLE {t}_new RENAME TO {t}")
        for t in old_ids:  # el contador empieza por encima de lo que se ve en Actividad: tampoco vuelven los ids ya borrados
            kinds = LOG_KINDS.get(t, ())
            top = db.execute(f"SELECT MAX(x) FROM (SELECT MAX(id) AS x FROM {t} UNION ALL "
                             f"SELECT MAX(ref) FROM log WHERE kind IN ({','.join('?' * len(kinds)) or 'NULL'}))", kinds).fetchone()[0] or 0
            db.execute("DELETE FROM sqlite_sequence WHERE name=?", [t])
            db.execute("INSERT INTO sqlite_sequence(name, seq) VALUES(?, ?)", [t, top])
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    db.executescript(SCHEMA)  # los índices se fueron con las tablas viejas
    print("ids sin reutilizar: tablas reconstruidas (copia en", DATA, ")")


DASH_OPTS = {"kind": ("stat", "inv", "mon", "lat", "health", "log", "map"), "view": ("line", "bar", "pie"),
             "by": ("kind", "status", "location"), "group": ("temp", "disk", "load", "fan", "net"),
             "stat": ("items", "pages", "maps", "racks", "down", "warn"), "hours": (6, 24, 168, 720, 2160)}
DASH_INTS = {"x": (0, 11), "y": (0, 500), "w": (1, 12), "h": (1, 8), "source": (1, 2 ** 31), "map": (1, 2 ** 31)}


def check_dash(d):
    """El frontal pinta estos campos: solo tipos conocidos y posiciones enteras dentro de la rejilla de 12 columnas."""
    ws = d.get("widgets") if isinstance(d, dict) and set(d) <= {"widgets"} else None
    if not isinstance(ws, list) or len(ws) > 60:
        raise ValueError("dashboard no válido")
    ids = set()
    for w in ws:
        if not isinstance(w, dict) or not re.fullmatch(r"[a-z0-9]{1,20}", str(w.get("id", ""))) or w["id"] in ids:
            raise ValueError("widget sin id válido")
        ids.add(w["id"])
        for k, v in w.items():
            ok = (k == "id" or k == "title" and isinstance(v, str) and len(v) <= 80
                  or k in DASH_INTS and type(v) is int and DASH_INTS[k][0] <= v <= DASH_INTS[k][1]
                  or k in DASH_OPTS and type(v) in (str, int) and v in DASH_OPTS[k])
            if not ok:
                raise ValueError(f"widget {w['id']}: {k} no válido")
        if "kind" not in w or any(k not in w for k in "xywh") or w["x"] + w["w"] > 12:
            raise ValueError(f"widget {w['id']}: fuera de la rejilla")


class Rows(list):
    """Las filas de una consulta, ya leídas. lastrowid y rowcount como en el cursor."""
    lastrowid = rowcount = None

    def fetchone(self):
        return self[0] if self else None

    def fetchall(self):
        return list(self)


def q(sql, args=()):
    # Todo dentro del candado: con un cursor leído fuera, otro hilo puede vaciarlo (salían 401 sueltos con sesión válida)
    with lock:
        cur = db.execute(sql, args)
        out = Rows(cur.fetchall())
        out.lastrowid, out.rowcount = cur.lastrowid, cur.rowcount
        db.commit()
        return out


# ── Usuarios: contraseñas con PBKDF2 (stdlib) y sesiones por cookie ──
def pw_hash(pw, salt=None):
    salt = salt or os.urandom(16)
    return f"pbkdf2${salt.hex()}${hashlib.pbkdf2_hmac('sha256', pw.encode(), salt, 600_000).hex()}"


def pw_ok(pw, stored):
    return hmac.compare_digest(pw_hash(pw, bytes.fromhex(stored.split("$")[1])), stored)


def check_pass(pw):
    if not (isinstance(pw, str) and 8 <= len(pw) <= 200):
        raise ValueError("la contraseña necesita al menos 8 caracteres")


_basic = {}  # (nombre, sha256 de la contraseña) -> id: con Basic no se repite PBKDF2 en cada petición


def login_ok(name, pw):
    key = (name.lower(), hashlib.sha256(pw.encode()).hexdigest())
    if key not in _basic:
        u = q("SELECT id, hash FROM users WHERE name=?", [name]).fetchone()
        if not (u and pw_ok(pw, u["hash"])):
            return None
        _basic[key] = u["id"]
    return _basic[key]


FAILS = {}  # ip -> horas de los fallos de login recientes
# Lo que se vacía al «Borrar la base de datos»: todo el contenido. Quedan los usuarios, los grupos, las sesiones y el id
# de la instalación (los Kitty instalados vuelven a pedir entrar aquí).
WIPE = ("pages", "items", "maps", "log", "checks", "pings", "pings_h", "sounds", "sources", "metrics", "metrics_h", "dash",
        "incidents", "notes", "agents")


def throttled(ip):
    FAILS[ip] = [t for t in FAILS.get(ip, []) if t > time.time() - 900]
    return len(FAILS[ip]) >= 10  # 10 fallos en 15 minutos: esa IP espera


def readonly(uid):
    """Solo vista: está en algún grupo de solo vista y en ninguno que pueda editar (los administradores siempre editan)."""
    r = q("SELECT u.admin, max(g.role = 'edit') AS e, max(g.role = 'view') AS v FROM users u LEFT JOIN members m ON m.user_id = u.id "
          "LEFT JOIN groups g ON g.id = m.group_id WHERE u.id=?", [uid]).fetchone()
    return bool(not r["admin"] and r["v"] and not r["e"])


def me(uid):
    return {**dict(q("SELECT id, name, admin, must_change FROM users WHERE id=?", [uid]).fetchone()), "readonly": readonly(uid),
            "groups": [r[0] for r in q("SELECT group_id FROM members WHERE user_id=?", [uid])]}


sha = lambda t: hashlib.sha256(t.encode()).hexdigest()  # en la BD solo el hash del token: robarla no da sesiones
# Una cookie por instalación: el navegador no separa cookies por puerto, y dos catlan en la misma máquina se cerraban la sesión
COOKIE = "catlan_" + sha(str(DATA.resolve()))[:10]
# Id de esta instalación (va en la BD, así sobrevive a copias y cambios de IP): un Kitty aceptado solo habla con ella
q("INSERT OR IGNORE INTO meta(k, v) VALUES('instance', ?)", [secrets.token_hex(16)])
INSTANCE = q("SELECT v FROM meta WHERE k='instance'").fetchone()[0]
ALERT_KEYS = ("SMTP_HOST", "SMTP_PORT", "SMTP_USER", "SMTP_PASS", "MAIL_FROM", "MAIL_TO", "TELEGRAM_TOKEN", "TELEGRAM_CHAT", "WEBHOOK_URL")
ALERT_SECRET = ("SMTP_PASS", "TELEGRAM_TOKEN", "WEBHOOK_URL")  # nunca salen por la API (la URL de un webhook es una llave)
ENV_ALERTS = {**SMTP, **HOOKS}  # lo que vino de variables de entorno al arrancar


def saved_alerts():
    return json.loads((q("SELECT v FROM meta WHERE k='alerts'").fetchone() or ["{}"])[0])


def apply_alerts():
    """Lo guardado en catlan manda; lo que no, sale de las variables de entorno. Todo el envío lee SMTP y HOOKS."""
    saved = saved_alerts()
    for k in ALERT_KEYS:
        (SMTP if k in SMTP else HOOKS)[k] = saved.get(k) or ENV_ALERTS[k]


def alerts_view():
    cfg, saved = {**SMTP, **HOOKS}, saved_alerts()
    return {**{k: cfg[k] for k in ALERT_KEYS if k not in ALERT_SECRET}, "set": {k: bool(cfg[k]) for k in ALERT_SECRET},
            "webhook_host": urlparse(cfg["WEBHOOK_URL"]).netloc if cfg["WEBHOOK_URL"] else "",
            "env": [k for k in ALERT_KEYS if ENV_ALERTS[k] and not saved.get(k)], "channels": channels()}


def check_alert(k, v):
    ok = {"SMTP_HOST": lambda: HOST.fullmatch(v), "SMTP_PORT": lambda: v.isdigit() and 1 <= int(v) <= 65535,
          "MAIL_FROM": lambda: re.fullmatch(r"[^@\s,]+@[^@\s,]+", v), "MAIL_TO": lambda: re.fullmatch(r"[^@\s,]+@[^@\s,]+(\s*,\s*[^@\s,]+@[^@\s,]+)*", v),
          "TELEGRAM_CHAT": lambda: re.fullmatch(r"-?\d{1,20}|@\w{4,64}", v), "WEBHOOK_URL": lambda: re.fullmatch(r"https?://[^\s/]+\S{0,500}", v),
          "TELEGRAM_TOKEN": lambda: re.fullmatch(r"\d{3,20}:[\w-]{20,100}", v)}.get(k, lambda: True)
    if not ok():
        raise ValueError({"SMTP_HOST": "servidor de correo no válido", "SMTP_PORT": "puerto del correo no válido", "MAIL_FROM": "remitente no válido",
                          "MAIL_TO": "destinatarios no válidos (separa varios con comas)", "TELEGRAM_CHAT": "chat de Telegram: un número o @canal",
                          "WEBHOOK_URL": "el webhook empieza por http:// o https://", "TELEGRAM_TOKEN": "token de Telegram no válido (123456:ABC…)"}[k])


apply_alerts()
# La primera página de la wiki en una instalación nueva: cómo se usa catlan y qué hace con los datos
GUIDE = """*catlan es la web de sistemas e inventario de tu equipo de IT: wiki, inventario, esquemas, racks, monitor, salud, incidencias y dashboard, todo enlazado entre sí.* Esta página la creó catlan al instalarse: es tuya, edítala o bórrala cuando quieras.

## Primeros pasos
1. Cambia la contraseña de **admin** (te la pide al entrar) y da de alta a tu equipo en **Opciones → Usuarios y grupos**.
2. Configura los avisos (correo, Telegram o un webhook de Slack, Teams o Discord) en **Opciones → Avisos** y pulsa «Enviar aviso de prueba».
3. Mete tus equipos en **Inventario**: uno a uno, **En serie** o con **Descubrir red**.
4. Vigila lo que no puede caerse en **Monitor**: ping, puertos, webs, certificados y DNS.
5. Lee temperaturas, discos, ventiladores y puertos de NAS y switches en **Salud** (por SNMP).
6. ¿Te pierdes? **Ajustes → Ver el tutorial** lo repite cuando quieras.

## Qué hace cada sección
- **Dashboard**: tu tablero. En «Personalizar» eliges las tarjetas, las arrastras y las agrandas.
- **Wiki**: procedimientos y documentación en Markdown, con editor visual. Enlaza un equipo con `[[#id]]` y otra página con `[[Nombre de la página]]`.
- **Inventario**: cada equipo con su IP, nº de serie, ubicación, estado, fin de garantía y notas. Filtra, exporta a CSV y, desde la ficha, copia la IP, haz ping o abre su web. Las garantías que caducan salen arriba y avisan 30 días antes.
- **Esquemas**: diagramas de red con iconos y conexiones. **Topología automática** lo dibuja solo leyendo LLDP, CDP y la tabla MAC de un switch.
- **Racks**: armarios montados U a U, con bocas de switch, patch panel y PDU.
- **Monitor**: comprueba cada pocos segundos lo que elijas y avisa en pantalla, con el sonido de cada dispositivo y por tus canales. Si cae un switch, avisa de él y no de todo lo que cuelga de él.
- **Salud**: SNMP v2c y v3 (Synology, QNAP, Cisco, HP, Ubiquiti, MikroTik…), grabadores Hikvision y los PCs con Kitty, con gráficos de hasta 90 días.
- **Incidencias**: tickets con prioridad, estado, persona o grupo asignado, seguimiento e incidencias hijas.
- **Actividad**: quién cambió qué y cuándo, con una foto de cada versión.
- **Opciones** (administradores): usuarios y grupos, avisos, Kitty, copia de seguridad y la zona de peligro.

## Trucos
- **Alt+C** o **/** abre el buscador: busca en todo. Empieza por `W:` para la wiki, `U:` para equipos y `T:` para incidencias.
- **Silenciar** un dispositivo, o **Mantenimiento** para todos, evita avisos mientras trabajas.
- Si dos personas editan lo mismo, catlan avisa en vez de pisar los cambios del otro.
- Kitty en PCs Windows: **Inventario → Añadir PC** da una línea para pegar en PowerShell. No instala programas.

## Tus datos: todo se queda en tu servidor
- catlan funciona entero en la máquina donde lo instalas, con una base de datos SQLite en `data/catlan.db`. Sin nube, sin cuentas externas, sin analítica, sin telemetría y sin publicidad.
- La web no carga nada de Internet: ni fuentes, ni scripts, ni imágenes de terceros.
- catlan solo se conecta a:
  - los equipos y direcciones que tú le pidas vigilar o leer (ping, puertos, webs, certificados, DNS, SNMP, Hikvision) y las redes que le pidas descubrir;
  - los canales de aviso que configures: tu servidor de correo, la API de Telegram (`api.telegram.org`) si pones un bot, y tu webhook.
- Kitty solo envía nombre del equipo, sistema, modelo, CPU, memoria, discos, IPs, tiempo encendido y nº de serie, y solo después de que un administrador lo acepte. Nada de usuarios, programas, archivos ni lo que se hace en el equipo.
- Las contraseñas de los usuarios se guardan con PBKDF2: no se pueden leer. Las de SNMP, correo y Telegram se guardan en la base de datos y nunca salen por la web. Ojo: **la copia de seguridad las incluye**, guárdala como algo sensible.
- Lo que borras queda en Actividad hasta que borras la base de datos (Opciones → zona de peligro, con contraseña y copia previa).

## Qué no hace
- No es un antivirus ni un EDR: no vigila lo que hacen los usuarios ni controla los equipos a distancia.
- No hace copias de tus servidores: solo de su propia base de datos (**Opciones → Descargar copia de seguridad**).
- No envía nada a nadie que no hayas configurado tú.
- No necesita Internet para funcionar.
- No trae HTTPS propio: si catlan sale de tu red local, ponlo detrás de un proxy con HTTPS (Caddy, nginx, Traefik).
"""
if not q("SELECT 1 FROM users").fetchone():  # primera vez: admin / admin (o CATLAN_PASSWORD), a cambiar en el primer login
    q("INSERT INTO users(name, hash, admin, must_change) VALUES('admin', ?, 1, ?)", [pw_hash(PASSWORD or "admin"), 0 if PASSWORD else 1])
    print("Usuario inicial: admin / " + ("CATLAN_PASSWORD" if PASSWORD else "admin (se pide cambiarla al entrar)"))
    q("INSERT INTO pages(title, body) VALUES(?, ?)", ["Guía de catlan", GUIDE])  # instalación nueva: guía de uso y de datos en la wiki


def check_rack(d):
    """El frontal pinta estos campos tal cual: solo se aceptan tipos conocidos y números enteros."""
    devs, h = d.get("devices", []), d.get("height", 42)
    ok = isinstance(h, int) and 1 <= h <= 60 and isinstance(devs, list) and all(
        isinstance(x, dict) and x.get("t") in RACK_TYPES
        and all(isinstance(x.get(k), int) for k in ("u", "h"))
        and all(isinstance(x.get(k, 0), int) for k in ("ports", "sfp")) for x in devs)
    if not ok:
        raise ValueError("datos de rack no válidos")


def check_host(d, new=False):
    if (new or "host" in d) and not (isinstance(d.get("host"), str) and HOST.fullmatch(d["host"])):
        raise ValueError("host no válido: usa una IP o un nombre (p. ej. 10.0.0.1 o sw-core.local)")
    if "every" in d and not (isinstance(d["every"], int) and 10 <= d["every"] <= 3600):
        raise ValueError("el intervalo va de 10 a 3600 segundos")
    k = d.get("kind", "ping")
    if k not in CHECK_KINDS:
        raise ValueError("tipo de comprobación desconocido")
    if d.get("port") is not None and not (type(d["port"]) is int and 1 <= d["port"] <= 65535):
        raise ValueError("puerto no válido")
    if d.get("url") and not (isinstance(d["url"], str) and re.fullmatch(r"https?://[^\s/]+\S{0,500}", d["url"])):
        raise ValueError("la URL empieza por http:// o https://")
    if "expect" in d and not (isinstance(d["expect"], str) and len(d["expect"]) <= 200):
        raise ValueError("texto esperado demasiado largo")
    if "warn_days" in d and not (type(d["warn_days"]) is int and 1 <= d["warn_days"] <= 365):
        raise ValueError("avisar de 1 a 365 días antes")
    if "kind" in d and (k == "tcp" and not d.get("port") or k == "http" and not d.get("url")):
        raise ValueError("falta el puerto" if k == "tcp" else "falta la URL")
    # sonido al caer: "" = el general de cada navegador, "none" = ninguno, uno de los de catlan o uno subido (u:id)
    if "sound" in d and not (isinstance(d["sound"], str) and re.fullmatch(r"|none|bell|beep|siren|meow|u:\d{1,9}", d["sound"])):
        raise ValueError("sonido no válido")


def ping(host):
    """Un ping con el ping del sistema. Devuelve (responde, ms)."""
    win = os.name == "nt"
    cmd = ["ping", "-n" if win else "-c", "1", "-w" if win else "-W", "1000" if win else "1", host]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, errors="replace", timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return False, None
    m = re.search(r"(?:time|tiempo)\s*[=<]\s*([\d.,]+)", r.stdout, re.I)  # Windows en español: «tiempo=3ms»
    # Windows da código 0 también con «host inaccesible»: hace falta TTL o un tiempo (IPv6 no muestra TTL)
    up = r.returncode == 0 and bool(m or "ttl=" in r.stdout.lower())
    return up, (float(m.group(1).replace(",", ".")) if up and m else None)


CHECK_KINDS = ("ping", "tcp", "http", "ssl", "dns")


def _ms(t0):
    return round((time.perf_counter() - t0) * 1000, 1)


def _why(e):
    """Motivo corto de un fallo de red, para el aviso."""
    if isinstance(e, urllib.error.URLError) and isinstance(e.reason, Exception):
        return _why(e.reason)
    if isinstance(e, socket.gaierror):
        return "el nombre no resuelve"
    if isinstance(e, TimeoutError):
        return "no contesta (tiempo agotado)"
    if isinstance(e, ConnectionRefusedError):
        return "rechaza la conexión"
    if isinstance(e, ssl.SSLCertVerificationError):
        return f"certificado no válido: {e.verify_message}"
    return str(getattr(e, "reason", "") or e) or e.__class__.__name__


def probe_tcp(host, port):
    t0 = time.perf_counter()
    try:
        socket.create_connection((host, port), timeout=3).close()
    except OSError as e:
        return False, None, f"puerto {port}: {_why(e)}"
    return True, _ms(t0), f"puerto {port} abierto"


def probe_http(url, expect=""):
    t0 = time.perf_counter()
    try:  # verifica el certificado: una web con HTTPS roto es una web caída
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "catlan"}), timeout=8) as r:
            code, body = r.status, r.read(2_000_000)
    except urllib.error.HTTPError as e:
        code, body = e.code, b""
        e.close()
    except (OSError, ValueError) as e:
        return False, None, _why(e)
    ms = _ms(t0)
    if code >= 400:
        return False, ms, f"HTTP {code}"
    if expect and expect.encode() not in body:
        return False, ms, f"HTTP {code}, pero sin «{expect}»"
    return True, ms, f"HTTP {code}"


def cert_expiry(der):
    """Fin de validez (notAfter) de un certificado X.509, con el mismo lector BER que SNMP."""
    _, cert, _ = ber_read(der, 0)
    _, tbs, _ = ber_read(cert, 0)
    tag, _, i = ber_read(tbs, 0)
    i = i if tag == 0xA0 else 0  # [0] versión: falta en certificados v1
    for _ in range(3):  # número de serie, algoritmo, emisor
        _, _, i = ber_read(tbs, i)
    _, validity, _ = ber_read(tbs, i)
    _, _, j = ber_read(validity, 0)
    tag, t, _ = ber_read(validity, j)
    fmt = "%y%m%d%H%M%SZ" if tag == 0x17 else "%Y%m%d%H%M%SZ"  # UTCTime o GeneralizedTime
    return datetime.strptime(t.decode(), fmt).replace(tzinfo=timezone.utc).timestamp()


def probe_ssl(host, port, days):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE  # aquí solo importa la caducidad: también la de los autofirmados
    t0 = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=5) as raw, ctx.wrap_socket(raw, server_hostname=host) as t:
            der = t.getpeercert(binary_form=True)
    except OSError as e:
        return False, None, _why(e)
    ms, left = _ms(t0), (cert_expiry(der) - time.time()) / 86400
    if left < 0:
        return False, ms, f"certificado caducado hace {int(-left) + 1} días"
    return left > days, ms, f"certificado caduca en {int(left)} días"


def probe_dns(name, expect=""):
    t0 = time.perf_counter()
    try:
        ips = sorted({a[4][0] for a in socket.getaddrinfo(name, None)})
    except OSError as e:
        return False, None, _why(e)
    if expect and expect not in ips:
        return False, _ms(t0), f"resuelve a {', '.join(ips[:3])}, no a {expect}"
    return True, _ms(t0), "resuelve a " + ", ".join(ips[:3])


def run_check(c):
    """Una comprobación de cualquier tipo. Devuelve (va bien, ms, detalle)."""
    k = c.get("kind") or "ping"
    try:
        if k == "tcp":
            return probe_tcp(c["host"], c["port"])
        if k == "http":
            return probe_http(c["url"], c.get("expect") or "")
        if k == "ssl":
            return probe_ssl(c["host"], c.get("port") or 443, c.get("warn_days") or 30)
        if k == "dns":
            return probe_dns(c["host"], c.get("expect") or "")
        up, rtt = ping(c["host"])
        return up, rtt, "" if up else "no responde al ping"
    except Exception as e:  # un certificado raro no debe tumbar el monitor
        return False, None, (str(e) or e.__class__.__name__)[:200]


def mail(subject, text):
    """Envía un aviso a CATLAN_MAIL_TO. False si el correo no está configurado."""
    if not (SMTP["SMTP_HOST"] and SMTP["MAIL_TO"]):
        return False
    msg = EmailMessage()
    msg["Subject"], msg["To"] = subject, SMTP["MAIL_TO"]
    msg["From"] = SMTP["MAIL_FROM"] or SMTP["SMTP_USER"] or "catlan@localhost"
    msg.set_content(text)
    port = int(SMTP["SMTP_PORT"] or 587)
    with (smtplib.SMTP_SSL if port == 465 else smtplib.SMTP)(SMTP["SMTP_HOST"], port, timeout=15) as srv:
        if port != 465:
            srv.ehlo()
            if srv.has_extn("starttls"):
                srv.starttls()
                srv.ehlo()
        if SMTP["SMTP_USER"]:
            srv.login(SMTP["SMTP_USER"], SMTP["SMTP_PASS"])
        srv.send_message(msg)
    return True


def channels():
    return [n for n, ok in (("correo", SMTP["SMTP_HOST"] and SMTP["MAIL_TO"]), ("Telegram", HOOKS["TELEGRAM_TOKEN"] and HOOKS["TELEGRAM_CHAT"]),
                            ("webhook", HOOKS["WEBHOOK_URL"])) if ok]


def post_json(url, data):
    urllib.request.urlopen(urllib.request.Request(url, json.dumps(data).encode(), {"Content-Type": "application/json"}), timeout=10).close()


def notify(subject, text):
    """Avisa por todos los canales configurados; si uno falla, los demás salen igual. Devuelve {canal: error o None}."""
    out = {}
    for ch in channels():
        try:
            if ch == "correo":
                mail(subject, text)
            elif ch == "Telegram":
                post_json(f"https://api.telegram.org/bot{HOOKS['TELEGRAM_TOKEN']}/sendMessage", {"chat_id": HOOKS["TELEGRAM_CHAT"], "text": f"{subject}\n\n{text}"})
            else:  # «text» lo leen Slack, Teams, Mattermost y Google Chat; «content», Discord
                post_json(HOOKS["WEBHOOK_URL"], {"text": f"{subject}\n{text}", "content": f"{subject}\n{text}", "subject": subject, "body": text})
            out[ch] = None
        except Exception as e:
            out[ch] = (str(e) or e.__class__.__name__)[:200]
            print(f"aviso por {ch} fallido:", out[ch])
    return out


def muted(row):
    return bool(row.get("mute_until")) and row["mute_until"] > time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


def alert(table, row, state, good, subject, text):
    """Avisa si el estado no es el último avisado. Silenciado no avisa: al acabar el silencio, si sigue mal, avisa entonces."""
    if state is None or state == row.get("alerted") or muted(row):
        return
    q(f"UPDATE {table} SET alerted=? WHERE id=?", [state, row["id"]])
    if not (row.get("alerted") is None and state == good):  # el primer «va bien» no es noticia
        notify(subject, text + "\n\n-- catlan")


CHECKS = "SELECT c.*, i.name AS item_name FROM checks c LEFT JOIN items i ON i.id = c.item"


def probe(c):
    up, rtt, detail = run_check(c)
    fails = 0 if up else (c["fails"] or 0) + 1
    state = "up" if up else "down" if fails >= 2 else c["state"]  # 2 fallos seguidos: sin falsas alarmas por un paquete perdido
    q("INSERT INTO pings(check_id, up, rtt) VALUES(?,?,?)", [c["id"], int(up), rtt])
    q("UPDATE checks SET state=?, fails=?, rtt=?, detail=?" + (", since=CURRENT_TIMESTAMP" if state != c["state"] else "") + " WHERE id=?",
      [state, fails, rtt, detail, c["id"]])
    if state == "down" and c["item"] and dependents().get(c["item"]):
        return  # cae porque cae otro del que cuelga: se avisa del culpable; si sigue caído cuando este vuelva, avisará entonces
    name, target = c["label"] or c["item_name"] or c["host"], c["url"] if c.get("kind") == "http" else c["host"]
    alert("checks", c, state, "up", f"catlan: {name}: {detail}" if state == "down" else f"catlan: {name} vuelve a funcionar",
          f"{name} ({target}): {detail}" if state == "down" else f"{name} ({target}) vuelve a funcionar: {detail}")


def dependents():
    """Equipos caídos solo porque cae otro del que cuelgan en un esquema: {item: [nombres de los culpables]}.
    Los esquemas no tienen dirección, así que la da quien sigue funcionando: en cada grupo de caídos conectados,
    el culpable es el que toca algo que funciona (o algo sin monitor, que cuenta como que funciona: en la duda, avisar)."""
    by_item = {}
    for c in q("SELECT item, state, fails FROM checks WHERE item IS NOT NULL"):
        by_item.setdefault(c["item"], []).append(c)
    # un equipo está caído si todas sus comprobaciones fallan; fallando sin llegar a «caído» ya cuenta (llegan a destiempo)
    down = {i for i, cs in by_item.items() if all(c["state"] == "down" or c["fails"] for c in cs)}
    names = {r["id"]: r["name"] for r in q("SELECT id, name FROM items")}
    verdict = {}  # item -> set de culpables, o None si en algún esquema es él el culpable
    for r in q("SELECT id, data FROM maps"):
        d = json.loads(r["data"])
        if d.get("type") == "rack":
            continue
        key = {n["id"]: n.get("item") or ("?", n["id"]) for n in d.get("nodes", []) if isinstance(n, dict) and "id" in n}
        adj = {k: set() for k in key.values()}
        for link in d.get("links", []):
            if isinstance(link, list) and len(link) >= 2 and link[0] in key and link[1] in key:
                a, b = key[link[0]], key[link[1]]
                adj[a].add(b)
                adj[b].add(a)
        seen = set()
        for start in [k for k in adj if k in down]:
            if start in seen:
                continue
            group, todo = set(), [start]
            while todo:  # grupo de caídos conectados entre sí
                k = todo.pop()
                if k not in group:
                    group.add(k)
                    todo += [n for n in adj[k] if n in down]
            seen |= group
            causes = {k for k in group if any(n not in down for n in adj[k])} or group  # nadie toca nada que funcione: avisan todos
            for k in group:
                if k in causes:
                    verdict[k] = None
                elif verdict.get(k, set()) is not None:
                    verdict.setdefault(k, set()).update(names.get(c, "?") for c in causes)
    return {k: sorted(v) for k, v in verdict.items() if v}


def monitor():
    pool, n = ThreadPoolExecutor(8), 0
    while True:
        for c in q(CHECKS + " WHERE c.last IS NULL OR c.last <= datetime('now', '-' || c.every || ' seconds')").fetchall():
            q("UPDATE checks SET last=CURRENT_TIMESTAMP WHERE id=?", [c["id"]])  # marcado antes: no se lanza dos veces
            pool.submit(probe, dict(c))
        for src in q(SOURCES + " WHERE s.kind != 'kitty' AND (s.last IS NULL OR s.last <= datetime('now', '-' || s.every || ' seconds'))").fetchall():
            q("UPDATE sources SET last=CURRENT_TIMESTAMP WHERE id=?", [src["id"]])
            pool.submit(gather, dict(src))
        for src in q(SOURCES + " WHERE s.kind = 'kitty' AND COALESCE(s.error, '') != ? AND s.last <= datetime('now', '-' || (3 * s.every) || ' seconds')",
                     [KITTY_LOST]).fetchall():  # los Kitty envían ellos; tres envíos sin noticias = apagado o sin red
            save_health(dict(src), [], [], None, KITTY_LOST)
        n += 1
        if n % 300 == 1:  # al arrancar y cada 10 min
            rollup()
            warranties()
        if n % 1800 == 0:  # en bruto, 7 días; lo de antes ya está resumido por horas
            q("DELETE FROM pings WHERE ts < datetime('now', '-7 days')")
            q("DELETE FROM metrics WHERE ts < datetime('now', '-7 days')")
            q(f"DELETE FROM pings_h WHERE hour < datetime('now', '-{KEEP_DAYS} days')")
            q(f"DELETE FROM metrics_h WHERE hour < datetime('now', '-{KEEP_DAYS} days')")
        time.sleep(2)


KEEP_DAYS = 400  # resúmenes por hora: más de un año, para comparar con el mismo mes del año anterior
HOUR_OF_TS, THIS_HOUR = "strftime('%Y-%m-%d %H:00:00', ts)", "strftime('%Y-%m-%d %H:00:00', 'now')"


def rollup():
    """Resume por horas (media, mínimo y máximo) las horas ya cerradas. Empieza en la última hora resumida
    y la rehace, así que no importa haber estado apagado ni que una hora se resumiera a medias."""
    start = q("SELECT COALESCE(max(hour), '') FROM pings_h").fetchone()[0]
    q(f"INSERT OR REPLACE INTO pings_h SELECT check_id, {HOUR_OF_TS} AS h, count(*), sum(up), avg(rtt), min(rtt), max(rtt) "
      f"FROM pings WHERE ts >= ? AND ts < {THIS_HOUR} GROUP BY check_id, h", [start])
    start = q("SELECT COALESCE(max(hour), '') FROM metrics_h").fetchone()[0]
    q(f"INSERT OR REPLACE INTO metrics_h SELECT source_id, key, {HOUR_OF_TS} AS h, max(label), max(unit), avg(value), min(value), max(value) "
      f"FROM metrics WHERE ts >= ? AND ts < {THIS_HOUR} GROUP BY source_id, key, h", [start])


def sla(month):
    """Disponibilidad de cada comprobación en un mes (hora local del servidor), sacada de los resúmenes por hora.
    shortcut: la hora en curso aún no está resumida, así que el mes actual va hasta 1 h por detrás."""
    if not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", month):
        raise ValueError("mes no válido: AAAA-MM")
    first = month + "-01"
    start, end, hours = q("SELECT datetime(?, 'utc'), datetime(?, '+1 month', 'utc'), (min(strftime('%s', datetime(?, '+1 month', 'utc')), "
                          "strftime('%s', 'now')) - strftime('%s', datetime(?, 'utc'))) / 3600", [first] * 4).fetchone()
    rows = []
    for r in q("SELECT c.id, COALESCE(NULLIF(c.label, ''), i.name, c.host) AS name, c.kind, c.host, c.every, c.item, "
               "sum(h.n) AS n, sum(h.up) AS up, count(h.hour) AS hours, sum(h.rtt * h.n) / sum(CASE WHEN h.rtt IS NULL THEN 0 ELSE h.n END) AS rtt "
               "FROM checks c LEFT JOIN items i ON i.id = c.item LEFT JOIN pings_h h ON h.check_id = c.id AND h.hour >= ? AND h.hour < ? "
               "GROUP BY c.id ORDER BY name COLLATE NOCASE", [start, end]):
        r = dict(r)
        r["uptime"] = r["up"] / r["n"] if r["n"] else None
        r["down_min"] = round((r["n"] - r["up"]) * r["every"] / 60) if r["n"] else None  # cada fallo cuenta como un intervalo entero
        r["coverage"] = min(1, r["hours"] / hours) if hours > 0 else 0
        r["rtt"] = r["rtt"] and round(r["rtt"], 1)
        rows.append(r)
    known = [r["uptime"] for r in rows if r["uptime"] is not None]
    return {"month": month, "hours": max(0, hours), "avg": sum(known) / len(known) if known else None, "checks": rows,
            "first": q("SELECT min(hour) FROM pings_h").fetchone()[0]}


def monitor_state():
    out, deps = [], dependents()
    for c in q(CHECKS + " ORDER BY COALESCE(NULLIF(c.label, ''), i.name, c.host) COLLATE NOCASE").fetchall():
        c = dict(c)
        c["uptime"] = q("SELECT avg(up) FROM pings WHERE check_id=? AND ts > datetime('now', '-1 day')", [c["id"]]).fetchone()[0]
        c["recent"] = [r[0] for r in q("SELECT up FROM pings WHERE check_id=? ORDER BY rowid DESC LIMIT 40", [c["id"]])][::-1]
        c["dep"] = deps.get(c["item"]) if c["state"] == "down" else None
        out.append(c)
    srcs = [{"id": r["id"], "name": r["label"] or r["item_name"] or r["host"], "state": r["state"], "problems": json.loads(r["problems"] or "[]"),
             "error": r["error"], "mute_until": r["mute_until"]} for r in q(SOURCES).fetchall()]
    return {"channels": channels(), "checks": out, "sources": srcs}


# ── SNMP mínimo: GET y GETBULK sobre UDP, codificación BER a mano (sin dependencias) ──
def _blen(n):
    return bytes([n]) if n < 128 else (lambda b: bytes([0x80 | len(b)]) + b)(n.to_bytes((n.bit_length() + 7) // 8, "big"))


def tlv(tag, v):
    return bytes([tag]) + _blen(len(v)) + v


def ber_int(n, tag=2):
    return tlv(tag, n.to_bytes(max(1, (n.bit_length() + 8) // 8), "big", signed=True))


def ber_oid(oid):
    p = [int(x) for x in oid.split(".")]
    out = bytearray([40 * p[0] + p[1]])
    for x in p[2:]:
        chunk = [x & 0x7F]
        x >>= 7
        while x:
            chunk.append(0x80 | (x & 0x7F))
            x >>= 7
        out += bytes(reversed(chunk))
    return tlv(6, bytes(out))


def ber_read(b, i):
    tag, n = b[i], b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        n, i = int.from_bytes(b[i:i + k], "big"), i + k
    return tag, b[i:i + n], i + n


def oid_str(v):
    p, x = [v[0] // 40, v[0] % 40], 0
    for c in v[1:]:
        x = (x << 7) | (c & 0x7F)
        if not c & 0x80:
            p.append(x)
            x = 0
    return ".".join(map(str, p))


class Octets(str):
    """Un OCTET STRING: se usa como texto, y .raw guarda los bytes tal cual (MAC, IP en binario, bits de capacidades)."""
    raw = b""


def ber_val(tag, v):
    if tag == 2:
        return int.from_bytes(v, "big", signed=True)
    if tag in (0x41, 0x42, 0x43, 0x46):  # Counter32, Gauge32, TimeTicks, Counter64
        return int.from_bytes(v, "big")
    if tag == 4:
        o = Octets(v.decode("utf-8", "replace"))
        o.raw = bytes(v)
        return o
    if tag == 6:
        return oid_str(v)
    if tag == 0x40:
        return ".".join(map(str, v))
    return None  # NULL, noSuchObject, noSuchInstance, endOfMibView


def snmp_msg(community, pdu, rid, oids, a=0, b=0):
    vbs = b"".join(tlv(0x30, ber_oid(o) + b"\x05\x00") for o in oids)
    return tlv(0x30, ber_int(1) + tlv(4, community.encode()) + tlv(pdu, ber_int(rid) + ber_int(a) + ber_int(b) + tlv(0x30, vbs)))


def snmp_parse(data):
    _, msg, _ = ber_read(data, 0)
    _, _, i = ber_read(msg, 0)  # versión
    _, _, i = ber_read(msg, i)  # comunidad
    _, pdu, _ = ber_read(msg, i)
    return pdu_parse(pdu)


def pdu_parse(pdu):
    _, rid, j = ber_read(pdu, 0)
    _, err, j = ber_read(pdu, j)
    _, _, j = ber_read(pdu, j)
    _, vbl, _ = ber_read(pdu, j)
    out, k = [], 0
    while k < len(vbl):
        _, vb, k = ber_read(vbl, k)
        _, o, m = ber_read(vb, 0)
        t, v, _ = ber_read(vb, m)
        out.append((oid_str(o), t, ber_val(t, v)))
    return int.from_bytes(rid, "big", signed=True), int.from_bytes(err, "big"), out


# ── SNMPv3 (USM: RFC 3414, 3826 y 7860): firma HMAC con hashlib y AES-128 escrito a mano ──
# shortcut: sin DES ni AES-192/256 (DES está obsoleto y AES-128 lo admiten todos los fabricantes); añadirlos si un equipo solo da esos.
AUTH = {"md5": ("md5", 12), "sha": ("sha1", 12), "sha224": ("sha224", 16), "sha256": ("sha256", 24),
        "sha384": ("sha384", 32), "sha512": ("sha512", 48)}  # algoritmo y bytes de la firma
USM_ERR = {"1": "el equipo no admite ese nivel de seguridad: revisa autenticación y cifrado",
           "3": "usuario SNMPv3 desconocido en el equipo",
           "5": "la firma no coincide: revisa la contraseña y el algoritmo de autenticación",
           "6": "no se pudo descifrar: revisa la contraseña y el algoritmo de cifrado"}


def usm_key(proto, password, engine):
    """Clave localizada: la contraseña repetida hasta 1 MB, resumida, y mezclada con el engineID del equipo."""
    h, p = AUTH[proto][0], password.encode()
    ku = hashlib.new(h, (p * (1048576 // len(p) + 1))[:1048576]).digest()
    return hashlib.new(h, ku + engine + ku).digest()


def _aes_sbox():
    s, p, q = [0x63] * 256, 1, 1
    rot = lambda x, k: ((x << k) | (x >> (8 - k))) & 0xFF
    while True:  # la S-box sale de invertir en GF(2^8) y la transformación afín
        p ^= ((p << 1) ^ (0x1B if p & 0x80 else 0)) & 0xFF
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        s[p] = q ^ rot(q, 1) ^ rot(q, 2) ^ rot(q, 3) ^ rot(q, 4) ^ 0x63
        if p == 1:
            return s


SBOX = _aes_sbox()
_xt = lambda a: ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def aes_keys(key):
    w, rc = list(key), 1
    for i in range(16, 176, 4):
        t = w[i - 4:i]
        if i % 16 == 0:
            t, rc = [SBOX[t[1]] ^ rc, SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]], _xt(rc)
        w += [w[i - 16 + j] ^ t[j] for j in range(4)]
    return w


def aes_block(w, b):
    s = [x ^ k for x, k in zip(b, w)]
    for r in range(1, 11):
        s = [SBOX[s[(i + 4 * (i % 4)) % 16]] for i in range(16)]  # SubBytes + ShiftRows
        if r < 10:  # MixColumns
            m = []
            for c in range(0, 16, 4):
                a = s[c:c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                m += [a[j] ^ t ^ _xt(a[j] ^ a[(j + 1) % 4]) for j in range(4)]
            s = m
        s = [x ^ k for x, k in zip(s, w[16 * r:])]
    return bytes(s)


def aes_cfb(key, iv, data, encrypt):
    w, out, prev = aes_keys(key), bytearray(), iv
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        o = bytes(a ^ b for a, b in zip(chunk, aes_block(w, prev)))
        out += o
        prev = o if encrypt else chunk
    return bytes(out)


class SNMP:
    def __init__(self, host, community="public", port=161, timeout=2.0, v3=None):
        """v3 = {"user", "auth", "pass", "priv", "priv_pass"}; sin v3 habla v2c con la comunidad."""
        self.host, self.port, self.c, self.t, self.rid = host, port, community, timeout, random.randint(1, 1 << 30)
        self.v3, self.eng = v3, None
        if v3:
            self.lvl = 0 if v3["auth"] == "none" else 1 if v3["priv"] == "none" else 3  # bits: 1 firma, 2 cifra

    def _ask(self, pdu, oids, b=0):
        fam, _, _, _, addr = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_DGRAM)[0]
        with socket.socket(fam, socket.SOCK_DGRAM) as s:
            s.settimeout(self.t)
            s.connect(addr)  # solo llegan respuestas de ese equipo y ese puerto
            if not self.v3:
                self.rid += 1
                tag, err, vbs = self._xchg(s, addr, snmp_msg(self.c, pdu, self.rid, oids, 0, b), lambda d: (lambda rid, err, vbs: (rid, 0xA2, err, vbs))(*snmp_parse(d)))
            else:
                for _ in range(3):  # descubrir el equipo y, si su reloj ha cambiado, resincronizar
                    if self.eng is None:
                        self._xchg(s, addr, self._v3_msg(0xA0, [], 0, discover=True), self._v3_parse)
                    tag, err, vbs = self._xchg(s, addr, self._v3_msg(pdu, oids, b), self._v3_parse)
                    if tag != 0xA8:
                        break
                    oid = vbs[0][0] if vbs else ""
                    why = oid.split(".")[-2] if oid.count(".") else ""  # informe vacío: sin motivo
                    if not oid.startswith("1.3.6.1.6.3.15.1.1.") or why not in ("2", "4"):  # 2 reloj, 4 engineID
                        raise ValueError(USM_ERR.get(why, f"el equipo rechazó la petición SNMPv3 ({oid or 'sin detalle'})"))
                else:
                    raise ValueError("no se pudo sincronizar con el reloj SNMPv3 del equipo")
        if err:
            raise ValueError(f"el equipo respondió con error SNMP {err}")
        return vbs

    def _xchg(self, s, addr, msg, parse):
        rid = self.rid
        for _ in range(2):  # un reintento: UDP pierde paquetes
            s.send(msg)
            try:
                while True:
                    r = parse(s.recv(65535))
                    if r and r[0] == rid:
                        return r[1:]
            except (socket.timeout, ConnectionResetError):  # Windows avisa así del «puerto cerrado» (ICMP)
                continue
        raise TimeoutError("sin respuesta SNMP: revisa la IP, " + ("el usuario" if self.v3 else "la comunidad")
                           + " y que SNMP" + (" v3" if self.v3 else "") + " esté activado en el equipo")

    def _v3_msg(self, pdu, oids, b, discover=False):
        self.rid += 1
        lvl, v = 0 if discover else self.lvl, self.v3
        eng = b"" if discover else self.eng
        boots, et = (0, 0) if discover else (self.boots, self.etime + int(time.monotonic() - self.at))
        vbs = b"".join(tlv(0x30, ber_oid(o) + b"\x05\x00") for o in oids)
        body = tlv(0x30, tlv(4, eng) + tlv(4, b"") + tlv(pdu, ber_int(self.rid) + ber_int(0) + ber_int(b) + tlv(0x30, vbs)))
        salt = os.urandom(8) if lvl & 2 else b""
        if lvl & 2:
            body = tlv(4, aes_cfb(self.kp, boots.to_bytes(4, "big") + et.to_bytes(4, "big") + salt, body, True))
        mark = os.urandom(AUTH[v["auth"]][1]) if lvl & 1 else b""  # hueco de la firma, se rellena al final
        sec = tlv(0x30, tlv(4, eng) + ber_int(boots) + ber_int(et) + tlv(4, b"" if discover else v["user"].encode())
                  + tlv(4, mark) + tlv(4, salt))
        msg = tlv(0x30, ber_int(3) + tlv(0x30, ber_int(self.rid) + ber_int(65507) + tlv(4, bytes([lvl | 4])) + ber_int(3))
                  + tlv(4, sec) + body)
        return msg.replace(mark, self._sign(msg.replace(mark, bytes(len(mark)), 1)), 1) if mark else msg

    def _sign(self, msg):
        return hmac.new(self.ka, msg, AUTH[self.v3["auth"]][0]).digest()[:AUTH[self.v3["auth"]][1]]

    def _v3_parse(self, data):
        _, m, _ = ber_read(data, 0)
        _, ver, i = ber_read(m, 0)
        if ver != b"\x03":
            return None
        _, g, i = ber_read(m, i)
        _, sp, i = ber_read(m, i)
        t, body, _ = ber_read(m, i)
        _, mid, k = ber_read(g, 0)
        _, _, k = ber_read(g, k)
        _, flags, _ = ber_read(g, k)
        f, sq, k = [], ber_read(sp, 0)[1], 0
        while k < len(sq):
            _, x, k = ber_read(sq, k)
            f.append(x)
        eng, boots, et, _, mac, salt = f
        boots, et = int.from_bytes(boots, "big"), int.from_bytes(et, "big")
        if flags[0] & 1:  # respuesta firmada: comprobar que la firma es buena
            if self.eng is None or not hmac.compare_digest(mac, self._sign(data.replace(mac, bytes(len(mac)), 1))):
                return None
        if flags[0] & 2:
            body = ber_read(aes_cfb(self.kp, boots.to_bytes(4, "big") + et.to_bytes(4, "big") + salt, body, False), 0)[1]
        elif t != 0x30:
            return None
        _, _, k = ber_read(body, 0)  # contextEngineID
        _, _, k = ber_read(body, k)  # contextName
        tag, pdu, _ = ber_read(body, k)
        if tag != 0xA8 and (flags[0] & 3) != self.lvl:  # solo los informes van sin firma; una respuesta sin ella es falsa
            return None
        if tag == 0xA8:  # informe: el equipo nos dice su engineID y su reloj
            if eng != self.eng and self.v3["auth"] != "none":
                self.ka = usm_key(self.v3["auth"], self.v3["pass"], eng)
                self.kp = usm_key(self.v3["auth"], self.v3["priv_pass"], eng)[:16] if self.lvl & 2 else b""
            self.eng, self.boots, self.etime, self.at = eng, boots, et, time.monotonic()
        return (int.from_bytes(mid, "big"), tag, *pdu_parse(pdu)[1:])

    def get(self, *oids):
        return {o: (None if t in (0x80, 0x81, 0x82) else v) for o, t, v in self._ask(0xA0, oids)}

    def walk(self, base):
        out, cur = {}, base
        while len(out) < 5000:
            vbs = self._ask(0xA5, [cur], 25)
            for o, t, v in vbs:
                if t == 0x82 or not o.startswith(base + ".") or o == cur:
                    return out
                out[o[len(base) + 1:]] = v
                cur = o
            if not vbs:
                return out
        return out

    def table(self, base):
        rows = {}
        for k, v in self.walk(base).items():
            col, _, idx = k.partition(".")
            rows.setdefault(idx, {})[col] = v
        return rows


# ── Perfiles: qué leer de cada fabricante ──
def num(v):
    m = re.search(r"-?\d+(?:[.,]\d+)?", str(v or ""))
    return float(m.group().replace(",", ".")) if m else None


def size_bytes(v):  # QNAP da tamaños como texto: "1.80 TB"
    m = re.search(r"([\d.,]+)\s*([KMGTP]?)B", str(v or ""), re.I)
    return float(m.group(1).replace(",", ".")) * 1024 ** "_KMGTP".index(m.group(2).upper() or "_") if m else None


def host_resources(s, out):
    """HOST-RESOURCES-MIB: CPU, memoria y discos de cualquier equipo con net-snmp (NAS, Linux, MikroTik, UniFi…)."""
    for r in s.table("1.3.6.1.2.1.25.2.3.1").values():
        size, used, unit, name = r.get("5") or 0, r.get("6") or 0, r.get("4") or 1, str(r.get("3") or "")
        if not size:
            continue
        if r.get("2") == "1.3.6.1.2.1.25.2.1.2":
            out.append(("mem", "Memoria", 100 * used / size, "%"))
        elif (r.get("2") == "1.3.6.1.2.1.25.2.1.4" and size * unit >= 1 << 30
              and not name.startswith(("/dev", "/run", "/sys", "/proc", "/boot", "/tmp"))):
            out.append(("disk:" + name, name, 100 * used / size, "%"))
    loads = [v for v in s.walk("1.3.6.1.2.1.25.3.3.1.2").values() if isinstance(v, int)]
    if loads:
        out.append(("cpu", "CPU", sum(loads) / len(loads), "%"))


def entity_temps(s, out):
    """ENTITY-SENSOR-MIB: sensores de temperatura de switches modernos (Cisco, Aruba CX, HPE…)."""
    types = s.walk("1.3.6.1.2.1.99.1.1.1.1")
    if 8 not in types.values():
        return
    prec, val, names = s.walk("1.3.6.1.2.1.99.1.1.1.3"), s.walk("1.3.6.1.2.1.99.1.1.1.4"), s.walk("1.3.6.1.2.1.47.1.1.1.1.7")
    for i, t in types.items():
        if t == 8 and isinstance(val.get(i), int):
            name = str(names.get(i) or f"Sensor {i}")
            out.append(("temp:" + name, name, val[i] / 10 ** (prec.get(i) or 0), "°C"))


def p_generic(s, out, probs):
    host_resources(s, out)
    entity_temps(s, out)


def p_synology(s, out, probs):
    host_resources(s, out)
    b = "1.3.6.1.4.1.6574."
    g = s.get(b + "1.1.0", b + "1.2.0", b + "1.3.0", b + "1.4.1.0", b + "1.4.2.0")
    if g[b + "1.2.0"] is not None:
        out.append(("temp:sistema", "Sistema", g[b + "1.2.0"], "°C"))
    for oid, msg in ((b + "1.1.0", "Estado del sistema: fallo"), (b + "1.3.0", "Fuente de alimentación con fallo"),
                     (b + "1.4.1.0", "Ventilador del sistema con fallo"), (b + "1.4.2.0", "Ventilador de la CPU con fallo")):
        if g[oid] == 2:
            probs.append(msg)
    for d in s.table(b + "2.1.1").values():
        name = str(d.get("2") or "Disco")
        if isinstance(d.get("6"), int):
            out.append(("temp:" + name, name, d["6"], "°C"))
        if d.get("5") in (4, 5):
            probs.append(f"{name}: {'partición del sistema dañada' if d['5'] == 4 else 'disco dañado'}")
    for r in s.table(b + "3.1.1").values():
        if r.get("3") in (11, 12):
            probs.append(f"{r.get('2') or 'Volumen'}: {'degradado' if r['3'] == 11 else 'caído'}")


def p_qnap(s, out, probs):
    host_resources(s, out)
    b = "1.3.6.1.4.1.24681.1.2."
    g = s.get(b + "5.0", b + "6.0")
    for oid, key, label in ((b + "5.0", "temp:cpu", "CPU"), (b + "6.0", "temp:sistema", "Sistema")):
        if num(g[oid]) is not None:
            out.append((key, label, num(g[oid]), "°C"))
    for d in s.table(b + "11.1").values():
        name = str(d.get("2") or "Disco")
        if num(d.get("3")) is not None:
            out.append(("temp:" + name, name, num(d["3"]), "°C"))
        smart = str(d.get("7") or "").strip().upper()
        if smart and smart not in ("GOOD", "NORMAL", "--"):
            probs.append(f"{name}: SMART {smart.lower()}")
    for v in s.table(b + "17.1").values():
        name, tot, free = str(v.get("2") or "Volumen"), size_bytes(v.get("4")), size_bytes(v.get("5"))
        if tot:
            out.append(("disk:" + name, name, 100 * (tot - (free or 0)) / tot, "%"))
        if re.search(r"degrad|error|fail|crash", str(v.get("6") or ""), re.I):
            probs.append(f"{name}: {v['6']}")


ENV_STATE = {2: "en aviso", 3: "crítico", 4: "apagado", 6: "averiado"}


def p_cisco(s, out, probs):
    b = "1.3.6.1.4.1.9.9."
    cpu = [v for v in s.walk(b + "109.1.1.1.1.8").values() if isinstance(v, int)]  # cpmCPUTotal5minRev
    if cpu:
        out.append(("cpu", "CPU", cpu[0], "%"))
    for r in s.table(b + "48.1.1.1").values():  # ciscoMemoryPool
        if str(r.get("2")).lower().startswith("processor") and (r.get("5") or 0) + (r.get("6") or 0):
            out.append(("mem", "Memoria", 100 * r["5"] / (r["5"] + r["6"]), "%"))
    temps = s.table(b + "13.1.3.1")
    for t in temps.values():
        name = str(t.get("2") or "Temperatura")
        if isinstance(t.get("3"), int):
            out.append(("temp:" + name, name, t["3"], "°C"))
        if t.get("6") in ENV_STATE:
            probs.append(f"{name}: {ENV_STATE[t['6']]}")
    for base, what in ((b + "13.1.4.1", "Ventilador"), (b + "13.1.5.1", "Fuente")):
        for f in s.table(base).values():
            if f.get("3") in ENV_STATE:
                probs.append(f"{f.get('2') or what}: {ENV_STATE[f['3']]}")
    if not temps:
        entity_temps(s, out)


def p_hp(s, out, probs):
    b = "1.3.6.1.4.1.11.2.14.11."
    cpu = s.get(b + "5.1.9.6.1.0")[b + "5.1.9.6.1.0"]
    if isinstance(cpu, int):
        out.append(("cpu", "CPU", cpu, "%"))
    for r in s.table(b + "5.1.1.2.1.1.1").values():  # hpLocalMem: total (5) y en uso (7)
        if r.get("5"):
            out.append(("mem", "Memoria", 100 * (r.get("7") or 0) / r["5"], "%"))
            break
    for r in s.table(b + "1.2.6.1").values():  # hpicfSensor: 2 mal, 3 aviso
        if r.get("4") in (2, 3):
            probs.append(f"{r.get('7') or 'Sensor'}: {'fallo' if r['4'] == 2 else 'en aviso'}")
    entity_temps(s, out)


def p_ubiquiti(s, out, probs):
    host_resources(s, out)
    b = "1.3.6.1.4.1.4413.1.1.43.1."  # EdgeSwitch / UniFi Switch (FASTPATH)
    for i, t in s.table(b + "8.1").items():
        if isinstance(t.get("5"), int):
            out.append((f"temp:sensor {i}", f"Sensor {i}", t["5"], "°C"))
    for i, f in s.table(b + "6.1").items():
        if f.get("3") == 3:
            probs.append(f"Ventilador {i}: fallo")
        if isinstance(f.get("4"), int):
            out.append((f"fan:{i}", f"Ventilador {i}", f["4"], "rpm"))
    if not any(k.startswith("temp:") for k, *_ in out):
        entity_temps(s, out)


def p_mikrotik(s, out, probs):
    host_resources(s, out)
    b = "1.3.6.1.4.1.14988.1.1.3."
    gauges = s.table(b + "100.1")  # RouterOS 7: nombre (2), valor (3), unidad (4: 1 °C, 2 rpm)
    for g in gauges.values():
        name, v = str(g.get("2") or "Sensor"), g.get("3")
        if g.get("4") == 1 and isinstance(v, int):
            out.append(("temp:" + name, name, v, "°C"))
        elif g.get("4") == 2 and isinstance(v, int):
            out.append(("fan:" + name, name, v, "rpm"))
    if not gauges:  # RouterOS 6: décimas de grado
        g = s.get(b + "10.0", b + "11.0")
        for oid, key, label in ((b + "10.0", "temp:placa", "Placa"), (b + "11.0", "temp:cpu", "CPU")):
            if isinstance(g[oid], int):
                out.append((key, label, g[oid] / 10, "°C"))


def parse_hik(xml):
    """Discos de un grabador Hikvision (ISAPI /ContentMgmt/Storage)."""
    out, probs = [], []
    for hdd in ET.fromstring(xml).iter():
        if hdd.tag.rsplit("}", 1)[-1] != "hdd":
            continue
        f = {c.tag.rsplit("}", 1)[-1]: (c.text or "").strip() for c in hdd}
        name = f.get("hddName") or f"Disco {f.get('id', '')}".strip()
        cap, free = num(f.get("capacity")), num(f.get("freeSpace"))
        if cap:
            out.append(("disk:" + name, name, 100 * (cap - (free or 0)) / cap, "%"))
        if f.get("status", "ok").lower() not in ("ok", "idle", "sleeping", "standby"):
            probs.append(f"{name}: {f['status']}")
    if not out and not probs:
        raise ValueError("el grabador no devolvió discos")
    return out, probs


def p_hikvision(src):
    base = f"http://{src['host']}/"
    pm = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    pm.add_password(None, base, src.get("user") or "admin", src.get("pass") or "")
    opener = urllib.request.build_opener(urllib.request.HTTPDigestAuthHandler(pm), urllib.request.HTTPBasicAuthHandler(pm))
    try:
        return parse_hik(opener.open(base + "ISAPI/ContentMgmt/Storage", timeout=8).read())
    except urllib.error.HTTPError as e:
        raise ValueError("usuario o contraseña del grabador incorrectos" if e.code == 401 else f"el grabador respondió {e.code}")


# ── Interfaces (IF-MIB): tráfico, errores y puertos caídos de cualquier equipo con SNMP ──
IF = {"type": "1.3.6.1.2.1.2.2.1.3", "descr": "1.3.6.1.2.1.2.2.1.2", "admin": "1.3.6.1.2.1.2.2.1.7", "oper": "1.3.6.1.2.1.2.2.1.8",
      "ierr": "1.3.6.1.2.1.2.2.1.14", "oerr": "1.3.6.1.2.1.2.2.1.20", "lspeed": "1.3.6.1.2.1.2.2.1.5", "name": "1.3.6.1.2.1.31.1.1.1.1",
      "alias": "1.3.6.1.2.1.31.1.1.1.18", "speed": "1.3.6.1.2.1.31.1.1.1.15", "hin": "1.3.6.1.2.1.31.1.1.1.6", "hout": "1.3.6.1.2.1.31.1.1.1.10"}
PORT_TYPES = {6, 23, 62, 69, 71, 117, 161}  # ethernet, PPP (WAN), fast/gigabit, wifi, LAG; fuera loopback, VLAN, túneles
IF_PREV = {}  # id de la fuente -> {ifIndex: (hora, entrada, salida, errores)}: un contador solo dice algo frente al anterior


def interfaces(s, sid, out, probs):
    """Puertos con su estado y, desde la segunda lectura, Mbps de entrada/salida y errores por minuto."""
    c = {k: s.walk(o) for k, o in IF.items()}
    hc = bool(c["hin"])
    if not hc:  # sin contadores de 64 bits: los de 32 (dan la vuelta cada ~34 s a 1 Gbps)
        c["hin"], c["hout"] = s.walk("1.3.6.1.2.1.2.2.1.10"), s.walk("1.3.6.1.2.1.2.2.1.16")
    t, prev, now, ports = time.time(), IF_PREV.get(sid, {}), {}, []
    for i, typ in c["type"].items():
        if typ not in PORT_TYPES:
            continue
        name = str(c["name"].get(i) or c["descr"].get(i) or f"if{i}")[:60]
        alias, up, admin = str(c["alias"].get(i) or "")[:80], c["oper"].get(i) == 1, c["admin"].get(i) == 1
        p = {"i": int(i), "name": name, "alias": alias, "up": up, "admin": admin, "speed": c["speed"].get(i) or (c["lspeed"].get(i) or 0) // 10 ** 6}
        rin, rout, err = c["hin"].get(i), c["hout"].get(i) or 0, (c["ierr"].get(i) or 0) + (c["oerr"].get(i) or 0)
        if rin is not None:
            now[i] = (t, rin, rout, err)
        if i in prev and rin is not None and t > prev[i][0]:
            dt, (_, pin, pout, perr) = t - prev[i][0], prev[i]
            # shortcut: con 32 bits solo se corrige una vuelta del contador; para enlaces rápidos hace falta ifHCInOctets (SNMP v2c/v3)
            d = lambda a, b: a - b if a >= b else None if hc else a + 2 ** 32 - b  # None: contador reiniciado (el equipo arrancó)
            din, dout = d(rin, pin), d(rout, pout)
            if din is not None and dout is not None:
                p.update(rx=round(din * 8 / dt / 1e6, 3), tx=round(dout * 8 / dt / 1e6, 3), err=round(max(0, err - perr) / dt * 60, 2))
                if up:
                    out += [(f"rx:{name}", f"{name} ↓", p["rx"], "Mbps"), (f"tx:{name}", f"{name} ↑", p["tx"], "Mbps"), (f"err:{name}", name, p["err"], "/min")]
                if p["err"] > 10:
                    probs.append(f"{name}: {p['err']:g} errores/min")
                if up and p["speed"] and max(p["rx"], p["tx"]) > p["speed"] * .9:
                    probs.append(f"{name}: al {max(p['rx'], p['tx']) / p['speed'] * 100:.0f} % de su capacidad")
        if alias and admin and not up:  # con descripción = puerto importante (uplink, servidor…): caído es noticia
            probs.append(f"{name} ({alias}): caído")
        ports.append(p)
    if sid:
        IF_PREV[sid] = now
    return ports


PROFILES = {"generic": p_generic, "synology": p_synology, "qnap": p_qnap, "cisco": p_cisco, "hp": p_hp,
            "ubiquiti": p_ubiquiti, "mikrotik": p_mikrotik, "hikvision": None}


def snmp_for(src):
    """El cliente SNMP (v2c o v3) con las credenciales guardadas de una fuente de Salud."""
    v3 = None
    if src.get("v3"):
        v3 = {k: src.get(k) or "" for k in ("user", "auth", "pass", "priv", "priv_pass")}
        v3["auth"], v3["priv"] = v3["auth"] or "sha", v3["priv"] or "aes"
        if v3["auth"] != "none" and not v3["pass"] or v3["auth"] != "none" and v3["priv"] != "none" and not v3["priv_pass"]:
            raise ValueError("faltan las contraseñas SNMPv3")
    return SNMP(src["host"], src.get("community") or "public", src.get("port") or 161, v3=v3)


# ── Auto-topología: quién está conectado a qué puerto, leído del switch por LLDP, CDP y su tabla MAC ──
LLDP_REM, LLDP_LOC, LLDP_MAN = "1.0.8802.1.1.2.1.4.1.1", "1.0.8802.1.1.2.1.3.7.1", "1.0.8802.1.1.2.1.4.2.1"
CDP = "1.3.6.1.4.1.9.9.23.1.2.1.1"
FDB_Q, FDB_D, BRIDGE_IF = "1.3.6.1.2.1.17.7.1.2.2.1.2", "1.3.6.1.2.1.17.4.3.1.2", "1.3.6.1.2.1.17.1.4.1.2"
ARP = "1.3.6.1.2.1.4.22.1.2"
MAX_MACS = 4  # un puerto con más MAC detrás es un enlace a otro switch o a un AP: no es «un equipo»


def raw(v):
    return getattr(v, "raw", None) or (v.encode("latin-1", "replace") if isinstance(v, str) else b"")


def mac_txt(b):
    return ":".join(f"{x:02x}" for x in b) if len(b) == 6 else None


def caps_icon(bits, cdp=False):
    """Icono según las capacidades que anuncia el vecino (LLDP: bits desde el más alto; CDP: máscara de 32 bits)."""
    if cdp:
        n = int.from_bytes(bits[:4], "big") if bits else 0
        return "router" if n & 1 else "switch" if n & 8 else "phone" if n & 0x80 else None
    n = bits[0] if bits else 0  # other, repeater, bridge, wlanAP, router, telephone, docsis, station
    return "router" if n & 0x08 else "ap" if n & 0x10 else "switch" if n & 0x20 else "phone" if n & 0x04 else "pc" if n & 0x01 else None


def topology(s):
    """Vecinos del switch, por puerto: [{port, via: lldp|cdp|mac, name, ip, mac, rport, icon}]. Cada tabla que falte, se salta."""
    def safe(fn, base):
        try:
            return fn(base)
        except (TimeoutError, ValueError, OSError):
            return {}
    names = safe(s.walk, IF["name"]) or safe(s.walk, IF["descr"])  # ifIndex -> Gi1/0/1
    by_name = {str(v): k for k, v in names.items()}
    found = {}  # ifIndex -> vecinos
    seen = set()

    def add(ifi, n):
        key = (ifi, (n.get("name") or n.get("mac") or "").lower())
        if key not in seen:  # el mismo vecino por LLDP y por CDP: una vez
            seen.add(key)
            found.setdefault(str(ifi), []).append(n)
    # LLDP: el puerto local va por su número; casi siempre es el ifIndex, si no, su nombre o descripción
    loc = safe(s.table, LLDP_LOC)
    def lldp_if(num):
        for col in ("3", "4"):
            if str(loc.get(num, {}).get(col, "")) in by_name:
                return by_name[str(loc[num][col])]
        return num
    ips = {}
    for k in safe(s.walk, LLDP_MAN):  # índice: col.timeMark.puerto.índice.tipo(1=IPv4).4.a.b.c.d
        p = k.split(".")
        if len(p) >= 10 and p[4] == "1" and p[5] == "4":
            ips[(p[2], p[3])] = ".".join(p[6:10])
    for idx, r in safe(s.table, LLDP_REM).items():
        p = idx.split(".")
        if len(p) < 3:
            continue
        chassis = raw(r.get("5"))
        name = str(r.get("9") or "").strip() or mac_txt(chassis) or str(r.get("5") or "")
        add(lldp_if(p[1]), {"via": "lldp", "name": name, "ip": ips.get((p[1], p[2])), "mac": mac_txt(chassis),
                            "rport": str(r.get("8") or r.get("7") or "").strip(), "icon": caps_icon(raw(r.get("12")))})
    # CDP (Cisco): índice ifIndex.n; la dirección llega en 4 bytes
    for idx, r in safe(s.table, CDP).items():
        a = raw(r.get("4"))
        add(idx.split(".")[0], {"via": "cdp", "name": str(r.get("6") or "").strip(), "ip": ".".join(map(str, a)) if len(a) == 4 else None,
                                "mac": None, "rport": str(r.get("7") or "").strip(), "icon": caps_icon(raw(r.get("9")), cdp=True)})
    # Tabla MAC (Q-BRIDGE con VLAN, o BRIDGE clásica): en los puertos sin vecino LLDP/CDP y con pocas MAC, un equipo por MAC
    port_if = safe(s.walk, BRIDGE_IF)  # puerto del bridge -> ifIndex
    macs = {}
    for k, bp in (safe(s.walk, FDB_Q) or safe(s.walk, FDB_D)).items():
        m = k.split(".")[-6:]
        if len(m) == 6:
            ifi = str(port_if.get(str(bp), bp))
            macs.setdefault(ifi, set()).add(":".join(f"{int(x):02x}" for x in m))
    arp = {}
    for k, v in safe(s.walk, ARP).items():  # índice: ifIndex.a.b.c.d -> MAC en binario
        p = k.split(".")
        if len(p) == 5 and mac_txt(raw(v)):
            arp[mac_txt(raw(v))] = ".".join(p[1:])
    for ifi, ms in macs.items():
        if ifi in found or ifi not in names or len(ms) > MAX_MACS:
            continue
        for m in sorted(ms):
            add(ifi, {"via": "mac", "name": "", "ip": arp.get(m), "mac": m, "rport": "", "icon": None})
    key = lambda ifi: [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", str(names.get(ifi, ifi)))]  # Gi1/0/2 antes que Gi1/0/10
    return [{"port": str(names.get(ifi, ifi)), **n} for ifi in sorted(found, key=key) for n in found[ifi]]


KIND_ICON = [("router", "router"), ("switch", "switch"), ("firewall", "firewall"), ("servidor", "server"), ("server", "server"), ("nas", "nas"),
             ("port", "laptop"), ("impres", "printer"), ("printer", "printer"), ("tel", "phone"), ("cám", "camera"), ("cam", "camera"),
             ("sai", "ups"), ("ups", "ups"), ("ap", "ap"), ("wifi", "ap"), ("pc", "pc")]


def auto_map(src):
    """Lee la topología del switch de una fuente de Salud y la dibuja en un esquema «Topología · switch» (lo rehace si existe)."""
    nbrs = topology(snmp_for(src))
    items = [dict(r) for r in q("SELECT id, name, kind, ip FROM items")]
    by_ip = {i["ip"]: i for i in items if i["ip"]}
    by_name = {i["name"].lower(): i for i in items if i["name"]}
    me = (src.get("item") and next((i for i in items if i["id"] == src["item"]), None)) or by_ip.get(src["host"])
    title = src.get("label") or (me and me["name"]) or src["host"]
    nodes = [{"id": "sw", "t": "switch", "x": 600, "y": 90, **({"item": me["id"]} if me else {"label": title})}]
    links, per_row = [], max(9, -(-len(nbrs) // 4))  # como mucho 4 filas: el lienzo mide 1200 x 800
    for k, n in enumerate(nbrs):
        it = by_ip.get(n["ip"]) or by_name.get((n["name"] or "").lower()) or by_name.get((n["name"] or "").split(".")[0].lower())
        kind = (it["kind"] or "").lower() if it else ""
        icon = next((ic for word, ic in KIND_ICON if word in kind), None) or n["icon"] or ("switch" if n["via"] != "mac" else "pc")  # manda el inventario
        row, col = divmod(k, per_row)
        nodes.append({"id": f"p{k}", "t": icon, "x": round(200 + (col + .5) * 950 / per_row), "y": 260 + row * 140 + col % 2 * 45,  # en zigzag: los nombres de al lado no se pisan
                      **({"item": it["id"]} if it else {"label": (n["name"] or n["ip"] or n["mac"] or "?") + (f" ({n['rport']})" if n["rport"] else "")})})
        n["item"] = it and it["id"]
        links.append(["sw", f"p{k}", n["port"]])  # el puerto del switch, en la línea
    name = f"Topología · {title}"[:200]
    data = {"nodes": nodes, "links": links, "auto": {"source": src["id"], "at": time.strftime("%Y-%m-%d %H:%M:%S")}}
    row = q("SELECT id FROM maps WHERE name=? AND json_extract(data, '$.auto.source')=?", [name, src["id"]]).fetchone()
    if row:
        q("UPDATE maps SET data=? WHERE id=?", [json.dumps(data), row["id"]])
        return row["id"], name, nbrs, False
    return q("INSERT INTO maps(name, mime, image, data) VALUES(?, '', ?, ?)", [name, b"", json.dumps(data)]).lastrowid, name, nbrs, True


def collect(src):
    """Lee un equipo y aplica sus umbrales. Devuelve (métricas, problemas, info)."""
    info = {}
    if src["kind"] == "hikvision":
        out, probs = p_hikvision(src)
    else:
        s = snmp_for(src)
        sys_ = s.get("1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.3.0", "1.3.6.1.2.1.1.5.0")
        info = {"descr": sys_["1.3.6.1.2.1.1.1.0"], "name": sys_["1.3.6.1.2.1.1.5.0"],
                "uptime": (sys_["1.3.6.1.2.1.1.3.0"] or 0) // 100}
        out, probs = [], []
        PROFILES[src["kind"]](s, out, probs)
        try:  # sin tabla de interfaces (o con una rara) se queda lo leído por el perfil
            info["ports"] = interfaces(s, src.get("id"), out, probs)
        except Exception as e:
            print("interfaces de", src["host"], "sin leer:", e)
    return limits(src, out, probs), probs, info


def limits(src, out, probs):
    """Redondea las lecturas y añade a probs las que pasan los umbrales del equipo."""
    out = [(k[:120], str(label)[:120], round(float(v), 2), u) for k, label, v, u in out]
    tmax, dmax = src.get("temp_max") or 65, src.get("disk_max") or 90
    for k, label, v, u in out:
        if u == "°C" and v > tmax:
            probs.append(f"{label}: {v:g} °C (límite {tmax:g})")
        if k.startswith("disk:") and v > dmax:
            probs.append(f"{label.rstrip(':')}: {v:.0f} % lleno (límite {dmax:g} %)")  # «C:» de Windows: sin «C::»
    return out


KITTY_LOST = "Kitty no responde: el equipo puede estar apagado o sin red"


def kitty_read(name, x):
    """Lo que cuenta Kitty -> (métricas, info), con tipos y tamaños acotados: llega de la red sin sesión."""
    x = x if isinstance(x, dict) else {}
    num = lambda v: v if isinstance(v, (int, float)) and not isinstance(v, bool) and 0 <= v < 2 ** 63 else None
    txt = lambda v, n=200: v.strip()[:n] if isinstance(v, str) else ""
    disks = [{"name": txt(d.get("name"), 60), "total": num(d.get("total")), "free": num(d.get("free"))}
             for d in (x.get("disks") if isinstance(x.get("disks"), list) else [])[:32] if isinstance(d, dict)]
    mt, mf = num(x.get("mem_total")), num(x.get("mem_free"))
    out = [("cpu", "CPU", min(100, num(x.get("load"))), "%")] if num(x.get("load")) is not None else []
    if mt and mf is not None and mf <= mt:
        out.append(("mem", "Memoria", 100 * (mt - mf) / mt, "%"))
    out += [("disk:" + d["name"], d["name"], 100 * (d["total"] - d["free"]) / d["total"], "%")
            for d in disks if d["name"] and d["total"] and d["free"] is not None and d["free"] <= d["total"]]
    info = {"descr": txt(x.get("osver")), "name": name, "uptime": int(num(x.get("uptime")) or 0), "model": txt(x.get("model")),
            "cpu": txt(x.get("cpu")), "cores": int(num(x.get("cores")) or 0), "mem_total": mt, "serial": txt(x.get("serial"), 100),
            "ips": [txt(i, 45) for i in (x.get("ips") if isinstance(x.get("ips"), list) else [])[:16] if isinstance(i, str)], "disks": disks}
    return out, info


def check_item(d):
    """Fin de garantía: vacío o una fecha AAAA-MM-DD de verdad (el aviso compara textos)."""
    w = d.get("warranty", "")
    if not isinstance(w, str):
        raise ValueError("fecha de garantía no válida")
    if w:
        try:
            datetime.strptime(w, "%Y-%m-%d")
        except ValueError:
            raise ValueError("fecha de garantía no válida: AAAA-MM-DD")


def warranties():
    """Una vez al día: avisa de las garantías que caducan dentro de 30 días y de las que caducan hoy."""
    today = time.strftime("%Y-%m-%d")
    if (q("SELECT v FROM meta WHERE k='warranty_day'").fetchone() or [None])[0] == today:
        return
    q("INSERT OR REPLACE INTO meta(k, v) VALUES('warranty_day', ?)", [today])
    rows = q("SELECT name, warranty FROM items WHERE warranty IN (date('now', 'localtime'), date('now', 'localtime', '+30 days')) "
             "ORDER BY warranty, name COLLATE NOCASE").fetchall()
    if rows and channels():
        notify("catlan: garantías que caducan", "\n".join(f"- {r['name']}: {'hoy' if r['warranty'] == today else 'el ' + r['warranty']}"
                                                         for r in rows) + "\n\n-- catlan")


def check_source(d, new=False):
    check_host({"host": d.get("host")} if new or "host" in d else {}, new)  # el intervalo se valida aquí, con otro rango
    if (new or "kind" in d) and d.get("kind", "generic") not in PROFILES:
        raise ValueError("tipo de equipo desconocido")
    if "port" in d and not (isinstance(d["port"], int) and 1 <= d["port"] <= 65535):
        raise ValueError("puerto no válido")
    if "every" in d and not (isinstance(d["every"], int) and 60 <= d["every"] <= 86400):
        raise ValueError("el intervalo va de 60 segundos a 1 día")
    for k in ("temp_max", "disk_max"):
        if k in d and not (isinstance(d[k], (int, float)) and 0 < d[k] <= 200):
            raise ValueError("los umbrales deben ser números entre 1 y 200")
    for k in ("community", "user", "pass", "label", "priv_pass"):
        if k in d and not (isinstance(d[k], str) and len(d[k]) <= 200):
            raise ValueError(f"{k} no válido")
    if "v3" in d and d["v3"] not in (0, 1):  # True/False también valen: son 1/0
        raise ValueError("v3 no válido")
    if "auth" in d and d["auth"] not in ("none", *AUTH) or "priv" in d and d["priv"] not in ("none", "aes"):
        raise ValueError("algoritmo SNMPv3 no admitido")
    if d.get("v3"):
        if "user" in d and not d["user"]:
            raise ValueError("SNMPv3 necesita un usuario")
        if d.get("auth") == "none" and d.get("priv", "none") != "none":
            raise ValueError("para cifrar, SNMPv3 exige también autenticación")
        if any(d.get(k) and len(d[k]) < 8 for k in ("pass", "priv_pass")):
            raise ValueError("las contraseñas SNMPv3 tienen al menos 8 caracteres")


def gather(src):
    try:
        out, probs, info = collect(src)
        err = None
    except Exception as e:
        out, probs, info, err = [], [], None, str(e)[:300] or e.__class__.__name__
    save_health(src, out, probs, info, err)


def save_health(src, out, probs, info, err):
    """Guarda una lectura (de SNMP o de un Kitty), el estado del equipo, y avisa si cambia."""
    state = "error" if err else "warn" if probs else "ok"
    if out:
        with lock:
            db.executemany("INSERT INTO metrics(source_id, key, label, value, unit) VALUES(?,?,?,?,?)",
                           [(src["id"], *m) for m in out])
            db.commit()
    q("UPDATE sources SET state=?, problems=?, error=?, info=COALESCE(?, info)"
      + (", since=CURRENT_TIMESTAMP" if state != src["state"] else "") + " WHERE id=?",
      [state, json.dumps(probs, ensure_ascii=False), err, json.dumps(info, ensure_ascii=False) if info else None, src["id"]])
    name = src["label"] or src.get("item_name") or src["host"]
    alert("sources", src, state, "ok", f"catlan: {name} vuelve a estar bien" if state == "ok" else f"catlan: {name}: {(probs or [err])[0]}",
          f"{name} ({src['host']}) ya no tiene avisos." if state == "ok" else f"{name} ({src['host']}):\n\n" + "\n".join(f"- {p}" for p in (probs or [err])))


SOURCES = "SELECT s.*, i.name AS item_name FROM sources s LEFT JOIN items i ON i.id = s.item"


def health():
    out, agents = [], {r[0]: r[1] for r in q("SELECT source, id FROM agents WHERE source IS NOT NULL")}
    for r in q(SOURCES + " ORDER BY COALESCE(NULLIF(s.label, ''), i.name, s.host) COLLATE NOCASE").fetchall():
        s = {k: v for k, v in dict(r).items() if k not in SECRET}
        s["problems"], s["info"], s["agent"] = json.loads(s["problems"] or "[]"), json.loads(s["info"] or "{}"), agents.get(r["id"])
        s["latest"] = [dict(m) for m in q("SELECT key, label, value, unit FROM metrics WHERE source_id=? AND ts = "
                                          "(SELECT max(ts) FROM metrics WHERE source_id=?) ORDER BY key", [r["id"], r["id"]])]
        out.append(s)
    return out


MAX_HOURS = 24 * KEEP_DAYS


def series(source, hours):
    """Histórico agrupado en ~300 puntos por serie, sea cual sea el rango. Más allá de 7 días solo quedan los resúmenes por hora."""
    step = max(60, int(hours * 3600 / 300))
    t, ts, v = ("metrics", "ts", "value") if hours <= 168 else ("metrics_h", "hour", "v")
    out = {}
    for r in q(f"SELECT key, label, unit, min({ts}) AS ts, avg({v}) AS v FROM {t} WHERE source_id=? AND {ts} > datetime('now', ?) "
               f"GROUP BY key, CAST(strftime('%s', {ts}) / ? AS INTEGER) ORDER BY ts", [source, f"-{hours} hours", step]):
        s = out.setdefault(r["key"], {"label": r["label"], "unit": r["unit"], "points": []})
        s["points"].append([r["ts"], round(r["v"], 2)])
    return out


def latency(hours):
    """Latencia media de cada dispositivo del monitor, agrupada en ~120 puntos."""
    step, out = max(60, int(hours * 3600 / 120)), {}
    t, ts = ("pings", "ts") if hours <= 168 else ("pings_h", "hour")
    for r in q(f"SELECT check_id, min({ts}) AS ts, avg(rtt) AS v FROM {t} WHERE {ts} > datetime('now', ?) AND rtt IS NOT NULL "
               f"GROUP BY check_id, CAST(strftime('%s', {ts}) / ? AS INTEGER) ORDER BY ts", [f"-{hours} hours", step]):
        out.setdefault(r["check_id"], []).append([r["ts"], round(r["v"], 2)])
    return out


# ── Descubrimiento: ping a toda una red y, a quien responde, SNMP y DNS inverso ──
VENDORS = {  # número de empresa (sysObjectID 1.3.6.1.4.1.N) -> fabricante y tipo probable
    "9": ("Cisco", "switch"), "11": ("HP", "switch"), "2636": ("Juniper", "router"), "4413": ("Ubiquiti", "switch"),
    "41112": ("Ubiquiti", "ap"), "14988": ("MikroTik", "router"), "14823": ("Aruba", "ap"), "25506": ("H3C", "switch"),
    "6574": ("Synology", "nas"), "24681": ("QNAP", "nas"), "12356": ("Fortinet", "firewall"), "25461": ("Palo Alto", "firewall"),
    "2604": ("Sophos", "firewall"), "311": ("Microsoft", "server"), "8072": ("Net-SNMP", "server"), "674": ("Dell", "server"),
    "232": ("HPE", "server"), "6876": ("VMware", "server"), "318": ("APC", "ups"), "534": ("Eaton", "ups"),
    "2435": ("Brother", "printer"), "367": ("Ricoh", "printer"), "1602": ("Canon", "printer"), "18334": ("Konica Minolta", "printer"),
    "253": ("Xerox", "printer"), "1347": ("Kyocera", "printer"), "39165": ("Hikvision", "camera"), "1004849": ("Dahua", "camera"),
}
WORDS = [("printer", r"printer|laserjet|officejet|mfp|impresora"), ("ap", r"access point|unifi ap|\buap\b|aironet|wireless"),
         ("firewall", r"firewall|fortigate|pfsense|opnsense|asa\b"), ("nas", r"synology|qnap|\bnas\b|diskstation|readynas"),
         ("ups", r"\bups\b|smart-ups"), ("camera", r"camera|ipc|nvr|dvr"), ("router", r"router|routeros|edgeos|ios xe"),
         ("switch", r"switch|catalyst|procurve|aruba"), ("server", r"linux|windows server|esxi|vmware|freebsd")]


def guess(descr, oid):
    """Fabricante y tipo probables de un equipo, por su sysObjectID y su sysDescr."""
    m = re.match(r"1\.3\.6\.1\.4\.1\.(\d+)", oid or "")
    vendor, kind = VENDORS.get(m.group(1), ("", "")) if m else ("", "")
    for k, rx in WORDS:  # la descripción manda: un HP puede ser impresora o switch
        if re.search(rx, descr or "", re.I):
            return vendor, k
    return vendor, kind


def identify(ip, community):
    out = {"ip": ip, "name": "", "descr": "", "vendor": "", "kind": "", "snmp": False}
    try:
        out["name"] = socket.gethostbyaddr(ip)[0]
    except OSError:
        pass
    try:  # un solo intento corto: quien no tiene SNMP no debe frenar el escaneo
        r = SNMP(ip, community, timeout=0.7).get("1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0", "1.3.6.1.2.1.1.5.0")
        out.update(snmp=True, descr=(r["1.3.6.1.2.1.1.1.0"] or "")[:200], name=r["1.3.6.1.2.1.1.5.0"] or out["name"])
        out["vendor"], out["kind"] = guess(out["descr"], r["1.3.6.1.2.1.1.2.0"])
    except Exception:
        pass
    return out


def discover(net, community):
    hosts = [str(h) for h in net.hosts()]
    with ThreadPoolExecutor(64) as pool:
        alive = [(h, rtt) for h, (up, rtt) in zip(hosts, pool.map(ping, hosts)) if up]
        found = list(pool.map(lambda x: {**identify(x[0], community), "rtt": x[1]}, alive))
    items = {r["ip"]: r["id"] for r in q("SELECT id, ip FROM items WHERE ip != ''")}
    watched = {r["host"] for r in q("SELECT host FROM checks")}
    return [{**f, "item": items.get(f["ip"]), "watched": f["ip"] in watched} for f in found]


# ── Incidencias: asignadas a una persona y/o a un grupo, con su historial de seguimiento ──
INC_STATUS = ("abierta", "en curso", "en espera", "resuelta", "cerrada")
INC_PRIO = ("baja", "media", "alta", "crítica")
INC_COLS = ("title", "body", "status", "priority", "assignee", "grp", "item", "parent")
DONE = ("resuelta", "cerrada")
INC = ("SELECT n.*, u.name AS assignee_name, g.name AS grp_name, i.name AS item_name, a.name AS author_name, "
       "(SELECT count(*) FROM notes WHERE incident = n.id AND change = 0) AS notes, p.title AS parent_title, "
       "(SELECT count(*) FROM incidents h WHERE h.parent = n.id) AS children FROM incidents n LEFT JOIN incidents p ON p.id = n.parent "
       "LEFT JOIN users u ON u.id = n.assignee "
       "LEFT JOIN groups g ON g.id = n.grp LEFT JOIN items i ON i.id = n.item LEFT JOIN users a ON a.id = n.author")


def check_incident(d, rid=None):
    if "title" in d and not (isinstance(d["title"], str) and 1 <= len(d["title"].strip()) <= 200):
        raise ValueError("el título va de 1 a 200 caracteres")
    if "body" in d and not (isinstance(d["body"], str) and len(d["body"]) <= 20000):
        raise ValueError("descripción demasiado larga")
    if "status" in d and d["status"] not in INC_STATUS or "priority" in d and d["priority"] not in INC_PRIO:
        raise ValueError("estado o prioridad no válidos")
    for k, table in (("assignee", "users"), ("grp", "groups"), ("item", "items"), ("parent", "incidents")):
        if d.get(k) is not None and not (type(d[k]) is int and q(f"SELECT 1 FROM {table} WHERE id=?", [d[k]]).fetchone()):
            raise ValueError(f"{ {'assignee': 'la persona', 'grp': 'el grupo', 'item': 'el equipo', 'parent': 'la incidencia padre'}[k]} no existe")
    p = d.get("parent")
    while rid and p:  # subiendo por los padres no se puede llegar a ella misma: sería un círculo
        if p == int(rid):
            raise ValueError("una incidencia no puede colgar de sí misma ni de una de sus hijas")
        p = q("SELECT parent FROM incidents WHERE id=?", [p]).fetchone()[0]


def refs(item):
    """Dónde aparece un equipo: páginas/notas con [[#id]] y esquemas/racks que lo enlazan."""
    tag = f"%[[#{item}]]%"
    in_map = "EXISTS (SELECT 1 FROM json_each(data, ?) WHERE json_extract(value, '$.item') = ?)"
    return {
        "pages": [dict(r) for r in q("SELECT id, title FROM pages WHERE body LIKE ? ORDER BY title", [tag])],
        "items": [dict(r) for r in q("SELECT id, name FROM items WHERE notes LIKE ? AND id != ? ORDER BY name", [tag, item])],
        "maps": [dict(r) for r in q(f"SELECT id, name, json_extract(data, '$.type') AS type FROM maps "
                                    f"WHERE {in_map} OR {in_map} ORDER BY name", ["$.nodes", item, "$.devices", item])],
        "incidents": [dict(r) for r in q("SELECT id, title, status FROM incidents WHERE item=? ORDER BY id DESC", [item])],
    }


def drop_source(a):
    """Kitty rechazado u olvidado: fuera de Salud, con su historial (si no, avisaría de que «no responde»)."""
    if a["source"] and q("SELECT 1 FROM sources WHERE id=? AND kind='kitty'", [a["source"]]).fetchone():
        for t, col in (("sources", "id"), ("metrics", "source_id"), ("metrics_h", "source_id")):
            q(f"DELETE FROM {t} WHERE {col}=?", [a["source"]])
    q("UPDATE agents SET source=NULL WHERE id=?", [a["id"]])


class H(BaseHTTPRequestHandler):
    def send(self, code, body=b"", mime="application/json", cookie=None, headers=None):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(code)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def authed(self, free, pending):
        """Sesión por cookie (navegador) o Basic (scripts). Sin WWW-Authenticate: el login es la página de catlan."""
        self.uid, self.user, self.admin, self.token, must = None, "", False, "", 0
        c = SimpleCookie(self.headers.get("Cookie", "")).get(COOKIE)
        h, ip = self.headers.get("Authorization", ""), self.client_address[0]
        if c and c.value:
            self.token = sha(c.value)
            u = q("SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=? AND s.expires > datetime('now')", [self.token]).fetchone()
        elif h.startswith("Basic ") and not throttled(ip):
            try:
                name, pw = base64.b64decode(h[6:]).decode().split(":", 1)
                uid = login_ok(name[:100], pw[:200])
            except Exception:
                uid = None
            if not uid:
                FAILS[ip].append(time.time())
            u = uid and q("SELECT * FROM users WHERE id=?", [uid]).fetchone()
        else:
            u = None
        if u:
            self.uid, self.user, self.admin, must = u["id"], u["name"], bool(u["admin"]), u["must_change"]
        if free or u and (not must or pending):
            return True
        if u:  # contraseña provisional (admin/admin incluido): solo se puede cambiarla o salir
            return self.send(403, {"error": "cambia tu contraseña para continuar", "must_change": True}) or False
        return self.send(401, {"error": "inicia sesión"}) or False

    def log(self, action, kind, ref, name, data):
        snap = json.dumps(data, ensure_ascii=False)
        last = q("SELECT id, action, who, ts > datetime('now', '-60 seconds') AS fresh FROM log "
                 "WHERE kind=? AND ref=? ORDER BY id DESC LIMIT 1", [kind, ref]).fetchone()
        # esquemas y racks se autoguardan al arrastrar: agrupa ediciones seguidas en una sola entrada
        if (kind in ("map", "rack") and action == "editar" and last and last["action"] == "editar"
                and last["who"] == self.user and last["fresh"]):
            q("UPDATE log SET ts=CURRENT_TIMESTAMP, name=?, data=? WHERE id=?", [name, snap, last["id"]])
        else:
            q("INSERT INTO log(who, action, kind, ref, name, data) VALUES(?,?,?,?,?,?)",
              [self.user, action, kind, ref, name, snap])

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("demasiado grande")
        return self.rfile.read(n)

    def route(self, method):
        # Escrituras desde otra web (CSRF): el navegador pone Origin; si no es este servidor, fuera.
        # Detrás de un proxy, este debe conservar la cabecera Host original.
        origin = self.headers.get("Origin")
        if method != "GET" and origin and urlparse(origin).netloc != self.headers.get("Host"):
            return self.send(403, {"error": "origen no permitido"})
        url = urlparse(self.path)
        parts = [p for p in url.path.split("/") if p]
        api = parts[:1] == ["api"]
        free = not api or parts[1:] in (["login"], ["agent"]) and method == "POST"  # la página, el login y Kitty, sin sesión
        pending = api and (parts[1:2] == ["logout"] or parts[1:3] in (["me"], ["me", "password"]))  # con contraseña provisional
        if not self.authed(free, pending):
            return
        if method != "GET" and not free and not pending and self.uid and readonly(self.uid):
            return self.send(403, {"error": "tu usuario es de solo vista"})
        try:
            if parts == ["kitty.ps1"] and method == "GET":  # instalador de Kitty con esta dirección y este id (catlan sin sesión, como la página)
                host = self.headers.get("Host", "")
                if not HOST.fullmatch(host):  # va dentro de un script que se ejecuta como administrador
                    return self.send(400, b"Host no valido", "text/plain; charset=utf-8")
                ps = (HERE / "kitty.ps1").read_text(encoding="utf-8").replace("{{URL}}", "http://" + host).replace("{{ID}}", INSTANCE)
                return self.send(200, ps.encode(), "text/plain; charset=utf-8")
            if not parts or parts[0] != "api":
                return self.send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
            res, rid = parts[1] if len(parts) > 1 else "", parts[2] if len(parts) > 2 else None
            if res in ("login", "logout", "me", "users"):
                return self.account(method, res, rid)
            if res == "backup" and method == "GET":  # copia de seguridad descargable (solo admin)
                if not self.admin:
                    return self.send(403, {"error": "solo para administradores"})
                tmp = DATA / f".descarga-{secrets.token_hex(6)}.db"
                try:
                    with lock:  # la conexión es compartida: nada de copiar a medias mientras otro hilo escribe
                        backup_to(tmp)
                    data = tmp.read_bytes()
                finally:
                    tmp.unlink(missing_ok=True)
                self.log("descargar", "db", 0, "una copia de seguridad", {"bytes": len(data)})
                return self.send(200, data, "application/vnd.sqlite3",
                                 headers={"Content-Disposition": f'attachment; filename="catlan-{time.strftime("%Y%m%d-%H%M")}.db"'})
            if res == "alerts":  # canales de aviso: solo admin; los secretos ni salen ni se pisan con un campo vacío
                if not self.admin:
                    return self.send(403, {"error": "solo para administradores"})
                if method == "GET":
                    return self.send(200, alerts_view())
                if method != "PUT":
                    return self.send(405, {"error": "método no permitido"})
                b = json.loads(self.body() or b"{}")
                if not isinstance(b, dict):
                    raise ValueError("envía un objeto")
                saved = saved_alerts()
                for k in ALERT_KEYS:
                    if k not in b:
                        continue
                    v = b[k]
                    if v is None:  # quitar lo guardado (vuelve la variable de entorno, si la hay)
                        saved.pop(k, None)
                        continue
                    if not (isinstance(v, str) and len(v) <= 600):
                        raise ValueError(f"{k} no válido")
                    v = v.strip()
                    if not v:
                        if k not in ALERT_SECRET:
                            saved.pop(k, None)
                        continue  # secreto vacío = conservar el guardado
                    check_alert(k, v)
                    saved[k] = v
                q("INSERT OR REPLACE INTO meta(k, v) VALUES('alerts', ?)", [json.dumps(saved)])
                apply_alerts()
                self.log("editar", "alerts", 0, "los avisos", {"campos": sorted(k for k in b if k in ALERT_KEYS)})
                return self.send(200, alerts_view())
            if res == "wipe" and method == "POST":
                return self.wipe()
            if res == "agent" and method == "POST":
                return self.agent_hello()
            if res == "agents":
                return self.agents(method, rid)
            if res == "groups":
                return self.groups(method, rid)
            if res == "incidents":
                return self.incidents(method, rid, parts)
            if res == "maps":
                return self.maps(method, rid, parts, parse_qs(url.query))
            if res == "log" and method == "GET":
                f = parse_qs(url.query)
                where, args = ("WHERE kind=? AND ref=?", [f["kind"][0], int(f["ref"][0])]) if "kind" in f and "ref" in f else ("", [])
                return self.send(200, [dict(r) for r in q(f"SELECT * FROM log {where} ORDER BY id DESC LIMIT 300", args)])
            if res == "items" and method == "GET" and len(parts) > 3 and parts[3] == "refs":
                return self.send(200, refs(int(rid)))
            if res == "monitor" and method == "GET" and rid is None:
                return self.send(200, monitor_state())
            if res == "monitor" and method == "POST" and rid == "test":
                if not channels():
                    return self.send(400, {"error": "ningún canal de aviso configurado: hazlo en Opciones → Avisos"})
                return self.send(200, notify("catlan: aviso de prueba", "Si lees esto, los avisos de catlan llegan por aquí.\n\n-- catlan"))
            if res in ("checks", "sources") and method == "POST" and len(parts) > 3 and parts[3] == "mute":
                m = (json.loads(self.body() or b"{}") or {}).get("minutes")
                if not (type(m) is int and 0 <= m <= 10080):
                    raise ValueError("silenciar de 0 minutos a 7 días")
                cur = q(f"UPDATE {res} SET mute_until = CASE WHEN ? > 0 THEN datetime('now', '+' || ? || ' minutes') END WHERE id=?", [m, m, rid])
                if not cur.rowcount:
                    return self.send(404, {"error": "no existe"})
                row = q(f"SELECT id, label, host, mute_until FROM {res} WHERE id=?", [rid]).fetchone()
                self.log("silenciar" if m else "quitar silencio", KIND[res], row["id"], row["label"] or row["host"], {"minutes": m})
                return self.send(200, dict(row))
            if res == "ping" and method == "POST":
                b = json.loads(self.body() or b"{}")
                d = {"host": b.get("host") if isinstance(b, dict) else None}
                check_host(d, new=True)
                up, rtt = ping(d["host"])
                return self.send(200, {"up": up, "rtt": rtt})
            if res == "sounds":
                return self.sounds(method, rid, parts, parse_qs(url.query))
            if res == "dashboard" and method == "GET":
                row = q("SELECT data FROM dash WHERE id=1").fetchone()
                return self.send(200, json.loads(row["data"]) if row else None)  # null: el frontal pone uno por defecto
            if res == "dashboard" and method == "PUT":
                d = json.loads(self.body() or b"{}")
                check_dash(d)
                q("INSERT OR REPLACE INTO dash(id, data) VALUES(1, ?)", [json.dumps(d)])
                return self.send(204)
            if res == "discover" and method == "POST":
                b = json.loads(self.body() or b"{}")
                try:
                    net = ipaddress.ip_network(str(b.get("net", "")).strip(), strict=False)
                except ValueError:
                    raise ValueError("red no válida: escribe algo como 10.0.0.0/24")
                if net.version != 4 or net.num_addresses > 1024:
                    raise ValueError("solo redes IPv4 de hasta 1024 direcciones (/22)")
                community = b.get("community") or "public"
                if not (isinstance(community, str) and len(community) <= 100):
                    raise ValueError("comunidad no válida")
                return self.send(200, discover(net, community))
            if res == "latency" and method == "GET":
                return self.send(200, latency(min(MAX_HOURS, max(1, int(parse_qs(url.query).get("hours", ["24"])[0])))))
            if res == "sla" and method == "GET":
                return self.send(200, sla(parse_qs(url.query).get("month", [time.strftime("%Y-%m")])[0]))
            if res == "health" and method == "GET":
                return self.send(200, health())
            if res == "metrics" and method == "GET":
                f = parse_qs(url.query)
                return self.send(200, series(int((f.get("source") or ["0"])[0]), min(MAX_HOURS, max(1, int(f.get("hours", ["24"])[0])))))
            if res == "sources" and method == "POST" and len(parts) > 3 and parts[3] == "topology":
                src = q("SELECT * FROM sources WHERE id=?", [rid]).fetchone()
                if not src or src["kind"] in ("kitty", "hikvision"):
                    return self.send(404 if not src else 400, {"error": "no existe" if not src else "solo los equipos que se leen por SNMP"})
                try:
                    mid, name, nbrs, new = auto_map(dict(src))
                except (TimeoutError, OSError, ValueError) as e:
                    return self.send(400, {"error": str(e) or e.__class__.__name__})
                if not nbrs:
                    return self.send(400, {"error": "el equipo no ha contado ningún vecino: activa LLDP o CDP en el switch y comprueba que SNMP deja leer las tablas BRIDGE/LLDP"})
                self.log("crear" if new else "editar", "map", mid, name, {"auto": True, "vecinos": len(nbrs)})
                return self.send(200, {"map": mid, "name": name, "neighbors": nbrs})
            if res == "sources" and method == "POST" and rid == "test":  # probar sin guardar
                b = json.loads(self.body() or b"{}")
                if not isinstance(b, dict):
                    raise ValueError("envía un objeto")
                d = {k: v for k, v in b.items() if k in TABLES["sources"]}
                if isinstance(b.get("id"), int):  # editando: las credenciales vacías son las guardadas
                    old = q(f"SELECT {', '.join(SECRET)} FROM sources WHERE id=?", [b["id"]]).fetchone()
                    for k in SECRET:
                        if old and not d.get(k):
                            d[k] = old[k]
                check_source(d, new=True)
                try:
                    out, probs, info = collect({"kind": "generic", **d})
                except Exception as e:
                    return self.send(400, {"error": str(e) or e.__class__.__name__})
                return self.send(200, {"metrics": out, "problems": probs, "info": info})
            if res not in TABLES:
                return self.send(404, {"error": "no existe"})
            cols = TABLES[res]
            pub = lambda r: {k: v for k, v in dict(r).items() if k not in SECRET}
            if method == "GET" and rid is None:
                order = {"pages": "title", "items": "name"}.get(res, "id")
                return self.send(200, [pub(r) for r in q(f"SELECT * FROM {res} ORDER BY {order} COLLATE NOCASE")])
            if method == "POST" and rid is None:  # un objeto, o una lista para crear en serie
                body = json.loads(self.body() or b"{}")
                batch = body if isinstance(body, list) else [body]
                if not batch or len(batch) > 1000 or not all(isinstance(b, dict) for b in batch):
                    raise ValueError("envía un objeto o una lista de 1 a 1000 objetos")
                for b in batch:  # todo validado antes de guardar nada
                    if res == "items":
                        check_item(b)
                    if res in ("checks", "sources"):
                        (check_host if res == "checks" else check_source)({k: v for k, v in b.items() if k in cols}, new=True)
                out = []
                for b in batch:
                    d = {k: v for k, v in b.items() if k in cols}
                    keys = list(d) or [cols[0]]
                    cur = q(f"INSERT INTO {res}({','.join(keys)}) VALUES({','.join('?' * len(keys))})",
                            [d.get(k, "") for k in keys])
                    row = pub(q(f"SELECT * FROM {res} WHERE id=?", [cur.lastrowid]).fetchone())
                    self.log("crear", KIND[res], row["id"], row[cols[0]], row)
                    out.append(row)
                return self.send(201, out if isinstance(body, list) else out[0])
            if method == "GET":
                row = q(f"SELECT * FROM {res} WHERE id=?", [rid]).fetchone()
                return self.send(200, pub(row)) if row else self.send(404, {"error": "no existe"})
            if method == "PUT":
                raw = json.loads(self.body() or b"{}")
                seen = raw.get("_seen") if isinstance(raw, dict) else None  # la versión que abrió quien guarda
                d = {k: v for k, v in raw.items() if k in cols}
                if res == "items":
                    check_item(d)
                if res == "checks":
                    check_host(d)
                    if "host" in d:
                        d.update(state=None, fails=0)  # otro host: su estado anterior no vale
                if res == "sources":
                    for k in SECRET:  # vacío = conservar la credencial guardada
                        if d.get(k) == "":
                            d.pop(k)
                    check_source(d)
                    d["last"] = None  # leer ya con la configuración nueva
                if d:  # con _seen, solo si nadie lo cambió desde entonces (en la misma sentencia: atómico)
                    cur = q(f"UPDATE {res} SET {','.join(k + '=?' for k in d)}, updated=CURRENT_TIMESTAMP WHERE id=?"
                            + (" AND updated=?" if seen is not None else ""), [*d.values(), rid, *([seen] if seen is not None else [])])
                    if not cur.rowcount and seen is not None and (now := q(f"SELECT updated FROM {res} WHERE id=?", [rid]).fetchone()):
                        who = q("SELECT who FROM log WHERE kind=? AND ref=? ORDER BY id DESC LIMIT 1", [KIND[res], rid]).fetchone()
                        return self.send(409, {"error": f"{who['who'] if who and who['who'] else 'Alguien'} lo cambió mientras lo editabas.",
                                               "updated": now["updated"]})
                row = q(f"SELECT * FROM {res} WHERE id=?", [rid]).fetchone()
                if not row:
                    return self.send(404, {"error": "no existe"})
                if d:
                    self.log("editar", KIND[res], row["id"], row[cols[0]], pub(row))
                return self.send(200, pub(row))
            if method == "DELETE":
                row = q(f"SELECT * FROM {res} WHERE id=?", [rid]).fetchone()
                q(f"DELETE FROM {res} WHERE id=?", [rid])
                if res in ("checks", "sources"):  # su historial de lecturas se va con él
                    t, col = ("pings", "check_id") if res == "checks" else ("metrics", "source_id")
                    q(f"DELETE FROM {t} WHERE {col}=?", [rid])
                    q(f"DELETE FROM {t}_h WHERE {col}=?", [rid])
                if row:  # la foto del borrado queda en el historial por si hay que recuperarlo
                    self.log("borrar", KIND[res], row["id"], row[cols[0]], pub(row))
                return self.send(204)
            self.send(405, {"error": "método no permitido"})
        except (ValueError, json.JSONDecodeError) as e:
            self.send(400, {"error": str(e)})
        except (AttributeError, TypeError, KeyError) as e:  # datos con otra forma (una lista donde va un objeto…)
            print("400 por datos raros en", self.path, repr(e))
            self.send(400, {"error": "los datos no tienen la forma esperada"})

    def wipe(self):
        """Borra todo el contenido. Solo un admin y con su contraseña; antes, una copia completa en la carpeta de datos."""
        if not self.admin:
            return self.send(403, {"error": "solo para administradores"})
        ip = self.client_address[0]
        if throttled(ip):
            return self.send(429, {"error": "demasiados intentos: espera 15 minutos"})
        b = json.loads(self.body() or b"{}")
        pw = b.get("pass") if isinstance(b, dict) else None
        if not (isinstance(pw, str) and pw_ok(pw[:200], q("SELECT hash FROM users WHERE id=?", [self.uid]).fetchone()["hash"])):
            FAILS[ip].append(time.time())  # cuenta como intento fallido: nadie prueba contraseñas por aquí
            return self.send(403, {"error": "contraseña incorrecta"})
        copy = f"catlan-antes-de-borrar-{time.strftime('%Y%m%d-%H%M%S')}.db"
        with lock:
            backup_to(DATA / copy)
            db.executescript("BEGIN;" + "".join(f"DELETE FROM {t};" for t in WIPE) + "COMMIT;")
        IF_PREV.clear()
        self.log("vaciar", "db", 0, "la base de datos", {"copia": copy})
        return self.send(200, {"copy": copy})

    def agent_hello(self):
        """Kitty se presenta con su clave: pendiente hasta que un admin lo acepta; aceptado, catlan mantiene su ficha."""
        b = json.loads(self.body() or b"{}")
        if not (isinstance(b, dict) and isinstance(b.get("key"), str) and 32 <= len(b["key"]) <= 128):
            raise ValueError("falta la clave de Kitty")
        f = {k: (b.get(k) if isinstance(b.get(k), str) else "").strip()[:100] for k in AGENT_FACTS}
        f["ip"] = f["ip"] or self.client_address[0]  # el Kitty de PowerShell no la calcula: la de su conexión
        if not f["name"]:
            raise ValueError("falta el nombre del equipo")
        key = sha(b["key"])
        a = q("SELECT * FROM agents WHERE key=?", [key]).fetchone()
        if not a:
            if q("SELECT COUNT(*) FROM agents WHERE state='pendiente'").fetchone()[0] >= 100:  # sin sesión: que nadie llene la tabla
                return self.send(429, {"error": "demasiados Kitty pendientes de aceptar"})
            q(f"INSERT INTO agents(key, {', '.join(f)}, seen) VALUES(?, {', '.join('?' * len(f))}, CURRENT_TIMESTAMP)", [key, *f.values()])
            return self.send(200, {"state": "pendiente", "catlan": INSTANCE})
        q(f"UPDATE agents SET {', '.join(k + '=?' for k in f)}, seen=CURRENT_TIMESTAMP WHERE id=?", [*f.values(), a["id"]])
        if a["state"] != "adoptado":
            return self.send(200, {"state": a["state"], "catlan": INSTANCE})
        self.user = "Kitty · " + f["name"]
        item, every = self.agent_item(a, f), b["every"] * 60 if type(b.get("every")) is int and 1 <= b["every"] <= 1440 else 300
        src = a["source"] and q(SOURCES + " WHERE s.id=? AND s.kind='kitty'", [a["source"]]).fetchone()
        if not src:  # su ficha de Salud: la primera vez, o si la borraron
            sid = q("INSERT INTO sources(host, item, kind, every) VALUES(?, ?, 'kitty', ?)", [f["ip"] or f["name"], item, every]).lastrowid
            q("UPDATE agents SET source=? WHERE id=?", [sid, a["id"]])
            src = q(SOURCES + " WHERE s.id=?", [sid]).fetchone()
        q("UPDATE sources SET host=?, item=?, every=?, last=CURRENT_TIMESTAMP WHERE id=?", [f["ip"] or f["name"], item, every, src["id"]])
        (out, info), probs = kitty_read(f["name"], b.get("facts")), []
        save_health(dict(src), limits(dict(src), out, probs), probs, info, None)
        return self.send(200, {"state": "adoptado", "item": item, "catlan": INSTANCE})

    def agent_item(self, a, f):
        """La ficha de este Kitty: la suya, o una con su nº de serie o su nombre (inventariado a mano), o una nueva.
        Solo cambia la IP y el nº de serie: nombre, tipo, ubicación y notas son del usuario."""
        it = a["item"] and q("SELECT * FROM items WHERE id=?", [a["item"]]).fetchone()
        if not it:
            it = (f["serial"] and q("SELECT * FROM items WHERE serial=? ORDER BY id LIMIT 1", [f["serial"]]).fetchone()
                  or q("SELECT * FROM items WHERE name=? COLLATE NOCASE ORDER BY id LIMIT 1", [f["name"]]).fetchone())
            if not it:
                rid = q("INSERT INTO items(name, kind, ip, serial, status, notes) VALUES(?,?,?,?,'activo',?)",
                        [f["name"], f["kind"], f["ip"], f["serial"], f"Alta automática de Kitty ({f['os']})."]).lastrowid
                it = q("SELECT * FROM items WHERE id=?", [rid]).fetchone()
                self.log("crear", "item", rid, it["name"], dict(it))
            q("UPDATE agents SET item=? WHERE id=?", [it["id"], a["id"]])
        d = {k: f[k] for k in ("ip", "serial") if f[k] and f[k] != it[k]}
        if d:  # sin cambios no se escribe: cada edición deja una entrada en Actividad
            q(f"UPDATE items SET {', '.join(k + '=?' for k in d)}, updated=CURRENT_TIMESTAMP WHERE id=?", [*d.values(), it["id"]])
            self.log("editar", "item", it["id"], it["name"], dict(q("SELECT * FROM items WHERE id=?", [it["id"]]).fetchone()))
        return it["id"]

    def agents(self, method, rid):
        if not self.admin:  # aceptar un Kitty es dejar entrar un equipo
            return self.send(403, {"error": "solo para administradores"})
        if method == "GET" and rid is None:
            return self.send(200, [{**{k: v for k, v in dict(r).items() if k != "key"}, "code": r["key"][:8]}
                                   for r in q("SELECT * FROM agents ORDER BY state != 'pendiente', name COLLATE NOCASE")])
        a = q("SELECT * FROM agents WHERE id=?", [rid]).fetchone()
        if not a:
            return self.send(404, {"error": "no existe"})
        if method == "PUT":
            st = (json.loads(self.body() or b"{}") or {}).get("state")
            if st not in ("adoptado", "rechazado"):
                raise ValueError("estado no válido")
            q("UPDATE agents SET state=? WHERE id=?", [st, a["id"]])
            if st == "rechazado":
                drop_source(a)
            self.log("aceptar" if st == "adoptado" else "rechazar", "agent", a["id"], a["name"], {"ip": a["ip"], "code": a["key"][:8]})
            item = self.agent_item(a, {k: a[k] or "" for k in AGENT_FACTS}) if st == "adoptado" else None  # su ficha ya, sin esperar a Kitty
            return self.send(200, {"state": st, "item": item})
        if method == "DELETE":  # olvidarlo: si sigue instalado, volverá a pedir entrada
            drop_source(a)
            q("DELETE FROM agents WHERE id=?", [a["id"]])
            self.log("olvidar", "agent", a["id"], a["name"], {"ip": a["ip"], "code": a["key"][:8]})
            return self.send(204)
        self.send(405, {"error": "método no permitido"})

    def groups(self, method, rid):
        if method == "GET":  # todos: hace falta para asignar incidencias
            return self.send(200, [{**dict(g), "members": [m[0] for m in q("SELECT user_id FROM members WHERE group_id=?", [g["id"]])]}
                                   for g in q("SELECT * FROM groups ORDER BY name COLLATE NOCASE")])
        if not self.admin:
            return self.send(403, {"error": "solo para administradores"})
        b = json.loads(self.body() or b"{}") if method != "DELETE" else {}
        users = {r[0] for r in q("SELECT id FROM users")}

        def check(x, new):
            if not isinstance(x, dict):
                raise ValueError("envía un objeto")
            if (new or "name" in x) and not (isinstance(x.get("name"), str) and 1 <= len(x["name"].strip()) <= 60):
                raise ValueError("el nombre del grupo va de 1 a 60 caracteres")
            if "role" in x and x["role"] not in ("edit", "view"):
                raise ValueError("permiso no válido")
            if "members" in x and not (isinstance(x["members"], list) and all(type(m) is int and m in users for m in x["members"])):
                raise ValueError("miembros no válidos")
        if method == "POST" and rid is None and isinstance(b, list):  # varios grupos de una vez, todo validado antes
            taken, seen = {r[0].lower() for r in q("SELECT name FROM groups")}, set()
            if not 1 <= len(b) <= 100:
                raise ValueError("de 1 a 100 grupos a la vez")
            for x in b:
                check(x, True)
                k = x["name"].strip().lower()
                if k in taken | seen:
                    raise ValueError(f"{'ya existe' if k in taken else 'repetido en la lista'}: {x['name'].strip()}")
                seen.add(k)
            out = []
            for x in b:
                gid = q("INSERT INTO groups(name, role) VALUES(?, ?)", [x["name"].strip(), x.get("role", "edit")]).lastrowid
                for m in set(x.get("members", [])):
                    q("INSERT INTO members(group_id, user_id) VALUES(?, ?)", [gid, m])
                self.log("crear", "group", gid, x["name"].strip(), x)
                out.append(dict(q("SELECT * FROM groups WHERE id=?", [gid]).fetchone()))
            return self.send(201, out)
        if method != "DELETE":
            check(b, method == "POST")
        if method == "POST" and rid is None:
            try:
                gid = q("INSERT INTO groups(name, role) VALUES(?, ?)", [str(b.get("name", "")).strip(), b.get("role", "edit")]).lastrowid
            except sqlite3.IntegrityError:
                raise ValueError("ese grupo ya existe")
        else:
            gid = rid and q("SELECT id FROM groups WHERE id=?", [rid]).fetchone()
            if not gid:
                return self.send(404, {"error": "no existe"})
            gid = gid[0]
        if method == "DELETE":
            name = q("SELECT name FROM groups WHERE id=?", [gid]).fetchone()[0]
            q("UPDATE incidents SET grp=NULL WHERE grp=?", [gid])
            q("DELETE FROM members WHERE group_id=?", [gid])
            q("DELETE FROM groups WHERE id=?", [gid])
            self.log("borrar", "group", gid, name, {})
            return self.send(204)
        if method == "PUT":
            for k in ("name", "role"):
                if k in b:
                    try:
                        q(f"UPDATE groups SET {k}=? WHERE id=?", [b[k].strip() if k == "name" else b[k], gid])
                    except sqlite3.IntegrityError:
                        raise ValueError("ese grupo ya existe")
        if "members" in b:
            q("DELETE FROM members WHERE group_id=?", [gid])
            for m in set(b["members"]):
                q("INSERT INTO members(group_id, user_id) VALUES(?, ?)", [gid, m])
        g = dict(q("SELECT * FROM groups WHERE id=?", [gid]).fetchone())
        self.log("crear" if method == "POST" else "editar", "group", gid, g["name"], b)
        return self.send(201 if method == "POST" else 200, g)

    def note(self, inc, text, change=0):
        q("INSERT INTO notes(incident, who, text, change) VALUES(?,?,?,?)", [inc, self.user, text, change])
        q("UPDATE incidents SET updated=CURRENT_TIMESTAMP WHERE id=?", [inc])

    def close_children(self, inc, status):
        """Resuelta (o cerrada) la padre, sus hijas abiertas también, y las hijas de estas. Devuelve cuántas."""
        n = 0
        for kid in q("SELECT id, title, status FROM incidents WHERE parent=?", [inc]).fetchall():
            if kid["status"] not in DONE:  # las ya resueltas se quedan como están, pero se baja igual: sus hijas pueden seguir abiertas
                q("UPDATE incidents SET status=? WHERE id=?", [status, kid["id"]])
                self.note(kid["id"], f"pasó a «{status}» con su incidencia padre #{inc}", 1)
                self.log("editar", "incident", kid["id"], kid["title"], {"status": status, "por la padre": inc})
                n += 1
            n += self.close_children(kid["id"], status)
        return n

    def incidents(self, method, rid, parts):
        if method == "GET" and rid is None:
            return self.send(200, [dict(r) for r in q(INC + " ORDER BY n.status IN ('resuelta', 'cerrada'), CASE n.priority WHEN 'crítica' THEN 0 "
                                                         "WHEN 'alta' THEN 1 WHEN 'media' THEN 2 ELSE 3 END, n.updated DESC")])
        b = json.loads(self.body() or b"{}") if method in ("POST", "PUT") else {}
        if not isinstance(b, dict):
            raise ValueError("envía un objeto")
        d = {k: b[k] for k in INC_COLS if k in b}
        if method == "POST" and rid is None:
            check_incident({"title": "", **d})
            cur = q(f"INSERT INTO incidents({', '.join(d)}, author) VALUES({', '.join('?' * len(d))}, ?)", [*d.values(), self.uid])
            self.note(cur.lastrowid, "abrió la incidencia", 1)
            self.log("crear", "incident", cur.lastrowid, d["title"], d)
            row = q(INC + " WHERE n.id=?", [cur.lastrowid]).fetchone()
            if row["priority"] == "crítica":  # lo urgente sale por correo, Telegram o webhook
                notify(f"catlan: incidencia crítica #{row['id']}: {row['title']}",
                       f"Abierta por {self.user}" + (f", asignada a {row['assignee_name'] or row['grp_name']}" if row["assignee"] or row["grp"] else "") + ".\n\n-- catlan")
            return self.send(201, dict(row))
        row = q(INC + " WHERE n.id=?", [rid]).fetchone()
        if not row:
            return self.send(404, {"error": "no existe"})
        if method == "GET" and len(parts) == 3:
            return self.send(200, {**dict(row), "history": [dict(r) for r in q("SELECT * FROM notes WHERE incident=? ORDER BY id", [rid])],
                                   "kids": [dict(r) for r in q(INC + " WHERE n.parent=? ORDER BY n.id", [rid])]})
        if method == "POST" and parts[3:] == ["notes"]:
            t = b.get("text")
            if not (isinstance(t, str) and 1 <= len(t.strip()) <= 5000):
                raise ValueError("la nota va de 1 a 5000 caracteres")
            self.note(row["id"], t.strip())
            return self.send(201, dict(q("SELECT * FROM notes WHERE id = (SELECT max(id) FROM notes WHERE incident=?)", [row["id"]]).fetchone()))
        if method == "PUT":
            check_incident(d, row["id"])
            d = {k: v for k, v in d.items() if v != row[k]}
            if d:
                q(f"UPDATE incidents SET {', '.join(k + '=?' for k in d)} WHERE id=?", [*d.values(), row["id"]])
                now = q(INC + " WHERE n.id=?", [row["id"]]).fetchone()
                say = {"status": f"cambió el estado a «{now['status']}»", "priority": f"cambió la prioridad a «{now['priority']}»",
                       "assignee": f"asignó a {now['assignee_name']}" if now["assignee"] else "quitó la persona asignada",
                       "grp": f"pasó al grupo {now['grp_name']}" if now["grp"] else "quitó el grupo",
                       "item": f"enlazó el equipo {now['item_name']}" if now["item"] else "quitó el equipo", "title": "cambió el título", "body": "editó la descripción",
                       "parent": f"la colgó de la incidencia #{now['parent']}" if now["parent"] else "la soltó de su incidencia padre"}
                for k in d:  # cada cambio queda en el historial de la incidencia
                    self.note(row["id"], say[k], 1)
                self.log("editar", "incident", row["id"], now["title"], d)
            closed = self.close_children(row["id"], d["status"]) if d.get("status") in DONE else 0
            return self.send(200, {**dict(q(INC + " WHERE n.id=?", [row["id"]]).fetchone()), "closed_children": closed})
        if method == "DELETE":
            if not self.admin:
                return self.send(403, {"error": "solo un administrador puede borrar incidencias"})
            q("UPDATE incidents SET parent=NULL WHERE parent=?", [row["id"]])  # las hijas siguen, ya sin padre
            q("DELETE FROM notes WHERE incident=?", [row["id"]])
            q("DELETE FROM incidents WHERE id=?", [row["id"]])
            self.log("borrar", "incident", row["id"], row["title"], dict(row))
            return self.send(204)
        return self.send(405, {"error": "método no permitido"})

    def create_users(self, b):
        """Uno o muchos (lista). Todo se valida antes de guardar nada. Sin contraseña se genera una provisional,
        que solo se devuelve en esta respuesta; con contraseña o sin ella, se pide cambiarla al entrar."""
        batch = b if isinstance(b, list) else [b]
        if not 1 <= len(batch) <= 200:
            raise ValueError("de 1 a 200 usuarios a la vez")
        groups, taken, seen = {r[0] for r in q("SELECT id FROM groups")}, {r[0].lower() for r in q("SELECT name FROM users")}, set()
        for x in batch:
            name = str(x.get("name", "")) if isinstance(x, dict) else ""
            if not re.fullmatch(r"[A-Za-z0-9._@-]{1,40}", name):
                raise ValueError(f"nombre de usuario no válido: «{name[:40]}» (letras, números y . _ @ -, hasta 40)")
            if name.lower() in taken | seen:
                raise ValueError(f"{'ya existe' if name.lower() in taken else 'repetido en la lista'}: {name}")
            seen.add(name.lower())
            if x.get("pass") is not None:
                check_pass(x["pass"])
            if not (isinstance(x.get("groups", []), list) and all(g in groups for g in x.get("groups", []))):
                raise ValueError(f"{name}: grupo no válido")
        pws = [x.get("pass") or secrets.token_urlsafe(9) for x in batch]
        with ThreadPoolExecutor(8) as pool:  # PBKDF2 es lento a propósito: con 50 usuarios, en paralelo
            hashes = list(pool.map(pw_hash, pws))
        out = []
        for x, pw, h in zip(batch, pws, hashes):
            try:
                uid = q("INSERT INTO users(name, hash, admin, must_change) VALUES(?,?,?,1)", [x["name"], h, int(x.get("admin") is True)]).lastrowid
            except sqlite3.IntegrityError:
                raise ValueError(f"ya existe: {x['name']}")
            for g in set(x.get("groups", [])):
                q("INSERT INTO members(group_id, user_id) VALUES(?, ?)", [g, uid])
            self.log("crear", "user", uid, x["name"], {"admin": x.get("admin") is True, "grupos": x.get("groups", [])})
            out.append({**me(uid), "pass": None if x.get("pass") else pw})
        return self.send(201, out if isinstance(b, list) else out[0])

    def account(self, method, res, rid):
        ip, b = self.client_address[0], json.loads(self.body() or b"{}") if method in ("POST", "PUT") else {}
        if not isinstance(b, dict) and not (res == "users" and method == "POST" and isinstance(b, list)):
            raise ValueError("envía un objeto")
        if res == "login" and method == "POST":
            if throttled(ip):
                return self.send(429, {"error": "demasiados intentos: espera 15 minutos"})
            uid = login_ok(str(b.get("name", ""))[:100], str(b.get("pass", ""))[:200])
            if not uid:
                FAILS[ip].append(time.time())
                return self.send(401, {"error": "usuario o contraseña incorrectos"})
            tok = secrets.token_urlsafe(32)
            q("DELETE FROM sessions WHERE expires <= datetime('now')")
            q("INSERT INTO sessions(token, user_id, expires) VALUES(?, ?, datetime('now', '+30 days'))", [sha(tok), uid])
            return self.send(200, me(uid), cookie=f"{COOKIE}={tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000")
        if res == "logout" and method == "POST":
            q("DELETE FROM sessions WHERE token=?", [self.token])
            return self.send(204, cookie=f"{COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
        if res == "me" and method == "GET" and rid is None:
            return self.send(200, me(self.uid))
        if res == "me" and method == "POST" and rid == "password":
            if not pw_ok(str(b.get("old", "")), q("SELECT hash FROM users WHERE id=?", [self.uid]).fetchone()["hash"]):
                return self.send(400, {"error": "la contraseña actual no es correcta"})
            check_pass(b.get("new"))
            if b["new"] == b.get("old"):
                raise ValueError("la nueva contraseña tiene que ser distinta")
            q("UPDATE users SET hash=?, must_change=0 WHERE id=?", [pw_hash(b["new"]), self.uid])
            q("DELETE FROM sessions WHERE user_id=? AND token != ?", [self.uid, self.token])  # cierra las demás sesiones
            _basic.clear()
            self.log("cambiar contraseña", "user", self.uid, self.user, {})
            return self.send(204)
        if res != "users":
            return self.send(405, {"error": "método no permitido"})
        if method == "GET" and not self.admin:  # para asignar incidencias: solo nombres
            return self.send(200, [dict(r) for r in q("SELECT id, name FROM users ORDER BY name COLLATE NOCASE")])
        if not self.admin:
            return self.send(403, {"error": "solo para administradores"})
        if method == "GET":
            return self.send(200, [dict(r) for r in q("SELECT id, name, admin, must_change, created FROM users ORDER BY name COLLATE NOCASE")])
        if method == "POST" and rid is None:
            return self.create_users(b)
        row = rid and q("SELECT id, name FROM users WHERE id=?", [rid]).fetchone()
        if not row:
            return self.send(404, {"error": "no existe"})
        if row["id"] == self.uid and (method == "DELETE" or b.get("admin") is False):
            raise ValueError("no puedes quitarte el admin ni borrarte a ti mismo")  # así siempre queda un administrador
        if method == "PUT":
            if "admin" in b:
                q("UPDATE users SET admin=? WHERE id=?", [int(b["admin"] is True), row["id"]])
            if "pass" in b:
                check_pass(b["pass"])
                q("UPDATE users SET hash=?, must_change=1 WHERE id=?", [pw_hash(b["pass"]), row["id"]])
                q("DELETE FROM sessions WHERE user_id=?", [row["id"]])
                _basic.clear()
            self.log("editar", "user", row["id"], row["name"], {"admin": b.get("admin"), "contraseña": "pass" in b})
            return self.send(200, me(row["id"]))
        if method == "DELETE":
            q("DELETE FROM sessions WHERE user_id=?", [row["id"]])
            q("DELETE FROM users WHERE id=?", [row["id"]])
            q("DELETE FROM members WHERE user_id=?", [row["id"]])
            q("UPDATE incidents SET assignee=NULL WHERE assignee=?", [row["id"]])
            _basic.clear()
            self.log("borrar", "user", row["id"], row["name"], {})
            return self.send(204)
        return self.send(405, {"error": "método no permitido"})

    def maps(self, method, rid, parts, qs):
        if method == "GET" and rid is None:
            return self.send(200, [dict(r) for r in q(
                "SELECT id, name, json_extract(data, '$.type') AS type, json_extract(data, '$.height') AS height, "
                "COALESCE(json_array_length(data, '$.devices'), json_array_length(data, '$.nodes'), 0) AS n "
                "FROM maps ORDER BY name COLLATE NOCASE")])
        if method == "POST" and rid is None:  # cuerpo vacío = lienzo en blanco, si no, imagen de fondo
            mime, img = self.headers.get("Content-Type", "").split(";")[0], self.body()
            if img and mime not in IMAGE_TYPES:
                return self.send(400, {"error": "sube una imagen (png, jpg, gif, webp, svg)"})
            name = (qs.get("name") or ["Mapa"])[0][:200]
            data = {"type": "rack"} if qs.get("type") == ["rack"] else {}
            cur = q("INSERT INTO maps(name, mime, image, data) VALUES(?,?,?,?)",
                    [name, mime if img else "", img, json.dumps(data)])
            self.log("crear", data.get("type", "map"), cur.lastrowid, name, {"name": name, "data": data})
            return self.send(201, {"id": cur.lastrowid, "name": name})
        if method == "GET" and len(parts) > 3 and parts[3] == "image":
            row = q("SELECT mime, image FROM maps WHERE id=?", [rid]).fetchone()
            if not row or not row["image"]:
                return self.send(404, {"error": "no existe"})
            # CSP bloquea scripts dentro de SVG subidos si se abren directamente
            self.send_response(200)
            self.send_header("Content-Type", row["mime"])
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
            self.send_header("Content-Length", str(len(row["image"])))
            self.end_headers()
            return self.wfile.write(row["image"])
        if method == "GET" and rid:
            row = q("SELECT id, name, data, length(image) > 0 AS has_image FROM maps WHERE id=?", [rid]).fetchone()
            return self.send(200, {**dict(row), "data": json.loads(row["data"])}) if row else self.send(404, {"error": "no existe"})
        if method == "PUT" and rid:
            d = json.loads(self.body() or b"{}")
            if not isinstance(d.get("name", ""), str) or not isinstance(d.get("data", {}), dict):
                raise ValueError("name debe ser texto y data un objeto")
            if "name" in d:
                q("UPDATE maps SET name=? WHERE id=?", [d["name"][:200], rid])
            if d.get("data", {}).get("type") == "rack":
                check_rack(d["data"])
            if "data" in d:
                q("UPDATE maps SET data=? WHERE id=?", [json.dumps(d["data"]), rid])
            self.log_map("editar", rid)
            return self.send(204)
        if method == "DELETE" and rid:
            self.log_map("borrar", rid)
            q("DELETE FROM maps WHERE id=?", [rid])
            return self.send(204)
        self.send(405, {"error": "método no permitido"})

    def sounds(self, method, rid, parts, qs):
        if method == "GET" and rid is None:
            return self.send(200, [dict(r) for r in q("SELECT id, name FROM sounds ORDER BY id")])
        if method == "POST" and rid is None:
            mime, data = self.headers.get("Content-Type", "").split(";")[0], self.body()
            if mime not in AUDIO_TYPES or not data or len(data) > 3 * 1024 * 1024:
                return self.send(400, {"error": "sube un audio (mp3, wav, ogg, m4a) de hasta 3 MB"})
            name = (qs.get("name") or ["Alerta"])[0][:100]
            cur = q("INSERT INTO sounds(name, mime, data) VALUES(?,?,?)", [name, mime, data])
            return self.send(201, {"id": cur.lastrowid, "name": name})
        if method == "GET" and len(parts) > 3 and parts[3] == "audio":
            row = q("SELECT mime, data FROM sounds WHERE id=?", [rid]).fetchone()
            return self.send(200, row["data"], row["mime"]) if row else self.send(404, {"error": "no existe"})
        if method == "DELETE" and rid:
            q("DELETE FROM sounds WHERE id=?", [rid])
            q("UPDATE checks SET sound='' WHERE sound=?", [f"u:{rid}"])  # quien lo usaba vuelve al sonido general
            return self.send(204)
        self.send(405, {"error": "método no permitido"})

    def log_map(self, action, rid):
        row = q("SELECT id, name, data FROM maps WHERE id=?", [rid]).fetchone()
        if row:
            data = json.loads(row["data"])
            self.log(action, "rack" if data.get("type") == "rack" else "map", row["id"], row["name"],
                     {"name": row["name"], "data": data})

    def do_GET(self): self.route("GET")
    def do_POST(self): self.route("POST")
    def do_PUT(self): self.route("PUT")
    def do_DELETE(self): self.route("DELETE")
    def log_message(self, fmt, *a): pass


if __name__ == "__main__":
    # ASCII: la consola de Windows (cp1252) revienta con emojis
    print(f"catlan {VERSION} en http://0.0.0.0:{PORT}  (datos en {DATA})")
    threading.Thread(target=monitor, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
