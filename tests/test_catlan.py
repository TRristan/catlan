"""Prueba de humo de la API contra el ejecutable de catlan (cargo build --release; o CATLAN_BIN=ruta): python tests/test_catlan.py
Lo interno (BER, AES, USM, interfaces, SLA…) lo prueban las pruebas de Rust: cargo test"""
from pathlib import Path
import base64, gzip, hashlib, hmac, http.server, json, os, socket, sqlite3, socketserver, subprocess, sys, tempfile, threading, time, urllib.parse, urllib.request, urllib.error
from datetime import datetime, timedelta, timezone

HERE = Path(__file__).parent.parent  # la raíz del repositorio
BIN = os.environ.get("CATLAN_BIN") or str(HERE / "target" / "release" / ("catlan.exe" if os.name == "nt" else "catlan"))
if not Path(BIN).exists():
    sys.exit(f"No encuentro {BIN}: compila con «cargo build --release» o indica la ruta en CATLAN_BIN")
MIGRATIONS = 34  # migraciones numeradas de src/db.rs
SECRET = ("community", "pass", "priv_pass")
SEAL = b"CATLAN-CIFRADO-1"
sha = lambda t: hashlib.sha256(t.encode()).hexdigest()


# BER a mano para el agente SNMP de mentira (independiente del de catlan: así se prueba el uno contra el otro)
def tlv(tag, v):
    n = len(v)
    return bytes([tag]) + (bytes([n]) if n < 128 else (lambda b: bytes([0x80 | len(b)]) + b)(n.to_bytes((n.bit_length() + 7) // 8, "big"))) + v


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


def totp(secret, t=None):
    mac = hmac.new(base64.b32decode(secret), int((time.time() if t is None else t) // 30).to_bytes(8, "big"), "sha1").digest()
    o = mac[-1] & 15
    return "%06d" % ((int.from_bytes(mac[o:o + 4], "big") & 0x7FFFFFFF) % 10 ** 6)


def unseal(blob, pw):
    """El formato de las copias cifradas, leído aquí en Python: el de Rust tiene que ser el mismo de siempre."""
    if not blob.startswith(SEAL) or len(blob) < len(SEAL) + 64:
        raise ValueError("no es una copia cifrada de catlan")
    salt, nonce, ct, tag = blob[16:32], blob[32:48], blob[48:-32], blob[-32:]
    k = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 600_000, 64)
    if not hmac.compare_digest(tag, hmac.new(k[32:], blob[:-32], "sha256").digest()):
        raise ValueError("contraseña incorrecta o copia dañada")
    stream = hashlib.shake_256(k[:32] + nonce).digest(len(ct))
    return bytes(a ^ b for a, b in zip(ct, stream))


def ws_open(port, path, headers):
    """WebSocket mínimo (RFC 6455), sin dependencias: (socket, código HTTP del saludo)."""
    s = socket.create_connection(("127.0.0.1", int(port)), timeout=10)
    key = base64.b64encode(os.urandom(16)).decode()
    extra = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    s.sendall(f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
              f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:  # de byte en byte: lo que venga detrás ya es del WebSocket
        c = s.recv(1)
        if not c:
            break
        head += c
    return s, int(head.split()[1])


def ws_send(s, data):
    """Texto (str) o binario (bytes), enmascarado como manda un cliente."""
    op, data = (1, data.encode()) if isinstance(data, str) else (2, data)
    n, mask = len(data), os.urandom(4)
    size = bytes([0x80 | n]) if n < 126 else bytes([0x80 | 126]) + n.to_bytes(2, "big") if n < 65536 else bytes([0x80 | 127]) + n.to_bytes(8, "big")
    s.sendall(bytes([0x80 | op]) + size + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(data)))


def ws_recv(s, timeout=10):
    """El siguiente mensaje: str si es texto, bytes si es binario, None si catlan cierra."""
    s.settimeout(timeout)
    def get(n):
        b = b""
        while len(b) < n:
            c = s.recv(n - len(b))
            if not c:
                raise EOFError
            b += c
        return b
    h = get(2)
    n = h[1] & 127
    n = int.from_bytes(get(2 if n == 126 else 8), "big") if n >= 126 else n
    data, op = get(n), h[0] & 15
    return None if op == 8 else data.decode() if op == 1 else data


def muted(row):
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    return bool(row.get("mute_until")) and row["mute_until"] > now and (row.get("mute_from") or "") <= now

mails = []  # correos recibidos por el servidor SMTP de mentira


class FakeSMTP(socketserver.StreamRequestHandler):
    def handle(self):
        try:
            self.talk()
        except ConnectionError:  # la comprobación TCP abre y cierra sin hablar
            pass

    def talk(self):
        say = lambda t: self.wfile.write((t + "\r\n").encode())
        say("220 fake")
        data, buf = False, []
        for raw in self.rfile:
            line = raw.decode(errors="replace").rstrip("\r\n")
            if data:
                if line == ".":
                    mails.append("\n".join(buf)); buf, data = [], False; say("250 ok")
                else:
                    buf.append(line)
            elif line.upper() == "DATA":
                data = True; say("354 go")
            elif line.upper() == "QUIT":
                return say("221 bye")
            else:
                say("250 ok")


smtp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), FakeSMTP)
threading.Thread(target=smtp.serve_forever, daemon=True).start()
hooks = []  # avisos recibidos por el webhook de mentira


class FakeWeb(http.server.BaseHTTPRequestHandler):
    """Una intranet («/» bien, el resto 503) y un webhook tipo Slack en /hook."""
    def do_GET(self):
        body = b"<h1>miau intranet</h1>" if self.path == "/" else b"caida"
        self.send_response(200 if self.path == "/" else 503)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        hooks.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *a): pass


web = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeWeb)
threading.Thread(target=web.serve_forever, daemon=True).start()
WEB = f"http://127.0.0.1:{web.server_address[1]}"

# Un Active Directory de mentira (LDAP en BER a mano): bind con el UPN, «¿quién soy?» y la búsqueda de su ficha
DOMINIO = {"juan": ("clave-juan", ["CN=IT,OU=Grupos,DC=empresa,DC=local"]), "jefa": ("clave-jefa", ["CN=Jefes,DC=empresa,DC=local"]),
           "ventas": ("clave-ventas", ["CN=Ventas,DC=empresa,DC=local"]), "admin": ("clave-admin-dominio", ["CN=Jefes,DC=empresa,DC=local"]),
           "pepe": ("clave-pepe", ["CN=IT,OU=Grupos,DC=empresa,DC=local"])}


class FakeLDAP(socketserver.BaseRequestHandler):
    def handle(self):
        buf, me = b"", None
        done = lambda tag, code: tlv(tag, ber_int(code, 10) + tlv(4, b"") + tlv(4, b""))
        while True:
            while len(buf) < 2 or len(buf) < ber_read(buf, 0)[2]:
                d = self.request.recv(65536)
                if not d: return
                buf += d
            n = ber_read(buf, 0)[2]
            _, m, _ = ber_read(buf[:n], 0)
            buf = buf[n:]
            _, mid, i = ber_read(m, 0)
            tag, op, _ = ber_read(m, i)
            say = lambda o: self.request.sendall(tlv(0x30, tlv(2, mid) + o))
            if tag == 0x60:  # bind
                _, _, j = ber_read(op, 0); _, dn, j = ber_read(op, j); _, pw, _ = ber_read(op, j)
                user = dn.decode().removesuffix("@empresa.local")
                me = user if user in DOMINIO and pw and DOMINIO[user][0] == pw.decode() else None
                say(done(0x61, 0 if me else 49))
            elif tag == 0x77:  # ¿quién soy?
                say(tlv(0x78, ber_int(0, 10) + tlv(4, b"") + tlv(4, b"") + tlv(0x8b, b"u:EMPRESA\\" + me.encode())))
            elif tag == 0x63:  # la ficha de quien ha hecho el bind
                attr = lambda k, vs: tlv(0x30, tlv(4, k.encode()) + tlv(0x31, b"".join(tlv(4, v.encode()) for v in vs)))
                say(tlv(0x64, tlv(4, f"CN={me},DC=empresa,DC=local".encode()) + tlv(0x30, attr("sAMAccountName", [me]) + attr("memberOf", DOMINIO[me][1]))))
                say(done(0x65, 0))
            else:
                return


ldap = socketserver.ThreadingTCPServer(("127.0.0.1", 0), FakeLDAP)
threading.Thread(target=ldap.serve_forever, daemon=True).start()
IDP_USER = {}  # lo que dirá el id_token de quien entra
idp_seen = {}  # lo que pidió catlan en /auth: state, nonce, code_challenge…


class FakeIdP(http.server.BaseHTTPRequestHandler):
    """Un proveedor OIDC (como Keycloak): descubrimiento, /auth que «entra» y vuelve, y /token que comprueba PKCE."""
    def send(self, code, body=None, loc=None):
        self.send_response(code)
        if loc: self.send_header("Location", loc)
        raw = json.dumps(body).encode() if body is not None else b""
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    def do_GET(self):
        if self.path == "/.well-known/openid-configuration":
            return self.send(200, {"issuer": IDP, "authorization_endpoint": IDP + "/auth", "token_endpoint": IDP + "/token"})
        q = dict(urllib.parse.parse_qsl(self.path.split("?", 1)[1]))
        idp_seen.update(q)
        self.send(302, loc=f"{q['redirect_uri']}?code=c-{q['state'][:6]}&state={q['state']}")

    def do_POST(self):
        f = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
        pkce = base64.urlsafe_b64encode(hashlib.sha256(f["code_verifier"].encode()).digest()).rstrip(b"=").decode()
        if pkce != idp_seen["code_challenge"] or f.get("client_secret") != "s3creto-oidc" or f["code"] != f"c-{idp_seen['state'][:6]}":
            return self.send(400, {"error": "invalid_grant"})
        enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        claims = {"iss": IDP, "aud": "catlan", "exp": time.time() + 300, "nonce": idp_seen["nonce"], **IDP_USER}
        self.send(200, {"id_token": f"{enc({'alg': 'RS256'})}.{enc(claims)}.firma"})

    def log_message(self, *a): pass


idp = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeIdP)
threading.Thread(target=idp.serve_forever, daemon=True).start()
IDP = f"http://127.0.0.1:{idp.server_address[1]}"

from email import message_from_string, policy  # noqa: E402

# NAS Synology de mentira: disco 2 caliente, /volume1 al 96 % y el RAID degradado
G, T, S = 0x42, 0x43, 4
MIB = {
    "1.3.6.1.2.1.1.1.0": (S, "Linux nas-cpd 4.4.302+ Synology"), "1.3.6.1.2.1.1.3.0": (T, 123456700), "1.3.6.1.2.1.1.5.0": (S, "nas-cpd"),
    "1.3.6.1.2.1.25.2.3.1.2.1": (6, "1.3.6.1.2.1.25.2.1.2"), "1.3.6.1.2.1.25.2.3.1.3.1": (S, "Physical memory"),
    "1.3.6.1.2.1.25.2.3.1.4.1": (2, 1024), "1.3.6.1.2.1.25.2.3.1.5.1": (2, 4000000), "1.3.6.1.2.1.25.2.3.1.6.1": (2, 3000000),
    "1.3.6.1.2.1.25.2.3.1.2.31": (6, "1.3.6.1.2.1.25.2.1.4"), "1.3.6.1.2.1.25.2.3.1.3.31": (S, "/volume1"),
    "1.3.6.1.2.1.25.2.3.1.4.31": (2, 4096), "1.3.6.1.2.1.25.2.3.1.5.31": (2, 1000000000), "1.3.6.1.2.1.25.2.3.1.6.31": (2, 960000000),
    "1.3.6.1.2.1.25.3.3.1.2.196608": (2, 12), "1.3.6.1.2.1.25.3.3.1.2.196609": (2, 20),
    "1.3.6.1.4.1.6574.1.1.0": (2, 1), "1.3.6.1.4.1.6574.1.2.0": (2, 48), "1.3.6.1.4.1.6574.1.3.0": (2, 1),
    "1.3.6.1.4.1.6574.1.4.1.0": (2, 1), "1.3.6.1.4.1.6574.1.4.2.0": (2, 1),
    "1.3.6.1.4.1.6574.2.1.1.2.0": (S, "Disk 1"), "1.3.6.1.4.1.6574.2.1.1.5.0": (2, 1), "1.3.6.1.4.1.6574.2.1.1.6.0": (2, 41),
    "1.3.6.1.4.1.6574.2.1.1.2.1": (S, "Disk 2"), "1.3.6.1.4.1.6574.2.1.1.5.1": (2, 1), "1.3.6.1.4.1.6574.2.1.1.6.1": (2, 71),
    "1.3.6.1.4.1.6574.3.1.1.2.0": (S, "Volume 1"), "1.3.6.1.4.1.6574.3.1.1.3.0": (2, 11),
}
KEY = lambda o: tuple(map(int, o.split(".")))


class FakeAgent(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        _, msg, _ = ber_read(data, 0)
        _, _, i = ber_read(msg, 0)
        _, comm, i = ber_read(msg, i)
        mib = {b"secreta": MIB, b"switch": SW}.get(comm)
        if mib is None:
            return  # comunidad incorrecta: silencio, como un equipo real
        tag, pdu, _ = ber_read(msg, i)
        _, rid, j = ber_read(pdu, 0)
        _, _, j = ber_read(pdu, j)
        _, rep, j = ber_read(pdu, j)
        _, vbl, _ = ber_read(pdu, j)
        oids, k = [], 0
        while k < len(vbl):
            _, vb, k = ber_read(vbl, k)
            oids.append(oid_str(ber_read(vb, 0)[1]))
        out = []
        for o in oids:
            if tag == 0xA0:
                out.append((o, mib.get(o, (0x80, None))))
            else:
                nxt = [x for x in sorted(mib, key=KEY) if KEY(x) > KEY(o)][:int.from_bytes(rep, "big")]
                out += [(x, mib[x]) for x in nxt] or [(o, (0x82, None))]
        enc = lambda t, v: bytes([t, 0]) if v is None else tlv(4, v if isinstance(v, bytes) else v.encode()) if t == 4 else ber_oid(v) if t == 6 else ber_int(v, t)
        vbs = b"".join(tlv(0x30, ber_oid(o) + enc(*tv)) for o, tv in out)
        sock.sendto(tlv(0x30, ber_int(1) + tlv(4, comm) + tlv(0xA2, tlv(2, rid) + ber_int(0)
                    + ber_int(0) + tlv(0x30, vbs))), self.client_address)


# Switch de mentira para la auto-topología: Gi1/0/1 servidor por LLDP, Gi1/0/2 router por CDP, Gi1/0/3 un PC por su MAC (IP por ARP),
# Gi1/0/4 dos MAC sin IP y Gi1/0/5 un enlace con 6 MAC detrás (no es «un equipo»)
SW = {f"1.3.6.1.2.1.31.1.1.1.1.{n}": (S, f"Gi1/0/{n}") for n in range(1, 6)}
SW.update({f"1.3.6.1.2.1.17.1.4.1.2.{n}": (2, n) for n in range(1, 6)})
L, LM, LL, C, F = "1.0.8802.1.1.2.1.4.1.1", "1.0.8802.1.1.2.1.4.2.1", "1.0.8802.1.1.2.1.3.7.1", "1.3.6.1.4.1.9.9.23.1.2.1.1", "1.3.6.1.2.1.17.7.1.2.2.1.2"
SW.update({f"{LL}.3.1": (S, "Gi1/0/1"), f"{L}.5.0.1.1": (S, bytes.fromhex("0050569a0001")), f"{L}.7.0.1.1": (S, "eth0"), f"{L}.8.0.1.1": (S, "eth0"),
           f"{L}.9.0.1.1": (S, "srv-web.empresa.lan"), f"{L}.12.0.1.1": (S, bytes([0x01, 0])), f"{LM}.3.0.1.1.1.4.10.0.0.10": (2, 2),
           f"{C}.4.2.1": (S, bytes([10, 0, 0, 1])), f"{C}.6.2.1": (S, "core-rtr"), f"{C}.7.2.1": (S, "Gi0/0"), f"{C}.9.2.1": (S, bytes([0, 0, 0, 1])),
           f"1.3.6.1.2.1.4.22.1.2.3.10.0.1.15": (S, bytes.fromhex("aabbcc000003"))})
for port, macs in ((3, ["aabbcc000003"]), (4, ["aabbcc000041", "aabbcc000042"]), (5, [f"aabbcc0000{i:02x}" for i in range(0x50, 0x56)])):
    SW.update({F + ".1." + ".".join(str(b) for b in bytes.fromhex(m)): (2, port) for m in macs})

agent = socketserver.ThreadingUDPServer(("127.0.0.1", 0), FakeAgent)
threading.Thread(target=agent.serve_forever, daemon=True).start()
APORT = agent.server_address[1]

PORT = "18099"
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as _u:  # un puerto UDP libre para el syslog
    _u.bind(("127.0.0.1", 0))
    SYSLOG = _u.getsockname()[1]
env = {**os.environ, "CATLAN_DATA": tempfile.mkdtemp(), "CATLAN_PORT": PORT, "CATLAN_PASSWORD": "miau", "CATLAN_SYSLOG_PORT": str(SYSLOG),
       "CATLAN_SMTP_HOST": "127.0.0.1", "CATLAN_SMTP_PORT": str(smtp.server_address[1]), "CATLAN_MAIL_TO": "it@example.com", "CATLAN_WEBHOOK_URL": WEB + "/hook"}
srv = subprocess.Popen([BIN], env=env)
AUTH = "Basic " + base64.b64encode(b"admin:miau").decode()  # CATLAN_PASSWORD = la del admin inicial


def call(path, method="GET", body=None, auth=AUTH, ctype="application/json", origin=None):
    data = json.dumps(body).encode() if ctype == "application/json" and body is not None else body
    headers = {"Authorization": auth, "Content-Type": ctype, **({"Origin": origin} if origin else {})}
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return r.status, json.loads(raw) if raw and r.headers["Content-Type"] == "application/json" else raw
    except urllib.error.HTTPError as e:
        return e.code, None


try:
    for _ in range(50):
        try: call("/api/pages"); break
        except OSError: time.sleep(0.1)
    assert call("/api/pages", auth="Basic " + base64.b64encode(b"x:mal").decode())[0] == 401
    assert call("/api/pages", auth="")[0] == 401
    assert call("/", auth="")[0] == 200  # la página (con su login) carga sin sesión

    def raw(path, method="GET", body=None, cookie=""):  # como el navegador: cookie de sesión, sin Basic
        req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", None if body is None else json.dumps(body).encode(), method=method,
                                     headers={"Content-Type": "application/json", "Cookie": cookie})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, (r.headers.get("Set-Cookie") or "").split(";")[0], json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, "", json.loads(e.read() or b"null")

    st, adm, me = raw("/api/login", "POST", {"name": "admin", "pass": "miau"})
    assert st == 200 and adm.startswith(f"catlan_{sha(str(Path(env['CATLAN_DATA']).resolve()))[:10]}=") and me == {"id": 1, "name": "admin", "admin": 1, "must_change": 0, "totp": 0, "ext": "", "readonly": False, "groups": []}
    assert raw("/api/pages", cookie=adm)[0] == 200 and raw("/api/login", "POST", {"name": "admin", "pass": "mal"})[0] == 401
    # Instalación nueva: la wiki trae la «Guía de catlan» (uso, funciones y qué hace con los datos), una sola vez
    guia = call("/api/pages")[1]
    assert [g["title"] for g in guia] == ["Guía de catlan"], guia
    body = call(f"/api/pages/{guia[0]['id']}")[1]["body"]
    assert not body.startswith("# ") and all(t in body for t in ("## Primeros pasos", "## Qué hace cada sección", "## Tus datos", "## Qué no hace", "telemetría", "api.telegram.org"))
    # Dos catlan en la misma máquina: el navegador comparte cookies entre puertos; entrar en uno no debe echar del otro
    import http.cookiejar
    otro = subprocess.Popen([BIN],
                            env={**env, "CATLAN_DATA": tempfile.mkdtemp(), "CATLAN_PORT": "18100"}, stdout=subprocess.DEVNULL)
    try:
        jar = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        post = lambda port, path, body: jar.open(urllib.request.Request(f"http://127.0.0.1:{port}{path}", json.dumps(body).encode(), {"Content-Type": "application/json"}))
        post(PORT, "/api/login", {"name": "admin", "pass": "miau"})
        for _ in range(50):
            try:
                post(18100, "/api/login", {"name": "admin", "pass": "miau"})
                break
            except OSError:
                time.sleep(0.1)
        assert jar.open(f"http://127.0.0.1:{PORT}/api/me").status == 200  # antes: 401, la cookie del otro pisaba esta
    finally:
        otro.terminate()
    for bad in [{"name": "ana", "pass": "corta"}, {"name": "a b", "pass": "provisional1"}, {"name": "ADMIN", "pass": "provisional1"}]:
        assert call("/api/users", "POST", bad)[0] == 400, bad
    ana = call("/api/users", "POST", {"name": "ana", "pass": "provisional1"})[1]
    assert ana["must_change"] == 1 and ana["admin"] == 0 and "hash" not in ana and all("hash" not in u for u in call("/api/users")[1])
    st, ck, _ = raw("/api/login", "POST", {"name": "Ana", "pass": "provisional1"})
    assert st == 200 and raw("/api/pages", cookie=ck)[0] == 403  # contraseña provisional: no deja hacer nada más
    assert raw("/api/me/password", "POST", {"old": "mala-mala", "new": "nueva-segura"}, ck)[0] == 400
    assert raw("/api/me/password", "POST", {"old": "provisional1", "new": "corta"}, ck)[0] == 400
    assert raw("/api/me/password", "POST", {"old": "provisional1", "new": "nueva-segura"}, ck)[0] == 204
    assert raw("/api/pages", cookie=ck)[0] == 200 and raw("/api/users", "POST", {"name": "z", "pass": "zzzzzzzz"}, ck)[0] == 403  # ya entra, pero no es admin
    assert all(set(u) == {"id", "name"} for u in raw("/api/users", cookie=ck)[2])  # para asignar: solo nombres
    assert call("/api/pages", auth="Basic " + base64.b64encode(b"ana:nueva-segura").decode())[0] == 200  # Basic para scripts
    assert raw("/api/logout", "POST", cookie=ck)[0] == 204 and raw("/api/pages", cookie=ck)[0] == 401  # cerrada de verdad
    _, ck, _ = raw("/api/login", "POST", {"name": "ana", "pass": "nueva-segura"})
    assert call(f"/api/users/{ana['id']}", "PUT", {"pass": "provisional2"})[1]["must_change"] == 1
    assert raw("/api/pages", cookie=ck)[0] == 401  # el admin le cambia la contraseña: sus sesiones se cierran
    assert call("/api/users/1", "DELETE")[0] == 400 and call("/api/users/1", "PUT", {"admin": False})[0] == 400  # siempre queda un admin
    assert call(f"/api/users/{ana['id']}", "DELETE")[0] == 204 and raw("/api/login", "POST", {"name": "ana", "pass": "provisional2"})[0] == 401
    assert ("user", "borrar") in [(h["kind"], h["action"]) for h in call("/api/log")[1]]
    assert raw("/api/pages", "POST", {"title": "x"}, adm)[0] == 201  # la sesión del admin sigue viva
    s, p = call("/api/pages", "POST", {"title": "Red", "body": "# VLANs", "id": 999, "evil; DROP": 1})
    assert s == 201 and p["title"] == "Red" and p["id"] != 999
    assert call(f"/api/pages/{p['id']}", "PUT", {"body": "x"})[1]["body"] == "x"
    s, m = call("/api/maps?name=Planta", "POST", b"\x89PNG fake", ctype="image/png")
    assert s == 201
    assert call("/api/maps", "POST", b"<html>", ctype="text/html")[0] == 400
    assert call(f"/api/maps/{m['id']}/image")[1] == b"\x89PNG fake"
    s, i = call("/api/items", "POST", {"name": "sw-core", "ip": "10.0.0.1"})
    assert s == 201
    esquema = {"nodes": [{"id": "a", "t": "switch", "x": 100, "y": 100, "item": i["id"]}], "links": []}
    assert call(f"/api/maps/{m['id']}", "PUT", {"name": "P1", "data": esquema})[0] == 200
    s, got = call(f"/api/maps/{m['id']}")
    assert got["name"] == "P1" and got["data"] == esquema and got["has_image"] == 1
    assert call(f"/api/maps/{m['id']}", "PUT", {"data": "no"})[0] == 400
    s, blank = call("/api/maps?name=Vacio", "POST", b"", ctype="")  # lienzo sin fondo
    assert s == 201 and call(f"/api/maps/{blank['id']}")[1]["has_image"] == 0
    assert call(f"/api/maps/{blank['id']}/image")[0] == 404
    call(f"/api/maps/{blank['id']}", "PUT", {"data": {"type": "rack", "height": 42, "devices": []}})
    tipos = {x["id"]: x["type"] for x in call("/api/maps")[1]}
    assert tipos[blank["id"]] == "rack" and tipos[m["id"]] is None  # la lista separa racks de esquemas
    call(f"/api/pages/{p['id']}", "PUT", {"body": "el switch [[#%d]] va al CPD" % i["id"]})
    r = call(f"/api/items/{i['id']}/refs")[1]
    assert [x["id"] for x in r["pages"]] == [p["id"]] and [x["id"] for x in r["maps"]] == [m["id"]]
    assert call(f"/api/items/{i['id'] + 100}/refs")[1] == {"pages": [], "items": [], "maps": [], "incidents": [], "expiries": [], "agent": None}
    hist = call(f"/api/log?kind=page&ref={p['id']}")[1]
    assert [h["action"] for h in hist] == ["editar", "editar", "crear"] and hist[0]["who"] == "admin"
    assert "[[#" in json.loads(hist[0]["data"])["body"]
    assert call(f"/api/maps/{m['id']}", "DELETE")[0] == 204
    assert call(f"/api/items/{i['id']}", "DELETE")[0] == 204
    assert call(f"/api/items/{i['id']}")[0] == 404
    borrado = call(f"/api/log?kind=item&ref={i['id']}")[1][0]
    assert borrado["action"] == "borrar" and json.loads(borrado["data"])["ip"] == "10.0.0.1"  # recuperable
    tipos = [(h["kind"], h["action"]) for h in call("/api/log")[1]]
    assert ("rack", "editar") in tipos and ("map", "borrar") in tipos
    s, many = call("/api/items", "POST", [{"name": f"PC-{n:03}", "ip": f"10.0.30.{n}"} for n in range(1, 101)])
    assert s == 201 and len(many) == 100 and many[-1]["name"] == "PC-100"  # alta en serie
    assert call("/api/items", "POST", [])[0] == 400 and call("/api/items", "POST", [1, 2])[0] == 400
    # Otra web no puede escribir (CSRF); la propia app sí
    assert call("/api/items", "POST", {"name": "pwn"}, origin="https://evil.example")[0] == 403
    assert call("/api/items", "POST", {"name": "ok"}, origin=f"http://127.0.0.1:{PORT}")[0] == 201
    # Rack con campos que acabarían como HTML en el navegador: rechazado
    rk = call("/api/maps?type=rack&name=R", "POST", b"", ctype="")[1]["id"]
    xss = '"><img src=x onerror=alert(1)>'
    for bad in [{"height": xss}, {"height": 42, "devices": [{"t": xss, "u": 1, "h": 1}]},
                {"height": 42, "devices": [{"t": "server", "u": xss, "h": 1}]}, {"height": 99}]:
        assert call(f"/api/maps/{rk}", "PUT", {"data": {"type": "rack", **bad}})[0] == 400, bad
    good = {"type": "rack", "height": 12, "devices": [{"id": "a", "t": "switch", "u": 12, "h": 1, "ports": 48, "sfp": 4, "pmap": {"1": "x"}},
                                                      {"id": "b", "t": "pdu", "u": 1, "h": 1, "ports": 8, "pmap": {"1": "ESXi-01 fuente A", "2": "[[#1]]"}}]}  # enchufes
    assert call(f"/api/maps/{rk}", "PUT", {"data": good})[0] == 200
    assert call(f"/api/maps/{rk}")[1]["data"] == good
    # Monitor: hosts que no pueden colarse como opciones del comando ping
    for bad in [{"host": "-c 9 x"}, {"host": "a;rm"}, {"host": ""}, {"host": "10.0.0.1", "every": 1}]:
        assert call("/api/checks", "POST", bad)[0] == 400, bad
    assert call("/api/ping", "POST", {"host": "--help"})[0] == 400
    assert call("/api/ping", "POST", {"host": "127.0.0.1"})[1]["up"] is True
    assert call("/api/ping", "POST", {"host": "localhost"})[1]["up"] is True  # en Windows es IPv6: sin «TTL=»
    ok_id = call("/api/checks", "POST", {"host": "127.0.0.1", "label": "local", "every": 10})[1]["id"]
    down_id = call("/api/checks", "POST", {"host": "192.0.2.1", "every": 10})[1]["id"]  # TEST-NET: nunca responde
    deadline = time.time() + 40
    while time.time() < deadline:
        st = {c["id"]: c for c in call("/api/monitor")[1]["checks"]}
        if st[ok_id]["state"] == "up" and st[down_id]["state"] == "down" and len(mails) >= 1:
            break
        time.sleep(1)
    assert st[ok_id]["state"] == "up" and st[ok_id]["uptime"] == 1 and st[ok_id]["recent"][-1] == 1
    assert st[down_id]["state"] == "down" and st[down_id]["fails"] >= 2  # caído solo tras 2 fallos seguidos
    assert any("192.0.2.1: no responde al ping" in m for m in mails), mails  # aviso por correo
    assert any("192.0.2.1: no responde al ping" in h["text"] for h in hooks), hooks  # y por webhook, a la vez
    assert not any("catlan: local" in m for m in mails)  # el primer «responde» no manda correo
    assert call("/api/monitor")[1]["channels"] == ["correo", "webhook"]
    assert call("/api/monitor/test", "POST") == (200, {"correo": None, "webhook": None}) and "prueba" in mails[-1] and "prueba" in hooks[-1]["text"]
    # Comprobaciones de puerto, web, certificado y DNS
    for bad in [{"kind": "smtp", "host": "x"}, {"kind": "tcp", "host": "127.0.0.1"}, {"kind": "http", "host": "x"}, {"kind": "tcp", "host": "x", "port": 70000},
                {"kind": "http", "host": "x", "url": "javascript:alert(1)"}, {"kind": "ssl", "host": "x", "port": 443, "warn_days": 0}]:
        assert call("/api/checks", "POST", bad)[0] == 400, bad
    new = lambda **b: call("/api/checks", "POST", {"host": "127.0.0.1", "every": 10, **b})[1]["id"]
    tcp_id, web_id, dns_id = new(kind="tcp", port=smtp.server_address[1]), new(kind="http", url=WEB + "/", expect="miau"), new(kind="dns", host="localhost", expect="127.0.0.1")
    roto = new(kind="http", url=WEB + "/roto", label="web rota")
    assert call(f"/api/checks/{roto}/mute", "POST", {"minutes": 60})[1]["mute_until"]  # mantenimiento antes de que caiga
    for bad in [{"minutes": -1}, {"minutes": "60"}, {"minutes": 99999}, {}]:
        assert call(f"/api/checks/{roto}/mute", "POST", bad)[0] == 400, bad
    assert call("/api/checks/999999/mute", "POST", {"minutes": 5})[0] == 404
    deadline = time.time() + 40
    while time.time() < deadline:
        st = {c["id"]: c for c in call("/api/monitor")[1]["checks"]}
        if all(st[i]["state"] == "up" for i in (tcp_id, web_id, dns_id)) and st[roto]["state"] == "down":
            break
        time.sleep(1)
    assert [st[i]["state"] for i in (tcp_id, web_id, dns_id, roto)] == ["up", "up", "up", "down"], st
    assert st[roto]["detail"] == "HTTP 503" and st[dns_id]["detail"].startswith("resuelve a 127.0.0.1")
    assert not any("web rota" in h["text"] for h in hooks)  # silenciado: no avisa
    assert call(f"/api/checks/{roto}/mute", "POST", {"minutes": 0})[1]["mute_until"] is None
    deadline = time.time() + 60  # al quitar el silencio sigue caída: ahora sí avisa (holgado: el equipo puede ir cargado)
    while time.time() < deadline and not any("web rota: HTTP 503" in h["text"] for h in hooks):
        time.sleep(1)
    assert any("web rota: HTTP 503" in h["text"] for h in hooks), hooks
    assert ("check", "silenciar") in [(h["kind"], h["action"]) for h in call(f"/api/log?kind=check&ref={roto}")[1]]  # queda en Actividad
    # Dependencias desde los esquemas: nube — router — switch — 2 PCs, y un PC suelto. Cae el switch: avisa del switch, no de sus PCs
    ids = {n: call("/api/items", "POST", {"name": n})[1]["id"] for n in ("router-dep", "switch-dep", "pc-dep-1", "pc-dep-2", "pc-suelto")}
    plano = call("/api/maps?name=Planta", "POST")[1]["id"]
    nodes = [{"id": f"n{i}", "t": "pc", "x": 100 * i, "y": 100, "item": ids[n]} for i, n in enumerate(ids)] + [{"id": "nube", "t": "cloud", "x": 0, "y": 0}]
    call(f"/api/maps/{plano}", "PUT", {"data": {"nodes": nodes, "links": [["nube", "n0"], ["n0", "n1"], ["n1", "n2"], ["n1", "n3"]]}})
    hosts = {"router-dep": "127.0.0.1", "switch-dep": "192.0.2.20", "pc-dep-1": "192.0.2.21", "pc-dep-2": "192.0.2.22", "pc-suelto": "192.0.2.23"}
    call("/api/checks", "POST", [{"host": h, "item": ids[n], "every": 10} for n, h in hosts.items()])
    deadline = time.time() + 90  # 2 fallos seguidos cada 10 s más pings que agotan su espera: holgado
    while time.time() < deadline:
        st = {c["item_name"]: c for c in call("/api/monitor")[1]["checks"] if c["item"] in ids.values()}
        sent = " ".join(h["text"] for h in hooks)  # los avisos salen en hilos: esperar a los dos, no solo al primero
        if [st[n]["state"] for n in hosts] == ["up", "down", "down", "down", "down"] and "pc-suelto: no" in sent and "switch-dep: no" in sent:
            break
        time.sleep(1)
    assert [st[n]["dep"] for n in hosts] == [None, None, ["switch-dep"], ["switch-dep"], None], {n: (st[n]["state"], st[n]["dep"]) for n in hosts}
    texts = " ".join(h["text"] for h in hooks)
    assert "switch-dep: no responde" in texts and "pc-suelto: no responde" in texts and "pc-dep" not in texts, texts  # solo el culpable y el suelto
    # Sonidos propios
    assert call("/api/sounds", "POST", b"no", ctype="text/plain")[0] == 400
    snd = call("/api/sounds?name=Gong", "POST", b"RIFF-fake-wav", ctype="audio/wav")[1]
    assert call(f"/api/sounds/{snd['id']}/audio")[1] == b"RIFF-fake-wav"
    assert call(f"/api/sounds/{snd['id']}", "DELETE")[0] == 204 and call("/api/sounds")[1] == []
    v3 = {"host": "127.0.0.1", "v3": True, "user": "lector", "auth": "sha", "pass": "clave-larga", "priv": "aes", "priv_pass": "otra-clave"}
    for bad in [{**v3, "user": ""}, {**v3, "auth": "none"}, {**v3, "pass": "corta"}, {**v3, "auth": "sha1"}, {**v3, "priv": "des"}, {**v3, "v3": 2}]:
        assert call("/api/sources", "POST", bad)[0] == 400, bad
    s3, r3 = call("/api/sources", "POST", {**v3, "label": "v3 sin equipo"})
    assert s3 == 201 and r3["v3"] == 1 and r3["auth"] == "sha" and not set(SECRET) & set(r3), r3  # contraseñas fuera
    assert call(f"/api/sources/{r3['id']}", "DELETE")[0] == 204
    hist3 = call(f"/api/log?kind=source&ref={r3['id']}")[1]
    assert len(hist3) == 2 and all(not set(SECRET) & set(json.loads(h["data"])) for h in hist3)  # ni en el historial
    nas = {"host": "127.0.0.1", "port": APORT, "kind": "synology", "community": "secreta"}
    for bad in [{**nas, "kind": "nope"}, {**nas, "every": 30}, {**nas, "host": "-x"}, {**nas, "temp_max": "a"}]:
        assert call("/api/sources", "POST", bad)[0] == 400, bad
    s, t = call("/api/sources/test", "POST", nas)  # probar sin guardar
    got = {k: v for k, _, v, _ in t["metrics"]}
    assert s == 200 and got["temp:Disk 2"] == 71 and got["disk:/volume1"] == 96 and got["mem"] == 75 and got["cpu"] == 16, got
    assert t["info"]["name"] == "nas-cpd" and t["info"]["uptime"] == 1234567
    assert call("/api/sources/test", "POST", {**nas, "community": "mala"})[0] == 400  # sin respuesta: error claro
    sid = call("/api/sources", "POST", {**nas, "label": "NAS CPD", "every": 60})[1]["id"]
    assert "community" not in call("/api/sources")[1][0] and "community" not in call(f"/api/sources/{sid}")[1]  # secretos fuera
    deadline = time.time() + 20
    while time.time() < deadline:
        h = [x for x in call("/api/health")[1] if x["id"] == sid][0]
        if h["state"]:
            break
        time.sleep(0.5)
    assert h["state"] == "warn" and "community" not in h, h
    assert any("Volume 1: degradado" == p for p in h["problems"]) and any(p.startswith("Disk 2: 71") for p in h["problems"])
    assert any(p.startswith("/volume1: 96") for p in h["problems"]) and not any("Disk 1" in p for p in h["problems"])
    assert {m["key"] for m in h["latest"]} >= {"temp:sistema", "temp:Disk 1", "temp:Disk 2", "disk:/volume1", "mem", "cpu"}
    assert call(f"/api/metrics?source={sid}&hours=1")[1]["temp:Disk 2"]["points"][-1][1] == 71
    deadline = time.time() + 10
    while time.time() < deadline and not any("NAS CPD" in str(message_from_string(m, policy=policy.default)["subject"]) for m in mails):
        time.sleep(0.5)
    assert any("NAS CPD" in str(message_from_string(m, policy=policy.default)["subject"]) for m in mails)  # aviso por correo
    assert any(x["state"] == "warn" for x in call("/api/monitor")[1]["sources"])  # para el aviso en pantalla
    # Dashboard: uno compartido; el frontal pinta lo guardado, así que solo entran campos conocidos
    assert call("/api/dashboard") == (200, None)  # sin guardar: el frontal pone el de por defecto
    dash = {"widgets": [{"id": "a1", "kind": "inv", "by": "status", "view": "pie", "x": 0, "y": 0, "w": 4, "h": 3, "title": "Estado"},
                        {"id": "b2", "kind": "health", "source": sid, "group": "disk", "hours": 168, "x": 4, "y": 0, "w": 8, "h": 4}]}
    assert call("/api/dashboard", "PUT", dash)[0] == 204 and call("/api/dashboard") == (200, dash)
    w0 = dash["widgets"][0]
    for bad in [{**w0, "id": "<img src=x>"}, {**w0, "x": 10}, {**w0, "kind": "iframe"}, {**w0, "onclick": "x"}, {**w0, "w": True},
                {**w0, "hours": 7}, {**w0, "view": ["pie"]}, {**w0, "title": "x" * 81}, {k: v for k, v in w0.items() if k != "h"}]:
        assert call("/api/dashboard", "PUT", {"widgets": [bad]})[0] == 400, bad
    assert call("/api/dashboard", "PUT", {"widgets": [w0, w0]})[0] == 400  # id repetido
    assert call("/api/dashboard") == (200, dash)  # lo rechazado no pisa lo guardado
    lat = call("/api/latency?hours=1")[1]
    assert lat[str(ok_id)] and all(isinstance(v, (int, float)) for _, v in lat[str(ok_id)]) and str(down_id) not in lat  # el caído no tiene latencia
    # Resúmenes por hora y disponibilidad: en cargo test; aquí, la API
    assert call("/api/sla?month=2026-13")[0] == 400 and call("/api/sla")[0] == 200
    # Descubrir red: solo IPv4 pequeñas; marca lo que ya está en el inventario y en el monitor
    for bad in [{"net": "nada"}, {"net": "10.0.0.0/16"}, {"net": "::1/128"}, {"net": "127.0.0.1/32", "community": 5}]:
        assert call("/api/discover", "POST", bad)[0] == 400, bad
    loc = call("/api/items", "POST", {"name": "este", "ip": "127.0.0.1"})[1]
    st, found = call("/api/discover", "POST", {"net": "127.0.0.1/32"})
    assert st == 200 and len(found) == 1 and found[0]["ip"] == "127.0.0.1" and found[0]["item"] == loc["id"] and found[0]["watched"] is True, found
    # Altas en bloque: todo se valida antes de guardar nada; sin contraseña se genera una provisional
    basic = lambda n, pw: "Basic " + base64.b64encode(f"{n}:{pw}".encode()).decode()
    for bad in [[], [{"name": "a b"}], [{"name": "uno"}, {"name": "UNO"}], [{"name": "ok1"}, {"name": "admin"}], [{"name": "ok2", "groups": [999]}], [{"name": "ok3", "pass": "corta"}]]:
        assert call("/api/users", "POST", bad)[0] == 400, bad
    assert not {"ok1", "ok2", "ok3", "uno"} & {u["name"] for u in call("/api/users")[1]}  # nada a medias
    assert call("/api/groups", "POST", [{"name": "Aula A"}, {"name": "aula a"}])[0] == 400 and call("/api/groups", "POST", {"role": "edit"})[0] == 400  # repetido; sin nombre
    aulas = call("/api/groups", "POST", [{"name": "Aula A"}, {"name": "Aula B", "role": "view"}])[1]
    assert [(g["name"], g["role"]) for g in aulas] == [("Aula A", "edit"), ("Aula B", "view")]
    t0 = time.time()
    st, us = call("/api/users", "POST", [{"name": f"alumno{i:02}", "groups": [aulas[0]["id"]]} for i in range(20)] + [{"name": "profe", "pass": "clave-del-profe", "admin": True}])
    assert st == 201 and len(us) == 21 and time.time() - t0 < 30, (st, time.time() - t0)  # PBKDF2 en paralelo
    assert all(len(u["pass"]) >= 12 for u in us[:20]) and len({u["pass"] for u in us[:20]}) == 20 and us[20]["pass"] is None and us[20]["admin"] == 1
    assert call("/api/me", auth=basic(us[3]["name"], us[3]["pass"]))[1]["must_change"] == 1  # la generada vale, y es provisional
    assert len([g for g in call("/api/groups")[1] if g["id"] == aulas[0]["id"]][0]["members"]) == 20
    for u in us:
        call(f"/api/users/{u['id']}", "DELETE")
    for g in aulas:
        call(f"/api/groups/{g['id']}", "DELETE")
    # Grupos y solo vista: «lector» solo en un grupo de solo vista no puede cambiar nada
    lid = call("/api/users", "POST", {"name": "lector", "pass": "provisional1"})[1]["id"]
    LEC = "Basic " + base64.b64encode(b"lector:lectura-segura").decode()
    assert call("/api/me/password", "POST", {"old": "provisional1", "new": "lectura-segura"}, auth="Basic " + base64.b64encode(b"lector:provisional1").decode())[0] == 204
    for bad in [{"name": ""}, {"name": "x", "role": "root"}, {"name": "x", "members": [999]}]:
        assert call("/api/groups", "POST", bad)[0] == 400, bad
    vista = call("/api/groups", "POST", {"name": "Dirección", "role": "view", "members": [lid]})[1]
    n1 = call("/api/groups", "POST", {"name": "Técnicos N1", "members": [1]})[1]
    assert call("/api/groups", "POST", {"name": "técnicos n1"})[0] == 400  # repetido, sin distinguir mayúsculas
    assert call("/api/me", auth=LEC)[1]["readonly"] is True and call("/api/items", auth=LEC)[0] == 200
    assert call("/api/items", "POST", {"name": "x"}, auth=LEC)[0] == 403 and call("/api/incidents", "POST", {"title": "x"}, auth=LEC)[0] == 403
    assert call("/api/groups", "POST", {"name": "y"}, auth=LEC)[0] == 403 and call("/api/users", auth=LEC)[1] == [{"id": 1, "name": "admin"}, {"id": lid, "name": "lector"}]
    assert call(f"/api/groups/{n1['id']}", "PUT", {"members": [1, lid]})[0] == 200 and call("/api/me", auth=LEC)[1]["readonly"] is False  # también técnico: edita
    # Incidencias: crear, asignar, seguimiento; cada cambio queda en su historial
    srv_item = call("/api/items", "POST", {"name": "srv-correo"})[1]["id"]
    for bad in [{}, {"title": " "}, {"title": "x", "status": "rara"}, {"title": "x", "assignee": 999}, {"title": "x", "grp": 999}, {"title": "x", "item": "1"}]:
        assert call("/api/incidents", "POST", bad)[0] == 400, bad
    st, inc = call("/api/incidents", "POST", {"title": "No llega el correo", "body": "Afecta a [[#%d]]" % srv_item, "priority": "crítica", "grp": n1["id"], "item": srv_item})
    assert st == 201 and inc["status"] == "abierta" and inc["grp_name"] == "Técnicos N1" and inc["author_name"] == "admin"
    assert any("incidencia crítica INC-%d" % inc["id"] in h["text"] for h in hooks)  # lo crítico avisa por los canales
    upd = call(f"/api/incidents/{inc['id']}", "PUT", {"status": "en curso", "assignee": lid, "priority": "crítica"}, auth=LEC)[1]
    assert upd["status"] == "en curso" and upd["assignee_name"] == "lector"
    assert call(f"/api/incidents/{inc['id']}/notes", "POST", {"text": "Reiniciado el servicio SMTP"}, auth=LEC)[0] == 201
    assert call(f"/api/incidents/{inc['id']}/notes", "POST", {"text": ""})[0] == 400
    hist = call(f"/api/incidents/{inc['id']}")[1]["history"]
    assert [(h["who"], h["text"]) for h in hist] == [("admin", "abrió la incidencia"), ("lector", "cambió el estado a «en curso»"), ("lector", "asignó a lector"),
                                                     ("lector", "Reiniciado el servicio SMTP")], hist  # la prioridad no cambió: no se anota
    assert call("/api/incidents")[1][0]["notes"] == 1 and call(f"/api/items/{srv_item}/refs")[1]["incidents"][0]["id"] == inc["id"]
    # Incidencias hijas: resolver la padre resuelve toda la rama abierta; sin círculos
    new_inc = lambda t, **k: call("/api/incidents", "POST", {"title": t, **k})[1]["id"]
    padre = new_inc("Caída de la planta 2")
    hija, hecha = new_inc("PCs sin red", parent=padre), new_inc("Impresora sin red", parent=padre, status="resuelta")
    nieta, bisnieta = new_inc("PC de recepción", parent=hija), new_inc("Monitor de recepción", parent=hecha)
    assert call("/api/incidents", "POST", {"title": "x", "parent": 99999})[0] == 400
    assert call(f"/api/incidents/{padre}", "PUT", {"parent": padre})[0] == 400  # de sí misma
    assert call(f"/api/incidents/{padre}", "PUT", {"parent": nieta})[0] == 400  # de su nieta: círculo
    p = call(f"/api/incidents/{padre}")[1]
    assert [k["id"] for k in p["kids"]] == [hija, hecha] and p["children"] == 2 and call(f"/api/incidents/{hija}")[1]["parent_title"] == "Caída de la planta 2"
    assert call(f"/api/incidents/{padre}", "PUT", {"status": "resuelta"})[1]["closed_children"] == 3  # hija, nieta y bisnieta (la hecha ya lo estaba)
    assert all(call(f"/api/incidents/{i}")[1]["status"] == "resuelta" for i in (hija, nieta, bisnieta, hecha))
    assert call(f"/api/incidents/{nieta}")[1]["history"][-1]["text"] == f"pasó a «resuelta» con su incidencia padre INC-{hija}"
    # Trazabilidad: [[INC-n]] en la wiki, en las notas de un equipo y en el seguimiento de otra incidencia
    pg = call("/api/pages", "POST", {"title": "Caída planta 2", "body": f"Ver [[INC-{padre}]] y [[inc-{hija}]]"})[1]
    call(f"/api/items/{srv_item}", "PUT", {"notes": f"Tocado en [[INC-{padre}]]"})
    call(f"/api/incidents/{hecha}/notes", "POST", {"text": f"Relacionada con [[INC-{padre}]]"})
    m = call(f"/api/incidents/{padre}")[1]["mentions"]
    assert [x["id"] for x in m["pages"]] == [pg["id"]] and [x["id"] for x in m["items"]] == [srv_item] and [x["id"] for x in m["incidents"]] == [hecha], m
    assert call(f"/api/incidents/{hija}")[1]["mentions"]["pages"][0]["id"] == pg["id"] and call(f"/api/incidents/{nieta}")[1]["mentions"]["pages"] == []  # [[INC-1]] no es [[INC-12]]
    call(f"/api/pages/{pg['id']}", "DELETE")
    assert call(f"/api/incidents/{padre}", "DELETE")[0] == 204 and call(f"/api/incidents/{hija}")[1]["parent"] is None  # las hijas quedan sueltas
    assert call(f"/api/groups/{n1['id']}", "DELETE")[0] == 204 and call(f"/api/incidents/{inc['id']}")[1]["grp"] is None
    assert call(f"/api/incidents/{inc['id']}", "DELETE", auth=LEC)[0] == 403 and call(f"/api/incidents/{inc['id']}", "DELETE")[0] == 204
    assert {("incident", "crear"), ("incident", "borrar"), ("group", "crear")} <= {(h["kind"], h["action"]) for h in call("/api/log")[1]}
    # Tablero personal: cada uno ve y toca solo lo suyo, también quien es de solo vista
    assert call("/api/me", auth=LEC)[1]["readonly"] is True
    st, t1 = call("/api/tasks", "POST", {"text": "Revisar copias", "col": "hoy"}, auth=LEC)
    assert st == 201 and t1["col"] == "hoy" and t1["pos"] == 0, t1
    t2 = call("/api/tasks", "POST", {"text": "  Llamar al proveedor  "}, auth=LEC)[1]
    t3 = call("/api/tasks", "POST", {"text": "otra", "col": "pendiente"}, auth=LEC)[1]
    assert t2["text"] == "Llamar al proveedor" and t2["col"] == "pendiente" and t3["pos"] == t2["pos"] + 1  # al final de su columna
    for bad in [{"text": ""}, {"text": "x" * 2001}, {"text": "x", "col": "luego"}, {"text": "x", "pos": "a"}, ["x"]]:
        assert call("/api/tasks", "POST", bad, auth=LEC)[0] == 400, bad
    assert call(f"/api/tasks/{t2['id']}", "PUT", {"col": "hoy", "pos": -1}, auth=LEC)[0] == 200
    assert [t["text"] for t in call("/api/tasks", auth=LEC)[1] if t["col"] == "hoy"] == ["Llamar al proveedor", "Revisar copias"]
    assert call("/api/tasks")[1] == [] and call(f"/api/tasks/{t1['id']}", "PUT", {"text": "mío"})[0] == 404 and call(f"/api/tasks/{t1['id']}", "DELETE")[0] == 404
    assert call(f"/api/tasks/{t1['id']}", "DELETE", auth=LEC)[0] == 204 and len(call("/api/tasks", auth=LEC)[1]) == 2
    call(f"/api/groups/{vista['id']}", "DELETE")
    # Kitty: el instalador de PowerShell lleva esta dirección y el id de esta instalación (al que queda atado);
    # se presenta sin sesión, queda pendiente y, aceptado, catlan mantiene su ficha
    st, ps = call("/kitty.ps1", auth="")
    ps = ps.decode()
    CAT = ps.split("$Catlan = '")[1][:32]
    assert st == 200 and f"$Url = 'https://127.0.0.1:{PORT}'" in ps and all(c in "0123456789abcdef" for c in CAT) and "{{" not in ps
    try:
        urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{PORT}/kitty.ps1", headers={"Host": "x'; calc #"}))
        raise AssertionError("Host raro aceptado")
    except urllib.error.HTTPError as e:
        assert e.code == 400
    kitty = lambda key, **f: call("/api/agent", "POST", {"key": key, "name": "pc-kitty", "ip": "10.0.0.50", "serial": "KSN1", "os": "windows/amd64", "kind": "pc", **f}, auth="")
    K1, K2, n_items = "a" * 64, "b" * 64, len(call("/api/items")[1])
    assert kitty("corta")[0] == 400 and kitty(K1, name="")[0] == 400
    assert kitty(K1) == (200, {"state": "pendiente", "catlan": CAT}) and kitty(K1)[1]["state"] == "pendiente" and len(call("/api/items")[1]) == n_items
    ag = next(a for a in call("/api/agents")[1] if a["name"] == "pc-kitty")
    assert "key" not in ag and ag["code"] == sha(K1)[:8] and ag["state"] == "pendiente"
    kitty("c" * 64, name="pc-sin-ip", ip="")  # el Kitty de PowerShell no manda IP: la de su conexión
    assert next(a for a in call("/api/agents")[1] if a["name"] == "pc-sin-ip")["ip"] == "127.0.0.1"
    assert call("/api/agents", auth=LEC)[0] == 403 and call(f"/api/agents/{ag['id']}", "PUT", {"state": "adoptado"}, auth=LEC)[0] == 403
    it = call(f"/api/items/{call(f'/api/agents/{ag['id']}', 'PUT', {'state': 'adoptado'})[1]['item']}")[1]  # la ficha sale ya al aceptar
    assert (it["name"], it["ip"], it["serial"], it["kind"], it["status"]) == ("pc-kitty", "10.0.0.50", "KSN1", "pc", "activo")
    assert kitty(K1) == (200, {"state": "adoptado", "item": it["id"], "catlan": CAT, "apps": [], "software": None, "run": []}) and len(call("/api/items")[1]) == n_items + 1
    call(f"/api/items/{it['id']}", "PUT", {"name": "Portátil de Ana", "notes": "mío"})
    nlog = len(call(f"/api/log?kind=item&ref={it['id']}")[1])
    kitty(K1, ip="10.0.0.51"), kitty(K1, ip="10.0.0.51")
    it2, logs = call(f"/api/items/{it['id']}")[1], call(f"/api/log?kind=item&ref={it['id']}")[1]
    assert (it2["name"], it2["notes"], it2["ip"]) == ("Portátil de Ana", "mío", "10.0.0.51")  # lo del usuario no se toca
    assert len(logs) == nlog + 1 and logs[0]["who"] == "Kitty · pc-kitty"  # sin cambios no escribe
    call(f"/api/items/{it['id']}", "DELETE")
    assert call(f"/api/items/{kitty(K1)[1]['item']}")[1]["name"] == "pc-kitty" and len(call("/api/items")[1]) == n_items + 1  # borrada en catlan: ficha nueva
    kitty(K2, name="intruso")
    b2 = next(a for a in call("/api/agents")[1] if a["name"] == "intruso")
    assert call(f"/api/agents/{b2['id']}", "PUT", {"state": "x"})[0] == 400
    assert call(f"/api/agents/{b2['id']}", "PUT", {"state": "rechazado"})[1] == {"state": "rechazado", "item": None} and kitty(K2, name="intruso")[1]["state"] == "rechazado"
    assert len(call("/api/items")[1]) == n_items + 1
    assert call(f"/api/agents/{b2['id']}", "DELETE")[0] == 204 and kitty(K2, name="intruso")[1]["state"] == "pendiente"  # olvidado: vuelve a pedir
    # Salud: el Kitty aceptado es un equipo más (tipo kitty) con lo que envía; los datos raros se ignoran
    facts = {"osver": "Microsoft Windows 11 Pro 10.0.26300", "model": "MSI MS-7C56", "cpu": "AMD Ryzen 7", "cores": 16, "load": 22.5,
             "mem_total": 64 * 2 ** 30, "mem_free": 16 * 2 ** 30, "uptime": 7200, "ips": ["10.0.0.51", 5],
             "disks": [{"name": "C:", "total": 1000, "free": 50}, {"name": "G:", "total": 1000, "free": 600}, {"name": "X:", "total": "mucho"}, "nada"]}
    assert kitty(K1, every=1, facts={"disks": "nada", "load": True})[0] == 200  # forma rara: no rompe
    kitty(K1, every=1, facts=facts)
    hk = next(h for h in call("/api/health")[1] if h["kind"] == "kitty")
    assert hk["agent"] == ag["id"] and hk["every"] == 60 and hk["host"] == "10.0.0.50" and hk["state"] == "warn" and hk["problems"] == ["C: 95 % lleno (límite 90 %)"]
    assert {m["key"]: m["value"] for m in hk["latest"]} == {"cpu": 22.5, "mem": 75.0, "disk:C:": 95.0, "disk:G:": 40.0}
    assert hk["info"]["descr"] == facts["osver"] and hk["info"]["uptime"] == 7200 and hk["info"]["ips"] == ["10.0.0.51"] and len(hk["info"]["disks"]) == 3
    assert call(f"/api/metrics?source={hk['id']}&hours=1")[1]["cpu"]["points"]
    # tres envíos sin noticias: «no responde» (y avisa); al volver, otra vez bien
    import sqlite3
    with sqlite3.connect(Path(env["CATLAN_DATA"]) / "catlan.db") as con:
        con.execute("UPDATE sources SET last = datetime('now', '-200 seconds') WHERE id=?", [hk["id"]])
    for _ in range(40):
        if next(h for h in call("/api/health")[1] if h["id"] == hk["id"])["state"] == "error":
            break
        time.sleep(0.25)
    lost = next(h for h in call("/api/health")[1] if h["id"] == hk["id"])
    assert lost["state"] == "error" and lost["error"].startswith("Kitty no responde"), lost
    kitty(K1, every=1, facts={**facts, "disks": [{"name": "C:", "total": 1000, "free": 500}]})
    assert next(h for h in call("/api/health")[1] if h["id"] == hk["id"])["state"] == "ok"
    # Visor de eventos: se guardan 7 días sin repetir; un crítico de las últimas 24 h avisa, un error solo se ve
    utc = lambda **d: (datetime.now(timezone.utc) - timedelta(**d)).strftime("%Y-%m-%dT%H:%M:%SZ")
    ev = lambda rec, level, **d: {"rec": rec, "log": "System", "time": utc(**d), "level": level, "source": "Kernel-Power", "code": 41, "msg": "Apagado inesperado."}
    ok_disks = {**facts, "disks": [{"name": "C:", "total": 1000, "free": 500}]}
    kitty(K1, every=1, facts=ok_disks, events=[ev(7, 2, hours=1), ev(8, 1, minutes=5), ev(8, 1, minutes=5), ev(1, 1, days=8), ev(2, 3, minutes=1),
                                               {"rec": "x"}, "nada", {**ev(9, 2, minutes=1), "time": "ayer"}])
    hk2 = next(h for h in call("/api/health")[1] if h["id"] == hk["id"])
    assert [e["rec"] for e in hk2["info"]["events"]] == [8, 7] and hk2["state"] == "warn"
    assert hk2["problems"] == ["Crítico en el registro: Kernel-Power 41 · Apagado inesperado."], hk2["problems"]
    # Programas en los PCs: solo los admins eligen; Kitty recibe la lista y devuelve cómo le fue a winget
    for bad in ({"name": "x", "winget": "-h"}, {"name": "x", "winget": "a b"}, {"name": "", "winget": "Google.Chrome"}, {"name": "x"}):
        assert call("/api/apps", "POST", bad)[0] == 400, bad
    assert call("/api/apps", "POST", {"name": "Chrome", "winget": "Google.Chrome"}, auth=LEC)[0] == 403
    chrome = call("/api/apps", "POST", {"name": "Chrome", "winget": "Google.Chrome"})[1]
    assert kitty(K1, every=1, facts=ok_disks)[1]["apps"] == ["Google.Chrome"]
    kitty(K1, every=1, facts=ok_disks, apps={"Google.Chrome": {"ok": True, "msg": "instalado"}})
    assert next(h for h in call("/api/health")[1] if h["id"] == hk["id"])["info"]["apps"] == {"Google.Chrome": {"ok": True, "msg": "instalado"}}
    assert call(f"/api/apps/{chrome['id']}", "DELETE")[0] == 204 and kitty(K1, every=1, facts=ok_disks)[1]["apps"] == []
    # Parches y seguridad: el semáforo y el aviso de más de 30 días sin parchear; con la MAC, el PC se enciende por la red
    iid0 = kitty(K1, every=1, facts=ok_disks)[1]["item"]
    assert call(f"/api/items/{iid0}/wake", "POST")[0] == 400  # aún no ha mandado su MAC
    posture = {**ok_disks, "macs": ["00:1a:2b:3c:4d:5e"], "patch": {"last": "2020-01-01", "kb": "KB1", "reboot": True, "pending": 4},
               "sec": {"defender": True, "sigdays": 1, "av": [], "fwoff": ["Public"], "bitlocker": 0, "admin": False}}
    kitty(K1, every=1, facts=posture)
    hp = next(h for h in call("/api/health")[1] if h["id"] == hk["id"])
    assert hp["info"]["seclight"] == "bad" and hp["info"]["secwhy"] == ["Firewall apagado: Public", "BitLocker apagado en el disco del sistema"], hp["info"]
    assert hp["info"]["patch"] == {"last": "2020-01-01", "kb": "KB1", "reboot": True, "pending": 4} and any(p.startswith("Sin parches de Windows desde hace") for p in hp["problems"])
    wk = call(f"/api/items/{iid0}/wake", "POST")
    assert wk == (200, {"macs": ["00:1a:2b:3c:4d:5e"]}), wk
    assert call(f"/api/items/{iid0}/wake", "POST", auth="")[0] == 401
    assert call(f"/api/log?kind=item&ref={iid0}")[1][0]["action"] == "encender"
    kitty(K1, every=1, facts=ok_disks)
    # Inventario de programas: apagado no se guarda nada; encendido, Kitty sabe cuántos tiene catlan y se busca por nombre
    prog = [{"name": "AnyDesk", "version": "9.0.1", "publisher": "AnyDesk Software"}, {"name": "7-Zip 24.09 (x64)", "version": "24.09"}, {"name": ""}, "nada"]
    assert kitty(K1, every=1, facts=ok_disks, software=prog)[1]["software"] is None and call("/api/software?item=" + str(it["id"]))[1] == {"on": False, "rows": []}
    assert call("/api/software", "PUT", {"on": True}, auth=LEC)[0] == 403 and call("/api/software", "PUT", {"on": "sí"})[0] == 400
    assert call("/api/software", "PUT", {"on": True})[1] == {"on": True}
    iid = kitty(K1, every=1, facts=ok_disks)[1]["item"]
    assert kitty(K1, every=1, facts=ok_disks)[1]["software"] == 0 and kitty(K1, every=1, facts=ok_disks, software=prog)[1]["software"] == 2
    assert kitty(K1, every=1, facts=ok_disks, software="mucho")[1]["software"] == 2  # forma rara: se queda lo que había
    hits = call("/api/software?q=anyd", auth=LEC)[1]
    assert hits["rows"] == [{"item": iid, "item_name": "pc-kitty", "name": "AnyDesk", "version": "9.0.1"}], hits
    assert call("/api/software?q=a")[1]["rows"] == [] and call("/api/software?q=%25")[1]["rows"] == []  # % es literal
    assert [r["name"] for r in call(f"/api/software?item={iid}")[1]["rows"]] == ["7-Zip 24.09 (x64)", "AnyDesk"]
    assert call("/api/software", "PUT", {"on": False})[1] == {"on": False} and call(f"/api/software?item={iid}")[1]["rows"] == []  # apagar lo borra
    # Scripts: solo admins; Kitty los recibe en su envío y devuelve la salida en el siguiente
    assert call("/api/scripts", "POST", {"name": "x", "body": "dir"}, auth=LEC)[0] == 403 and call("/api/scripts", auth=LEC)[0] == 403
    assert call("/api/scripts", "POST", {"name": "", "body": "dir"})[0] == 400 and call("/api/scripts", "POST", {"name": "x", "body": " "})[0] == 400
    scr = call("/api/scripts", "POST", {"name": "Quién hay", "body": "whoami"})[1]
    assert call(f"/api/scripts/{scr['id']}/run", "POST", {"items": []})[0] == 400
    assert call(f"/api/scripts/{scr['id']}/run", "POST", {"items": [iid]}, auth=LEC)[0] == 403
    lone = call("/api/items", "POST", {"name": "sin-kitty"})[1]
    rr = call(f"/api/scripts/{scr['id']}/run", "POST", {"items": [iid, lone["id"]]})[1]
    assert len(rr["runs"]) == 1 and rr["skipped"] == [lone["id"]]
    got = kitty(K1, every=1, facts=ok_disks)[1]["run"]
    assert got == [{"id": rr["runs"][0], "body": "whoami"}] and kitty(K1, every=1, facts=ok_disks)[1]["run"] == []  # una sola vez
    kitty(K1, every=1, facts=ok_disks, runs=[{"id": rr["runs"][0], "code": 0, "out": "nt authority\\system"}, {"id": 99999, "code": 0, "out": "x"}])
    run = call(f"/api/runs?item={iid}")[1][0]
    assert (run["state"], run["code"], run["output"], run["name"]) == ("hecho", 0, "nt authority\\system", "Quién hay"), run
    assert call(f"/api/runs?item={iid}", auth=LEC)[0] == 403 and call(f"/api/log?kind=item&ref={iid}")[1][0]["action"] == "ejecutar"
    # Actualizar catlan: solo admins; sin pedirlo no se habla con GitHub (aquí no se pulsa «Buscar»)
    up = call("/api/update")[1]
    assert up["auto"] is False and up["last"] is None and up["current"] and call("/api/update", auth=LEC)[0] == 403
    assert call("/api/update", "PUT", {"auto": True})[1]["auto"] is True and call("/api/update", "PUT", {"auto": "sí"})[0] == 400
    assert call("/api/update", "PUT", {"auto": False})[1]["auto"] is False
    kitty(K1, every=1, facts=ok_disks, events=[ev(10, 2, minutes=1)])  # el siguiente envío trae solo lo nuevo: lo de antes sigue
    assert [e["rec"] for e in next(h for h in call("/api/health")[1] if h["id"] == hk["id"])["info"]["events"]] == [10, 8, 7]
    kitty(K1, every=1, facts=ok_disks, events=[])
    # Avisos desde la ventana de Kitty: con su clave de incidencias (la que leen los usuarios del PC), solo si IT aceptó el equipo
    UK, UK2 = "u" * 64, "w" * 64
    agent = lambda path, body: call(f"/api/agent/{path}", "POST", body, auth="")
    assert agent("mine", {"ukey": UK})[0] == 404  # aún no la ha contado el agente
    kitty(K1, ukey=UK), kitty(K2, name="intruso", ukey=UK2)
    assert agent("mine", {"ukey": UK2})[0] == 403  # pendiente: nada
    assert agent("incident", {"ukey": UK2, "title": "x"})[0] == 403 and agent("incident", {"ukey": "corta", "title": "x"})[0] == 400
    for bad in ({"ukey": UK}, {"ukey": UK, "title": " "}, {"ukey": UK, "title": "x", "priority": "urgentísima"}, {"ukey": UK, "title": "x", "body": "y" * 5001}):
        assert agent("incident", bad)[0] == 400, bad
    st, ki = agent("incident", {"ukey": UK, "title": "No imprime", "body": "Sale en rojo", "priority": "crítica"})
    assert st == 201 and ki["status"] == "abierta", ki
    full = call(f"/api/incidents/{ki['id']}")[1]
    assert full["item"] == hk["item"] and full["author"] is None and full["history"][0]["who"] == "Kitty · pc-kitty", full
    assert any(f"incidencia crítica INC-{ki['id']}" in h["text"] for h in hooks)  # lo urgente avisa a IT como cualquier incidencia
    call("/api/incidents", "POST", {"title": "abierta por IT", "item": hk["item"]})
    st, mine = agent("mine", {"ukey": UK})
    assert st == 200 and [i["title"] for i in mine["incidents"]] == ["No imprime"], mine  # solo lo que avisó el PC
    # captura al abrir el aviso: un JPEG, guardado con la incidencia y enlazado en su seguimiento
    assert agent("incident", {"ukey": UK, "title": "x", "shot": base64.b64encode(b"no es jpeg").decode()})[0] == 400
    st, k2 = agent("incident", {"ukey": UK, "title": "Pantalla rara", "shot": base64.b64encode(b"\xff\xd8\xffcaptura").decode()})
    note = [h for h in call(f"/api/incidents/{k2['id']}")[1]["history"] if not h["change"]][0]
    fid = int(note["text"].split("/api/files/")[1].rstrip(")"))
    assert st == 201 and call(f"/api/files/{fid}") == (200, b"\xff\xd8\xffcaptura") and call(f"/api/files/{fid}", auth="")[0] == 401
    # chat: el usuario ve su aviso y las notas públicas de IT, y contesta
    call(f"/api/incidents/{ki['id']}/notes", "POST", {"text": "nota interna"})
    call(f"/api/incidents/{ki['id']}/notes", "POST", {"text": "¿Has probado a reiniciarla?", "public": True})
    st, th = agent("thread", {"ukey": UK, "id": ki["id"]})
    assert st == 200 and th["incident"]["body"] == "Sale en rojo" and [n["text"] for n in th["notes"]] == ["¿Has probado a reiniciarla?"], th
    assert agent("thread", {"ukey": UK, "id": full["id"] + 1000})[0] == 404 and agent("thread", {"ukey": UK2, "id": ki["id"]})[0] == 403
    it_inc = next(i for i in call("/api/incidents")[1] if i["title"] == "abierta por IT")
    assert agent("thread", {"ukey": UK, "id": it_inc["id"]})[0] == 404  # solo las que abrió este PC
    assert agent("reply", {"ukey": UK, "id": ki["id"], "text": " "})[0] == 400
    assert agent("reply", {"ukey": UK, "id": ki["id"], "text": "Sí, y sigue igual"}) == (201, {"ok": True})
    assert [n["who"] for n in agent("thread", {"ukey": UK, "id": ki["id"]})[1]["notes"]][-1] == "Kitty · pc-kitty"
    mine2 = agent("mine", {"ukey": UK})[1]
    row = next(i for i in mine2["incidents"] if i["id"] == ki["id"])
    assert row["notes"] == 2 and row["last_it"] == th["notes"][0]["id"]
    # autoayuda: solo las páginas marcadas para Kitty
    call("/api/pages", "POST", {"title": "Impresora atascada", "body": "Abre la tapa y saca el papel.", "kitty": True})
    call("/api/pages", "POST", {"title": "Contraseñas de la impresora", "body": "secreta"})
    assert call("/api/pages", "POST", {"title": "x", "kitty": "sí"})[0] == 400
    hp2 = agent("help", {"ukey": UK, "q": "la impresora no imprime"})[1]["pages"]
    assert [p["title"] for p in hp2] == ["Impresora atascada"] and agent("help", {"ukey": UK, "q": "no"})[1] == {"pages": []}
    # avisos masivos: a todos o a unos equipos, hasta que caducan o se quitan
    for bad in ({"text": "", "hours": 2}, {"text": "x", "hours": 0}, {"text": "x", "hours": 2, "items": [999999]}, {"text": "x", "hours": 2, "items": []}):
        assert call("/api/notices", "POST", bad)[0] == 400, bad
    assert call("/api/notices", "POST", {"text": "x", "hours": 2}, auth="")[0] == 401
    n1 = call("/api/notices", "POST", {"text": "El correo estará caído de 14 a 15 h", "hours": 2})[1]
    other = call("/api/items", "POST", {"name": "otro-pc"})[1]
    call("/api/notices", "POST", {"text": "Solo para otro", "hours": 2, "items": [other["id"]]})
    assert [n["text"] for n in agent("mine", {"ukey": UK})[1]["notices"]] == ["El correo estará caído de 14 a 15 h"]
    assert call(f"/api/notices/{n1['id']}", "DELETE")[0] == 204 and agent("mine", {"ukey": UK})[1]["notices"] == []
    assert [agent("incident", {"ukey": UK, "title": f"n{i}"})[0] for i in range(10)][-1] == 429  # 10 por hora
    assert agent("nada", {"ukey": UK})[0] == 404
    # Cerrar Kitty: solo con un administrador de catlan
    assert agent("quit", {"ukey": UK2, "name": "admin", "pass": "miau"})[0] == 403  # equipo pendiente
    assert agent("quit", {"ukey": UK, "name": "lector", "pass": "lectura-segura"})[0] == 403  # no es admin
    assert agent("quit", {"ukey": UK, "name": "admin", "pass": "miau"}) == (200, {"ok": True})
    # Control remoto: Kitty pregunta; el técnico lo pide; el usuario del PC acepta; pantalla de ida y ratón de vuelta
    assert call("/api/remote", "POST", {"agent": ag["id"]})[0] == 409  # Kitty no ha preguntado nunca: no está abierto
    assert agent("remote", {"ukey": UK2})[0] == 403 and agent("remote", {"ukey": UK}) == (200, {})
    st, rs = call("/api/remote", "POST", {"agent": ag["id"]})
    assert st == 201 and rs["status"]["state"] == "pedida", rs
    sid = rs["id"]
    assert call("/api/remote", "POST", {"agent": ag["id"]})[0] == 409 and call("/api/remote", "POST", {"agent": 99999})[0] == 404  # una a la vez
    assert agent("remote", {"ukey": UK})[1] == {"id": sid, "who": "admin"}
    assert call(f"/api/items/{hk['item']}/refs")[1]["agent"] == ag["id"]  # la ficha del equipo enseña el botón

    def frame(body, key=UK):
        req = urllib.request.Request(f"http://127.0.0.1:{PORT}/api/agent/remote/frame", body, method="POST", headers={"X-Kitty": key, "X-Sesion": sid, "Content-Type": "image/jpeg"})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, None
    assert frame(b"\xff\xd8x")[1] == {"state": "pedida", "why": ""}  # sin permiso: ni pantalla ni ratón
    # el técnico la ve por un WebSocket: solo con sesión, solo la suya y nunca abierto desde otra web
    tech, st = ws_open(PORT, f"/api/remote/{sid}/ws", {"Authorization": AUTH})
    assert st == 101 and json.loads(ws_recv(tech))["state"] == "pedida"
    assert ws_open(PORT, f"/api/remote/{sid}/ws", {})[1] == 401 and ws_open(PORT, "/api/remote/nada/ws", {"Authorization": AUTH})[1] == 404
    assert ws_open(PORT, f"/api/remote/{sid}/ws", {"Authorization": AUTH, "Origin": "https://malo.example"})[1] == 403
    assert agent("remote/answer", {"ukey": UK, "id": sid, "ok": True})[1]["state"] == "aceptada"
    assert json.loads(ws_recv(tech))["state"] == "aceptada"  # sin preguntar: llega solo
    ws_send(tech, json.dumps([{"t": "m", "x": .5, "y": .5}, {"t": "k", "c": "KeyA", "k": "a", "d": True}]))
    ws_send(tech, json.dumps({"t": "m"}))
    assert "error" in json.loads(ws_recv(tech))  # una lista de eventos, o nada
    assert frame(b"no es jpeg")[0] == 400 and frame(b"\xff\xd8x", key="z" * 64)[0] == 404
    st, r = frame(b"\xff\xd8\xff\xe0pantalla")  # una Kitty de antes del WebSocket: un fotograma por petición
    assert st == 200 and [e["t"] for e in r["input"]] == ["m", "k"], r
    assert frame(b"")[1]["input"] == []  # pantalla sin cambios: va vacío, solo a por el ratón
    assert ws_recv(tech) == b"\xff\xd8\xff\xe0pantalla"  # la pantalla llega al técnico en cuanto la envía Kitty
    # la Kitty de ahora, también por WebSocket: fotogramas de ida, ratón y teclado de vuelta al momento
    assert ws_open(PORT, "/api/agent/remote/ws", {"X-Kitty": "z" * 64, "X-Sesion": sid})[1] == 404
    assert ws_open(PORT, "/api/agent/remote/ws", {"X-Kitty": UK, "X-Sesion": "otra"})[1] == 404
    kit, st = ws_open(PORT, "/api/agent/remote/ws", {"X-Kitty": UK, "X-Sesion": sid})
    assert st == 101
    ws_send(kit, b"\xff\xd8\xff\xe0otra")
    assert ws_recv(tech) == b"\xff\xd8\xff\xe0otra"
    ws_send(tech, json.dumps([{"t": "w", "d": 100}]))
    assert json.loads(ws_recv(kit))["input"] == [{"t": "w", "d": 100}]
    # archivos: el técnico manda uno (Kitty lo recoge) y pide otro (Kitty lo sube y el técnico lo descarga)
    def send_file(path, data, headers):
        req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", data, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, None
    up = send_file(f"/api/remote/{sid}/files", b"hola PC", {"Authorization": AUTH, "x-nombre": urllib.parse.quote("../informe ñ.txt")})
    assert up[0] == 201, up
    assert json.loads(ws_recv(kit))["input"] == [{"t": "file", "id": up[1]["id"], "name": "informe ñ.txt", "size": 7}]
    assert call("/api/agent/remote/file", "POST", {"ukey": UK, "sesion": sid, "id": up[1]["id"]}, auth="") == (200, b"hola PC")
    assert call("/api/agent/remote/file", "POST", {"ukey": UK2, "sesion": sid, "id": up[1]["id"]}, auth="")[0] == 403
    assert send_file("/api/agent/remote/upload", b"%PDF-1", {"x-kitty": UK, "x-sesion": sid, "x-nombre": "nota.pdf"})[0] == 201
    st_files = json.loads(ws_recv(tech))
    assert [(f["name"], f["size"]) for f in st_files["files"]] == [("nota.pdf", 6)], st_files
    assert call(f"/api/remote/{sid}/files/{st_files['files'][0]['id']}") == (200, b"%PDF-1")
    assert call(f"/api/remote/{sid}/files/{up[1]['id']}")[0] == 404  # lo que va al PC no vuelve al técnico
    assert agent("remote/answer", {"ukey": UK, "id": sid, "ok": False})[1]["state"] == "cerrada"  # lo corta el usuario del PC
    assert json.loads(ws_recv(tech))["why"] == "la cortó el usuario del PC" and json.loads(ws_recv(kit))["state"] == "cerrada"
    assert frame(b"\xff\xd8x")[1]["state"] == "cerrada"
    tech.close(), kit.close()
    # Salud se refresca sola: el WebSocket avisa cuando llega una lectura nueva
    hws, st = ws_open(PORT, "/api/health/ws", {"Authorization": AUTH})
    assert st == 101
    kitty(K1, every=1, facts=facts)
    assert ws_recv(hws) == "salud"
    hws.close()
    hist = [h["action"] for h in call(f"/api/log?kind=item&ref={hk['item']}")[1]]
    assert hist[:5] == ["control remoto terminado", "copiar archivo del PC", "enviar archivo al PC", "control remoto aceptado", "pedir control remoto"], hist
    assert urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{PORT}/kitty.exe")).status == 200 if (Path(BIN).parent / "kitty.exe").exists() else call("/kitty.exe", auth="")[0] == 404
    kexe = Path(BIN).parent / "kitty.exe"  # las Kitty instaladas comparan este sha256 con el suyo para actualizarse
    assert call("/kitty.json", auth="")[1]["kitty"] == (hashlib.sha256(kexe.read_bytes()).hexdigest() if kexe.exists() else "")
    # expulsado: fuera de Salud con su historial; la ficha del inventario se queda
    assert call(f"/api/agents/{ag['id']}", "PUT", {"state": "rechazado"})[0] == 200 and not [h for h in call("/api/health")[1] if h["kind"] == "kitty"]
    assert call(f"/api/metrics?source={hk['id']}&hours=1")[1] == {} and len(call("/api/items")[1]) == n_items + 3  # + otro-pc y sin-kitty
    assert {("agent", "aceptar"), ("agent", "rechazar"), ("agent", "olvidar")} <= {(h["kind"], h["action"]) for h in call("/api/log")[1]}
    assert call("/api/nope")[0] == 404
    # Auto-topología: LLDP, CDP y tabla MAC del switch -> quién está en qué puerto, casado con el inventario y dibujado
    srv_it = call("/api/items", "POST", {"name": "srv-web", "kind": "servidor", "ip": "192.168.99.10"})[1]  # por nombre (sin dominio)
    pc = call("/api/items", "POST", {"name": "pc-topo", "kind": "pc", "ip": "10.0.1.15"})[1]  # por la IP de la ARP
    sw_src = call("/api/sources", "POST", {"host": "127.0.0.1", "port": APORT, "community": "switch", "kind": "generic", "label": "sw-planta"})[1]
    st, tp = call(f"/api/sources/{sw_src['id']}/topology", "POST")
    assert st == 200 and tp["name"] == "Topología · sw-planta" and len(tp["neighbors"]) == 5, (st, tp)
    got = [(n["port"], n["via"], n["name"], n["ip"], n["mac"], n["rport"], n["icon"]) for n in tp["neighbors"]]
    assert got == [("Gi1/0/1", "lldp", "srv-web.empresa.lan", "10.0.0.10", "00:50:56:9a:00:01", "eth0", "pc"),
                   ("Gi1/0/2", "cdp", "core-rtr", "10.0.0.1", None, "Gi0/0", "router"),
                   ("Gi1/0/3", "mac", "", "10.0.1.15", "aa:bb:cc:00:00:03", "", None),
                   ("Gi1/0/4", "mac", "", None, "aa:bb:cc:00:00:41", "", None),
                   ("Gi1/0/4", "mac", "", None, "aa:bb:cc:00:00:42", "", None)], got  # Gi1/0/5 (6 MAC) es un enlace: fuera
    m = call(f"/api/maps/{tp['map']}")[1]["data"]
    byid = {n["id"]: n for n in m["nodes"]}
    assert m["auto"]["source"] == sw_src["id"] and byid["sw"]["t"] == "switch" and len(m["nodes"]) == 6
    assert [l[2] for l in m["links"]] == ["Gi1/0/1", "Gi1/0/2", "Gi1/0/3", "Gi1/0/4", "Gi1/0/4"]
    assert byid["p0"]["item"] == srv_it["id"] and byid["p0"]["t"] == "server" and byid["p1"]["t"] == "router" and byid["p1"]["label"] == "core-rtr (Gi0/0)"
    assert byid["p2"]["item"] == pc["id"] and byid["p3"]["label"] == "aa:bb:cc:00:00:41"
    assert all(0 < n["x"] < 1200 and 0 < n["y"] < 800 for n in m["nodes"])  # dentro del lienzo
    assert call(f"/api/sources/{sw_src['id']}/topology", "POST")[1]["map"] == tp["map"]  # otra vez: rehace el mismo esquema
    nada = call("/api/sources", "POST", {"host": "127.0.0.1", "port": APORT, "community": "secreta", "kind": "generic"})[1]  # el NAS: sin vecinos
    assert call(f"/api/sources/{nada['id']}/topology", "POST")[0] == 400
    for x in (sw_src, nada):
        call(f"/api/sources/{x['id']}", "DELETE")
    # Muchas peticiones a la vez con la misma sesión: ninguna puede salir 401 (q() lee las filas dentro del candado)
    ck = raw("/api/login", "POST", {"name": "admin", "pass": "miau"})[1]
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(8) as pool:
        codes = list(pool.map(lambda k: raw(("/api/items", "/api/maps", "/api/monitor", "/api/health")[k % 4], cookie=ck)[0], range(200)))
    assert set(codes) == {200}, {c: codes.count(c) for c in set(codes)}
    # Ids que no se reutilizan: el equipo nuevo no hereda el historial ni los enlaces del último borrado
    a = call("/api/items", "POST", {"name": "temporal"})[1]
    assert call(f"/api/items/{a['id']}", "DELETE")[0] == 204
    b = call("/api/items", "POST", {"name": "nuevo"})[1]
    assert b["id"] > a["id"] and [h["action"] for h in call(f"/api/log?kind=item&ref={b['id']}")[1]] == ["crear"], (a, b)
    # Una BD de antes (sin AUTOINCREMENT, con un equipo ya borrado en Actividad): se reconstruye una vez, sin perder nada
    import sqlite3
    olddir = Path(tempfile.mkdtemp())
    with sqlite3.connect(olddir / "catlan.db") as con:
        con.executescript("""CREATE TABLE items(id INTEGER PRIMARY KEY, name TEXT NOT NULL DEFAULT '', kind TEXT DEFAULT '', ip TEXT DEFAULT '',
              serial TEXT DEFAULT '', location TEXT DEFAULT '', status TEXT DEFAULT '', notes TEXT DEFAULT '', updated TEXT DEFAULT CURRENT_TIMESTAMP,
              warranty TEXT DEFAULT '');
            CREATE TABLE log(id INTEGER PRIMARY KEY, ts TEXT DEFAULT CURRENT_TIMESTAMP, who TEXT, action TEXT, kind TEXT, ref INTEGER, name TEXT, data TEXT);
            INSERT INTO items(id, name) VALUES(1, 'switch'), (2, 'nas');
            INSERT INTO items(id, name, warranty) VALUES(3, 'portatil-caduca-hoy', date('now', 'localtime'));
            INSERT INTO log(who, action, kind, ref, name, data) VALUES('admin', 'borrar', 'item', 7, 'viejo', '{}');
            CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE, hash TEXT NOT NULL,
              admin INTEGER DEFAULT 0, must_change INTEGER DEFAULT 0, created TEXT DEFAULT CURRENT_TIMESTAMP);""")
        # la contraseña del admin, guardada como la guardaba la versión en Python: tiene que seguir valiendo
        salt = os.urandom(16)
        con.execute("INSERT INTO users(name, hash, admin) VALUES('admin', ?, 1)", [f"pbkdf2${salt.hex()}${hashlib.pbkdf2_hmac('sha256', b'miau', salt, 600_000).hex()}"])
    vieja = subprocess.Popen([BIN],
                             env={**env, "CATLAN_DATA": str(olddir), "CATLAN_PORT": "18103"}, stdout=subprocess.DEVNULL)
    try:
        old = lambda path, method="GET", body=None: json.loads(urllib.request.urlopen(urllib.request.Request(
            f"http://127.0.0.1:18103{path}", None if body is None else json.dumps(body).encode(), {"Authorization": AUTH, "Content-Type": "application/json"}, method=method)).read())
        for _ in range(50):
            try: old("/api/items"); break
            except OSError: time.sleep(0.1)
        assert [i["name"] for i in old("/api/items")] == ["nas", "portatil-caduca-hoy", "switch"]
        # al arrancar, el aviso de garantías sale por los canales de verdad (correo y webhook de mentira de este test)
        for _ in range(150):
            if any("portatil-caduca-hoy: hoy" in m for m in mails) and any("portatil-caduca-hoy" in json.dumps(h) for h in hooks):
                break
            time.sleep(0.1)
        assert any("garant" in m and "portatil-caduca-hoy: hoy" in m for m in mails), mails[-1:]
        assert any("portatil-caduca-hoy" in json.dumps(h, ensure_ascii=False) for h in hooks), hooks[-1:]
        assert old("/api/items", "POST", {"name": "nuevo"})["id"] == 8  # ni el 3 (siguiente) ni el 7 (borrado): después
        assert list(olddir.glob("catlan-antes-de-ids-*.db"))
    finally:
        vieja.terminate()
    with sqlite3.connect(olddir / "catlan.db") as con:
        assert "AUTOINCREMENT" in con.execute("SELECT sql FROM sqlite_master WHERE name='items'").fetchone()[0]
        assert con.execute("SELECT 1 FROM sqlite_master WHERE name='log_ref'").fetchone()  # el índice vuelve
    # v1.0: garantía (fecha de verdad), datos con forma rara = 400 (no cortar la conexión) y copia de seguridad descargable
    g = call("/api/items", "POST", {"name": "portatil-garantia", "warranty": "2027-03-31"})[1]
    assert g["warranty"] == "2027-03-31" and call("/api/items", "POST", {"name": "x", "warranty": "31/03/2027"})[0] == 400
    assert call(f"/api/items/{g['id']}", "PUT", {"warranty": "2027-02-30"})[0] == 400 and call(f"/api/items/{g['id']}", "PUT", {"warranty": ""})[1]["warranty"] == ""
    assert call(f"/api/items/{g['id']}", "PUT", ["x"])[0] == 400 and call("/api/pages/1", "PUT", 5)[0] == 400
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/api/backup", headers={"Authorization": AUTH})
    with urllib.request.urlopen(req) as r:
        assert r.headers["Content-Disposition"].startswith('attachment; filename="catlan-') and r.read(16) == b"SQLite format 3\x00"
    assert call("/api/backup", auth=LEC)[0] == 403
    assert not list(Path(env["CATLAN_DATA"]).glob(".descarga-*"))  # el temporal no se queda
    # Copia cifrada: solo se abre con su contraseña, y cualquier cambio en el archivo se nota
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/api/backup", json.dumps({"password": "copia-segura"}).encode(), method="POST",
                                 headers={"Authorization": AUTH, "Content-Type": "application/json"})
    with urllib.request.urlopen(req) as r:
        assert r.headers["Content-Disposition"].endswith('.catlan"')
        blob = r.read()
    assert blob.startswith(SEAL) and b"SQLite format 3" not in blob
    assert unseal(blob, "copia-segura").startswith(b"SQLite format 3\x00")
    for bad in ((blob, "otra-clave"), (blob[:-40] + bytes([blob[-40] ^ 1]) + blob[-39:], "copia-segura"), (b"SQLite", "copia-segura")):
        try:
            unseal(*bad); raise AssertionError("abrió una copia mala")
        except ValueError:
            pass
    assert call("/api/backup", "POST", {"password": "corta"})[0] == 400 and call("/api/backup", "POST", {"password": "copia-segura"}, auth=LEC)[0] == 403
    with tempfile.TemporaryDirectory() as tmp:  # y se descifra desde la consola
        (Path(tmp) / "c.catlan").write_bytes(blob)
        out = subprocess.run([BIN, "descifrar", str(Path(tmp) / "c.catlan"), str(Path(tmp) / "c.db")],
                             input="copia-segura\n", capture_output=True, text=True, env={**os.environ, "CATLAN_DATA": tmp + "/nada"})
        assert (Path(tmp) / "c.db").read_bytes().startswith(b"SQLite format 3\x00") and not Path(tmp, "nada").exists(), out.stderr
    # Verificación en dos pasos (TOTP, RFC 6238)
    assert totp(base64.b32encode(b"12345678901234567890").decode(), 59) == "287082"  # vector del RFC
    call("/api/users", "POST", {"name": "dospasos", "pass": "provisional-1"})
    ck = raw("/api/login", "POST", {"name": "dospasos", "pass": "provisional-1"})[1]
    assert raw("/api/me/password", "POST", {"old": "provisional-1", "new": "segura-dos-pasos"}, cookie=ck)[0] == 204
    sec = raw("/api/me/totp", "POST", {}, cookie=ck)[2]["secret"]
    assert raw("/api/me/totp", "POST", {"secret": sec, "code": "000000" if totp(sec) != "000000" else "111111"}, cookie=ck)[0] == 400
    assert raw("/api/me/totp", "POST", {"secret": sec, "code": totp(sec)}, cookie=ck)[2]["totp"] == 1
    st, _, body = raw("/api/login", "POST", {"name": "dospasos", "pass": "segura-dos-pasos"})
    assert st == 401 and body["totp"] is True
    assert raw("/api/login", "POST", {"name": "dospasos", "pass": "mal", "code": totp(sec)})[2].get("totp") is None  # sin pista con mala contraseña
    assert raw("/api/login", "POST", {"name": "dospasos", "pass": "segura-dos-pasos", "code": totp(sec)})[0] == 200
    assert call("/api/pages", auth="Basic " + base64.b64encode(b"dospasos:segura-dos-pasos").decode())[0] == 401  # por Basic, no
    uid = next(u["id"] for u in call("/api/users")[1] if u["name"] == "dospasos")
    assert call(f"/api/users/{uid}", "PUT", {"totp": False})[1]["totp"] == 0  # perdió el móvil
    assert raw("/api/login", "POST", {"name": "dospasos", "pass": "segura-dos-pasos"})[0] == 200
    call(f"/api/users/{uid}", "DELETE")
    # Contraseña olvidada: desde la consola del servidor, con catlan en marcha
    cli = lambda *a: subprocess.run([BIN, "restablecer", *a], capture_output=True, text=True, env=env)
    call("/api/users", "POST", {"name": "olvidadizo", "pass": "no-me-acuerdo"})
    old = raw("/api/login", "POST", {"name": "olvidadizo", "pass": "no-me-acuerdo"})[1]
    out = cli("olvidadizo")
    pw = out.stdout.split("olvidadizo: ")[1].split()[0]
    assert out.returncode == 0 and raw("/api/me", cookie=old)[0] == 401  # sus sesiones, cerradas
    st, _, me2 = raw("/api/login", "POST", {"name": "olvidadizo", "pass": pw})
    assert st == 200 and me2["must_change"] == 1 and raw("/api/login", "POST", {"name": "olvidadizo", "pass": "no-me-acuerdo"})[0] == 401
    assert any(l["action"] == "restablecer contraseña" for l in call("/api/log")[1])
    out = cli("nadie")
    assert out.returncode == 1 and "olvidadizo" in out.stdout and "admin (admin)" in out.stdout
    with tempfile.TemporaryDirectory() as otra:  # otra carpeta de datos: avisa y no se inventa una BD con su admin
        out = subprocess.run([BIN, "restablecer", "admin"], capture_output=True, text=True, env={**env, "CATLAN_DATA": otra})
        assert out.returncode == 1 and "CATLAN_DATA" in out.stderr and not os.listdir(otra), (out.stdout, out.stderr)
    call(f"/api/users/{next(u['id'] for u in call('/api/users')[1] if u['name'] == 'olvidadizo')}", "DELETE")
    # Ediciones a la vez: con _seen, si otro lo cambió desde entonces, 409 con quién; sin _seen, como siempre
    pg = call("/api/pages", "POST", {"title": "Conflicto", "body": "v1"})[1]
    assert call(f"/api/pages/{pg['id']}", "PUT", {"body": "v2", "_seen": pg["updated"]})[0] == 200  # nadie en medio: guarda
    time.sleep(1.1)  # updated tiene resolución de segundos
    call(f"/api/pages/{pg['id']}", "PUT", {"body": "v3 de otro"})
    st, body = call(f"/api/pages/{pg['id']}", "PUT", {"body": "v2 tardía", "_seen": pg["updated"]})
    assert st == 409 and call(f"/api/pages/{pg['id']}")[1]["body"] == "v3 de otro", (st, body)
    assert call(f"/api/pages/{pg['id']}", "PUT", {"body": "la mía"})[1]["body"] == "la mía"  # «Guardar igualmente»
    # Lo mismo en esquemas, racks e incidencias, con un número de versión
    mp = call("/api/maps?name=Conflicto", "POST")[1]
    v0 = call(f"/api/maps/{mp['id']}")[1]["version"]
    v1 = call(f"/api/maps/{mp['id']}", "PUT", {"data": {"nodes": []}, "_seen": v0})[1]["version"]
    assert v1 == v0 + 1 and call(f"/api/maps/{mp['id']}", "PUT", {"name": "otro", "_seen": v1})[0] == 200
    st, body = call(f"/api/maps/{mp['id']}", "PUT", {"name": "tardío", "_seen": v1})
    assert st == 409 and call(f"/api/maps/{mp['id']}")[1]["name"] == "otro", (st, body)
    assert call("/api/maps/999999", "PUT", {"name": "x", "_seen": 0})[0] == 404
    call(f"/api/maps/{mp['id']}", "DELETE")
    inc = call("/api/incidents", "POST", {"title": "Conflicto"})[1]
    assert call(f"/api/incidents/{inc['id']}", "PUT", {"body": "a", "_seen": inc["version"]})[0] == 200
    assert call(f"/api/incidents/{inc['id']}", "PUT", {"body": "b", "_seen": inc["version"]})[0] == 409
    assert call(f"/api/incidents/{inc['id']}")[1]["body"] == "a" and call(f"/api/incidents/{inc['id']}", "PUT", {"body": "b"})[0] == 200
    call(f"/api/incidents/{inc['id']}", "DELETE")
    with sqlite3.connect(Path(env["CATLAN_DATA"]) / "catlan.db") as con:  # migraciones numeradas al día
        assert con.execute("PRAGMA user_version").fetchone()[0] == MIGRATIONS
    # Caducidades que no son garantías (licencias, dominios…): mismo aviso
    day = lambda n: (datetime.now() + timedelta(days=n)).strftime("%Y-%m-%d")
    dom = call("/api/expiries", "POST", {"name": "midominio.es", "kind": "dominio", "date": day(30)})[1]
    assert dom["kind"] == "dominio" and call("/api/expiries", "POST", {"name": "Office", "kind": "licencia", "date": day(31)})[0] == 201
    for bad in ({"name": "x", "date": "2026-02-30"}, {"name": "", "date": day(1)}, {"name": "x", "kind": "coche", "date": day(1)}, {"name": "x"}):
        assert call("/api/expiries", "POST", bad)[0] == 400, bad
    assert call(f"/api/expiries/{dom['id']}", "PUT", {"date": "mañana"})[0] == 400
    it = call("/api/items", "POST", {"name": "con-licencia"})[1]
    call(f"/api/expiries/{dom['id']}", "PUT", {"item": it["id"]})
    assert [e["name"] for e in call(f"/api/items/{it['id']}/refs")[1]["expiries"]] == ["midominio.es"]
    # Syslog: lo que manda un equipo del inventario sale en su ficha; lo de IPs desconocidas, no
    lo = call("/api/items", "POST", {"name": "manda-syslog", "ip": "127.0.0.9"})[1]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
        u.bind(("127.0.0.9", 0))  # desde la IP del equipo
        u.sendto("<11>Nov 20 18:00:00 sw1 kernel: disco lleno ñ".encode(), ("127.0.0.1", SYSLOG))
        u.sendto(b"sin prioridad", ("127.0.0.1", SYSLOG))
    for _ in range(50):
        logs = call(f"/api/items/{lo['id']}/syslog")[1]
        if len(logs) == 2: break
        time.sleep(0.1)
    assert [(l["sev"], l["msg"]) for l in logs] == [(6, "sin prioridad"), (3, "Nov 20 18:00:00 sw1 kernel: disco lleno ñ")], logs
    todo = [l for l in call("/api/syslog", auth=LEC)[1] if l["item"] == lo["id"]]  # vista global, también para los de solo vista
    assert [(l["msg"], l["item_name"]) for l in todo] == [("sin prioridad", "manda-syslog"), ("Nov 20 18:00:00 sw1 kernel: disco lleno ñ", "manda-syslog")], todo
    # IPAM: subred normalizada; en uso, libres, IP repetida en el inventario y lo que responde sin estar en él
    for bad in ({"cidr": "10.0.0.0/15"}, {"cidr": "fe80::/64"}, {"cidr": "hola"}, {}):
        assert call("/api/subnets", "POST", bad)[0] == 400, bad
    sn = call("/api/subnets", "POST", {"cidr": "127.0.0.5/29", "name": "Lazo"})[1]
    assert sn["cidr"] == "127.0.0.0/29"
    call("/api/items", "POST", {"name": "repetido", "ip": "127.0.0.1"})
    r = call(f"/api/subnets/{sn['id']}/ips")[1]
    assert (r["size"], r["used"], r["free"]) == (6, 1, 5) and r["ips"][0]["conflict"] == "duplicada" and r["next_free"][0] == "127.0.0.2", r
    r = call(f"/api/subnets/{sn['id']}/scan", "POST")[1]  # 127.0.0.1-6 responden (lazo local)
    assert r["used"] == 6 and {i["conflict"] for i in r["ips"][1:]} == {"sin registrar"} and r["ips"][0]["up"] is True, r
    assert call("/api/subnets", "POST", {"cidr": "10.0.0.0/21"})[0] == 201 and call(f"/api/subnets/{sn['id']}/scan", auth=LEC)[0] == 200
    big = call("/api/subnets", "POST", {"cidr": "10.0.0.0/16"})[1]
    r = call(f"/api/subnets/{big['id']}/ips")[1]
    assert call(f"/api/subnets/{big['id']}/scan", "POST")[0] == 400 and r["size"] == 65534 and r["free"] == 65534 - r["used"], r["used"]
    # Kitty para Linux: el instalador lleva esta dirección, va con LF y, en Linux, el agente habla bien con catlan
    st, sh = call("/kitty.sh", auth="")
    sh = sh.decode()
    assert st == 200 and f"URL='https://127.0.0.1:{PORT}'" in sh and "{{" not in sh and "\r" not in sh
    if sys.platform.startswith("linux"):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "agent.sh").write_text(sh.split("<<'AGENT'\n")[1].split("\nAGENT\n")[0])
            (Path(tmp) / "key").write_text("k" * 64)
            out = subprocess.run(["sh", str(Path(tmp) / "agent.sh")], env={**os.environ, "KITTY_DIR": tmp}, capture_output=True, text=True)
            state = (Path(tmp) / "state").read_text().splitlines()
            assert state[0] == "pendiente", (state, out.stderr)
            ag = next(a for a in call("/api/agents")[1] if a["name"] == socket.gethostname())
            call(f"/api/agents/{ag['id']}", "PUT", {"state": "adoptado"})
            subprocess.run(["sh", str(Path(tmp) / "agent.sh")], env={**os.environ, "KITTY_DIR": tmp}, check=True)
            assert (Path(tmp) / "state").read_text().splitlines()[0] == "adoptado" and (Path(tmp) / "since").exists()
            h = next(s for s in call("/api/health")[1] if s["kind"] == "kitty" and s["info"].get("name") == socket.gethostname())
            assert h["info"]["mem_total"] and h["info"]["disks"] and h["info"]["cores"], h["info"]
    # El JavaScript de la página (src/ui/js/, unido como en build.rs), sin errores de sintaxis (si hay Node; en GitHub Actions lo hay)
    import shutil
    if shutil.which("node"):
        js = sorted((HERE / "src" / "ui" / "js").glob("*.js"))
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "app.js").write_text("".join(f.read_text(encoding="utf-8") for f in js), encoding="utf-8")
            for f in [Path(tmp) / "app.js", *js]:  # cada archivo también por separado: el error sale con su nombre
                out = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True)
                assert out.returncode == 0, out.stderr
    # La página: comprimida, con ETag y 304 si ya la tiene el navegador
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}/", headers={"Accept-Encoding": "gzip"})
    with urllib.request.urlopen(req) as r:
        tag, body = r.headers["ETag"], r.read()
        assert r.headers["Content-Encoding"] == "gzip" and gzip.decompress(body).startswith(b"<!doctype html>") and len(body) < 150_000
    try:
        urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{PORT}/", headers={"If-None-Match": tag}))
        raise AssertionError("sin 304")
    except urllib.error.HTTPError as e:
        assert e.code == 304
    # Deshacer un borrado: vuelve con su id; dos veces no, y lo que no se puede deshacer, tampoco
    eq = call("/api/items", "POST", {"name": "se-borra", "ip": "10.9.9.9", "notes": "con [[#1]]"})[1]
    call(f"/api/items/{eq['id']}", "DELETE")
    lid = call(f"/api/log?kind=item&ref={eq['id']}")[1][0]["id"]
    assert call(f"/api/log/{lid}/undo", "POST")[0] == 200
    back = call(f"/api/items/{eq['id']}")[1]
    assert (back["name"], back["ip"], back["notes"]) == ("se-borra", "10.9.9.9", "con [[#1]]") and call(f"/api/log/{lid}/undo", "POST")[0] == 409
    rk2 = call("/api/maps?type=rack&name=Rack-deshacer", "POST")[1]
    call(f"/api/maps/{rk2['id']}", "PUT", {"data": {"type": "rack", "height": 12, "devices": [{"id": "d1", "t": "server", "u": 1, "h": 1, "item": eq["id"]}]}})
    call(f"/api/maps/{rk2['id']}", "DELETE")
    call(f"/api/log/{call(f'/api/log?kind=rack&ref={rk2['id']}')[1][0]['id']}/undo", "POST")
    assert call(f"/api/maps/{rk2['id']}")[1]["data"]["devices"][0]["item"] == eq["id"]
    assert call(f"/api/log/{call('/api/log')[1][-1]['id']}/undo", "POST")[0] == 400  # no es un borrado
    # Mantenimiento programado: de un equipo o de todo un rack; mientras no empieza, avisa como siempre
    ck = call("/api/checks", "POST", {"host": "10.9.9.9", "every": 3600})[1]
    iso = lambda m: (datetime.now(timezone.utc) + timedelta(minutes=m)).isoformat()
    for bad in ({"items": [eq["id"]], "from": iso(60), "to": iso(30)}, {"items": [], "from": iso(1), "to": iso(2)},
                {"items": [eq["id"]], "from": "ayer", "to": iso(2)}, {"items": [eq["id"]], "from": iso(0), "to": iso(60 * 24 * 40)}):
        assert call("/api/maintenance", "POST", bad)[0] == 400, bad
    r = call("/api/maintenance", "POST", {"rack": rk2["id"], "from": iso(60), "to": iso(120)})[1]
    assert r["muted"] == 1 and not muted(dict(call(f"/api/checks/{ck['id']}")[1]))  # aún no ha empezado
    call("/api/maintenance", "POST", {"items": [eq["id"]], "from": iso(-1), "to": iso(60)})
    assert muted(dict(call(f"/api/checks/{ck['id']}")[1]))
    call(f"/api/checks/{ck['id']}/mute", "POST", {"minutes": 0})  # quitar el silencio quita también el programado
    assert not muted(dict(call(f"/api/checks/{ck['id']}")[1])) and call(f"/api/checks/{ck['id']}")[1]["mute_from"] is None
    call(f"/api/checks/{ck['id']}", "DELETE")
    # Salud de catlan (solo admin): BD íntegra, monitor con latido, sin atrasos
    st, sy = call("/api/system")
    assert st == 200 and sy["integrity"] == "ok" and sy["monitor"]["age"] < 10 and sy["schema"] == MIGRATIONS and sy["db_bytes"] > 0, sy
    assert call("/api/system", auth=LEC)[0] == 403 and call("/api/monitor")[1]["monitor"]["age"] < 10
    assert sy["backups"] and sy["backups"][0]["name"].startswith("catlan-")  # la copia diaria se hace al arrancar
    # Apagado limpio con SIGTERM (docker stop): en Linux, el WAL queda volcado en catlan.db
    if sys.platform.startswith("linux"):
        d3 = tempfile.mkdtemp()
        p3 = subprocess.Popen([BIN], env={**env, "CATLAN_DATA": d3, "CATLAN_PORT": "18104", "CATLAN_SYSLOG_PORT": "0"},
                              stdout=subprocess.PIPE, text=True)
        for _ in range(50):
            try: urllib.request.urlopen("http://127.0.0.1:18104/"); break
            except OSError: time.sleep(0.1)
        p3.terminate()
        assert "catlan parado" in p3.communicate(timeout=10)[0] and not (Path(d3) / "catlan.db-wal").stat().st_size
    # Sonido por dispositivo: se guarda en la comprobación; borrar un sonido subido devuelve a sus usuarios al general
    ck = call("/api/checks", "POST", {"host": "127.0.0.1", "label": "con sirena", "sound": "siren", "every": 3600})[1]
    assert ck["sound"] == "siren" and call("/api/checks", "POST", {"host": "127.0.0.1", "sound": "trompeta"})[0] == 400
    snd = call("/api/sounds?name=Gong", "POST", b"RIFF0000WAVEfmt ", ctype="audio/wav")[1]
    assert call(f"/api/checks/{ck['id']}", "PUT", {"sound": f"u:{snd['id']}"})[1]["sound"] == f"u:{snd['id']}"
    assert next(c for c in call("/api/monitor")[1]["checks"] if c["id"] == ck["id"])["sound"] == f"u:{snd['id']}"  # lo recibe la web
    call(f"/api/sounds/{snd['id']}", "DELETE")
    assert call(f"/api/checks/{ck['id']}")[1]["sound"] == ""
    call(f"/api/checks/{ck['id']}", "DELETE")
    # Avisos configurables: solo admin; los secretos no salen; vacío = conservar; lo guardado manda sobre el entorno
    a = call("/api/alerts")[1]
    assert a["SMTP_HOST"] == "127.0.0.1" and a["MAIL_TO"] == "it@example.com" and a["set"]["WEBHOOK_URL"] and "WEBHOOK_URL" not in a
    assert {"SMTP_HOST", "MAIL_TO", "WEBHOOK_URL"} <= set(a["env"]) and WEB not in json.dumps(a) and a["channels"] == ["correo", "webhook"]
    assert call("/api/alerts", auth=LEC)[0] == 403 and call("/api/alerts", "PUT", {"MAIL_TO": "x@y.z"}, auth=LEC)[0] == 403
    for bad in ({"TELEGRAM_CHAT": "mi chat"}, {"MAIL_TO": "nadie"}, {"WEBHOOK_URL": "ftp://x"}, {"SMTP_PORT": "99999"}, {"SMTP_HOST": "-o mal"}, ["x"]):
        assert call("/api/alerts", "PUT", bad)[0] == 400, bad
    a = call("/api/alerts", "PUT", {"MAIL_TO": "guardia@example.com, jefe@example.com", "WEBHOOK_URL": "", "SMTP_PASS": ""})[1]
    assert a["MAIL_TO"] == "guardia@example.com, jefe@example.com" and "MAIL_TO" not in a["env"] and a["set"]["WEBHOOK_URL"]  # webhook conservado
    n = len(mails)
    assert call("/api/monitor/test", "POST")[1] == {"correo": None, "webhook": None}
    for _ in range(50):
        if len(mails) > n: break
        time.sleep(0.1)
    assert "guardia@example.com, jefe@example.com" in mails[-1], mails[-1][:300]  # el destinatario guardado en catlan
    assert call("/api/alerts", "PUT", {"MAIL_TO": None})[1]["MAIL_TO"] == "it@example.com"  # quitado: vuelve el del entorno
    assert ("alerts", "editar") in [(h["kind"], h["action"]) for h in call("/api/log")[1]] and "guardia" not in json.dumps([h for h in call("/api/log")[1] if h["kind"] == "alerts"])
    # Borrar la base de datos: solo un admin y con su contraseña; copia antes; se quedan usuarios y grupos
    users_before = len(call("/api/users")[1])
    assert call("/api/wipe", "POST", {"pass": "lectura-segura"}, auth=LEC)[0] == 403
    assert call("/api/wipe", "POST", {"pass": "mal"})[0] == 403 and call("/api/wipe", "POST", ["x"])[0] == 403
    assert call("/api/items")[1]  # nada borrado todavía
    st, w = call("/api/wipe", "POST", {"pass": "miau"})
    assert st == 200 and (Path(env["CATLAN_DATA"]) / w["copy"]).exists(), w
    assert call("/api/items")[1] == [] and call("/api/pages")[1] == [] and call("/api/incidents")[1] == [] and call("/api/health")[1] == []
    assert len(call("/api/users")[1]) == users_before
    assert [(h["action"], h["kind"]) for h in call("/api/log")[1]] == [("vaciar", "db")]
    # Cuánto se guarda: por defecto 7 / 30 / 400 días; solo un admin lo cambia y dentro de sus límites
    assert call("/api/retention")[1] == {"raw": 7, "syslog": 30, "hours": 400}
    assert call("/api/retention", "PUT", {"raw": 0})[0] == 400 and call("/api/retention", "PUT", {"hours": "x"})[0] == 400
    assert call("/api/retention", "PUT", {"raw": 14}, auth=LEC)[0] == 403
    assert call("/api/retention", "PUT", {"raw": 14})[1] == {"raw": 14, "syslog": 30, "hours": 400} and call("/api/retention", auth=LEC)[1]["raw"] == 14
    assert call("/api/system")[1]["rejected"] == 0
    # Usuarios del dominio (LDAP y OIDC de mentira), en otro catlan: así sus intentos no cuentan para el límite de este
    sso_p = subprocess.Popen([BIN], env={**env, "CATLAN_DATA": tempfile.mkdtemp(), "CATLAN_PORT": "18105", "CATLAN_SYSLOG_PORT": "0"}, stdout=subprocess.DEVNULL)
    try:
        class NoRedir(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a): return None

        def s5(path, method="GET", body=None, cookie="", auth=""):  # (código, cookies, cuerpo o Location), sin seguir redirecciones
            url = path if path.startswith("http") else f"http://127.0.0.1:18105{path}"
            req = urllib.request.Request(url, None if body is None else json.dumps(body).encode(), method=method,
                                         headers={"Content-Type": "application/json", "Cookie": cookie, **({"Authorization": auth} if auth else {})})
            try:
                r = urllib.request.build_opener(NoRedir).open(req)
            except urllib.error.HTTPError as e:
                r = e
            raw = r.read()
            jar = {c.split("=", 1)[0]: c.split(";")[0] for c in r.headers.get_all("Set-Cookie") or []}
            return r.status if hasattr(r, "status") else r.code, jar, r.headers.get("Location") or (json.loads(raw) if raw[:1] in (b"{", b"[") else raw)
        for _ in range(50):
            try: s5("/"); break
            except OSError: time.sleep(0.1)
        tec = s5("/api/groups", "POST", {"name": "Técnicos", "role": "edit"}, auth=AUTH)[2]["id"]
        lec = s5("/api/groups", "POST", {"name": "Lectura", "role": "view"}, auth=AUTH)[2]["id"]
        s5("/api/users", "POST", {"name": "pepe", "pass": "local-de-pepe"}, auth=AUTH)  # un local con el nombre de uno del dominio
        conf = {"ldap_url": f"ldap://127.0.0.1:{ldap.server_address[1]}", "ldap_domain": "empresa.local", "oidc_issuer": IDP, "oidc_client": "catlan",
                "oidc_secret": "s3creto-oidc", "oidc_name": "Keycloak",
                "map": [{"from": "IT", "to": tec}, {"from": "CN=Jefes,DC=empresa,DC=local", "to": "admin"}, {"from": "@empresa.com", "to": lec}]}
        assert s5("/api/sso/config")[0] == 401
        for bad in ({"ldap_url": "ldap://10.0.0.1"}, {"oidc_issuer": "http://idp.empresa.com"}, {"map": [{"from": "IT", "to": 999}]}, {"ldap_pin": "abc"}):
            assert s5("/api/sso/config", "PUT", bad, auth=AUTH)[0] == 400, bad
        c = s5("/api/sso/config", "PUT", conf, auth=AUTH)[2]
        assert c["set"] == {"oidc_secret": True} and "s3creto" not in json.dumps(c) and c["map"][0] == {"from": "IT", "to": tec}
        assert s5("/api/sso/config", "PUT", {"oidc_secret": "", "oidc_name": "Keycloak"}, auth=AUTH)[2]["set"]["oidc_secret"]  # vacío = conservar
        assert "s3creto" not in json.dumps(s5("/api/log", auth=AUTH)[2]) and ("sso", "editar") in [(h["kind"], h["action"]) for h in s5("/api/log", auth=AUTH)[2]]
        assert s5("/api/sso")[2] == {"ldap": True, "oidc": "Keycloak", "error": None} and "grupo" in s5("/api/sso?e=acceso")[2]["error"]
        # LDAP: entra con la contraseña del dominio; sus grupos mandan lo que puede hacer
        st, ck, me = s5("/api/login", "POST", {"name": "juan", "pass": "clave-juan"})
        sess = next(v for k, v in ck.items() if not k.endswith("_sso"))
        assert st == 200 and me["ext"] == "ldap" and me["admin"] == 0 and me["groups"] == [tec] and not me["readonly"], me
        assert s5("/api/items", "POST", {"name": "del dominio"}, cookie=sess)[0] == 201
        assert s5("/api/login", "POST", {"name": "EMPRESA\\juan", "pass": "clave-juan"})[2]["id"] == me["id"]  # el mismo usuario, se escriba como se escriba
        assert s5("/api/login", "POST", {"name": "jefa@empresa.local", "pass": "clave-jefa"})[2]["admin"] == 1
        st, _, r = s5("/api/login", "POST", {"name": "ventas", "pass": "clave-ventas"})
        assert st == 403 and "grupo" in r["error"]  # su contraseña vale, pero ningún grupo suyo tiene acceso
        assert s5("/api/login", "POST", {"name": "juan", "pass": "mala"})[0] == 401 and s5("/api/login", "POST", {"name": "juan", "pass": ""})[0] == 401
        assert s5("/api/pages", auth="Basic " + base64.b64encode(b"juan:clave-juan").decode())[0] == 200  # Basic para scripts, también del dominio
        # el admin local no lo tapa el del dominio, ni el local «pepe»
        assert s5("/api/login", "POST", {"name": "admin", "pass": "clave-admin-dominio"})[0] == 401 and s5("/api/login", "POST", {"name": "admin", "pass": "miau"})[0] == 200
        assert s5("/api/login", "POST", {"name": "pepe", "pass": "clave-pepe"})[0] == 401
        st, _, r = s5("/api/login", "POST", {"name": "pepe@empresa.local", "pass": "clave-pepe"})
        assert st == 403 and "local" in r["error"], r
        # su contraseña y su admin son cosa del dominio
        assert s5("/api/me/password", "POST", {"old": "clave-juan", "new": "otra-clave-1"}, cookie=sess)[0] == 400
        assert s5(f"/api/users/{me['id']}", "PUT", {"pass": "provisional1"}, auth=AUTH)[0] == 400 and s5(f"/api/users/{me['id']}", "PUT", {"admin": True}, auth=AUTH)[0] == 400
        assert {u["name"]: u["ext"] for u in s5("/api/users", auth=AUTH)[2]} == {"admin": "", "pepe": "", "juan": "ldap", "jefa": "ldap"}
        # dominio caído: los del dominio no entran (503), el admin local sí, y no cuenta como intento fallido
        s5("/api/sso/config", "PUT", {"ldap_url": "ldap://127.0.0.1:1"}, auth=AUTH)
        codes = [s5("/api/login", "POST", {"name": "jefa", "pass": "clave-jefa"})[0] for _ in range(11)]  # «jefa» sin la caché de 10 minutos
        assert codes == [503] * 11, codes
        assert s5("/api/login", "POST", {"name": "admin", "pass": "miau"})[0] == 200
        s5("/api/sso/config", "PUT", {"ldap_url": conf["ldap_url"]}, auth=AUTH)
        # OIDC con PKCE: catlan → proveedor → catlan, con el state atado a este navegador por una cookie
        IDP_USER.update({"sub": "ana-1", "preferred_username": "ana@empresa.com", "email": "ana@empresa.com", "email_verified": True})
        st, ck, loc = s5("/api/sso/start")
        assert st == 302 and loc.startswith(IDP + "/auth?") and "code_challenge_method=S256" in loc and "s3creto" not in loc, loc
        state_ck = next(v for k, v in ck.items() if k.endswith("_sso"))
        back = s5(loc)[2]  # el proveedor «entra» y devuelve el navegador a catlan
        assert back.startswith("http://127.0.0.1:18105/api/sso/callback?code=") and idp_seen["redirect_uri"] == "http://127.0.0.1:18105/api/sso/callback"
        assert s5(back)[2] == "/?sso=caducado"  # sin la cookie del state: otro navegador
        st, ck, loc = s5(back, cookie=state_ck)
        assert st == 302 and loc == "/", loc
        sess = next(v for k, v in ck.items() if not k.endswith("_sso") and v.split("=", 1)[1])
        me = s5("/api/me", cookie=sess)[2]
        assert me["name"] == "ana@empresa.com" and me["ext"] == "oidc" and me["groups"] == [lec] and me["readonly"] is True, me
        assert s5(back, cookie=state_ck)[2] == "/?sso=caducado"  # el mismo state no vale dos veces
        assert s5("/api/login", "POST", {"name": "ana@empresa.com", "pass": "lo-que-sea"})[0] == 401  # sin contraseña en catlan
        IDP_USER.update({"sub": "intruso", "preferred_username": "x@gmail.com", "email": "x@gmail.com"})
        _, ck, loc = s5("/api/sso/start")
        assert s5(s5(loc)[2], cookie=next(v for k, v in ck.items() if k.endswith("_sso")))[2] == "/?sso=acceso"  # de fuera de la empresa: no
        assert s5("/api/sso/callback?error=access_denied&error_description=Llama+al+555")[2] == "/?sso=cancelado"  # su texto no llega a la página
    finally:
        sso_p.terminate()
    # HTTPS siempre: certificado autofirmado y su huella para anclarlo en Kitty y en el comando de instalación
    import ssl
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection(("127.0.0.1", PORT)) as s, ctx.wrap_socket(s) as t:
        der = t.getpeercert(binary_form=True)
    with urllib.request.urlopen(f"https://127.0.0.1:{PORT}/kitty.json", context=ctx) as r:
        kj, hdr = json.loads(r.read()), r.headers
    assert kj["pin"] == hashlib.sha256(der).hexdigest().upper() and len(base64.b64decode(kj["spki"])) == 32, kj
    assert hdr["X-Frame-Options"] == "DENY" and "frame-ancestors 'none'" in hdr["Content-Security-Policy"] and "Strict-Transport-Security" not in hdr  # HSTS no, con autofirmado
    ps = urllib.request.urlopen(f"https://127.0.0.1:{PORT}/kitty.ps1", context=ctx).read().decode()
    assert f"$Pin = '{kj['pin']}'" in ps and "[KittyPin]::Set($Pin)" in ps and "{{" not in ps  # el anclado va en C# (a2c6c7f)
    # CSRF sin Origin: el navegador dice Sec-Fetch-Site
    xs = urllib.request.Request(f"http://127.0.0.1:{PORT}/api/items", b'{"name":"csrf"}', method="POST", headers={"Authorization": AUTH, "Content-Type": "application/json", "Sec-Fetch-Site": "cross-site"})
    try: urllib.request.urlopen(xs); assert False
    except urllib.error.HTTPError as e: assert e.code == 403
    # En claro desde la red (no desde este equipo): la página redirige a https y solo pasa la telemetría de las Kitty antiguas
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.connect(("10.255.255.255", 1)); lan = u.getsockname()[0]; u.close()
    if not lan.startswith("127.") and lan != "0.0.0.0":
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a): return None
        def plain(path, method="GET", body=None):
            req = urllib.request.Request(f"http://{lan}:{PORT}{path}", None if body is None else json.dumps(body).encode(), method=method, headers={"Authorization": AUTH, "Content-Type": "application/json"})
            try:
                with urllib.request.build_opener(NoRedirect).open(req) as r: return r.status, r.read(), r.headers
            except urllib.error.HTTPError as e: return e.code, e.read(), e.headers
        st, _, h = plain("/inventario")
        assert st == 301 and h["Location"] == f"https://{lan}:{PORT}/inventario", (st, h)
        assert plain("/api/items")[0] == 403 and plain("/api/login", "POST", {"name": "admin", "pass": "miau"})[0] == 403
        assert plain("/api/agent/remote", "POST", {})[0] == 403 and plain("/api/agent/quit", "POST", {})[0] == 403 and plain("/kitty.exe")[0] == 403
        assert plain("/kitty.ps1")[1].startswith(b"throw ") and json.loads(plain("/kitty.json")[1])["kitty"] == ""
        assert "https" not in json.loads(plain("/api/agent", "POST", {})[1] or b"{}").get("error", "")  # Kitty antigua: sigue enviando
    # Fuerza bruta: 10 fallos en 15 min desde una IP y esa IP espera, aunque luego acierte (va al final: bloquea 127.0.0.1)
    codes = [raw("/api/login", "POST", {"name": "admin", "pass": f"intento{i}"})[0] for i in range(12)]
    assert codes[-1] == 429 and raw("/api/login", "POST", {"name": "admin", "pass": "miau"})[0] == 429, codes
    assert b"catlan" in call("/")[1]
    print("OK")
finally:
    srv.terminate()
