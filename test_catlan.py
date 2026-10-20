"""Prueba de humo de la API: python test_catlan.py"""
from pathlib import Path
import base64, http.server, json, os, socketserver, ssl, subprocess, sys, tempfile, threading, time, urllib.request, urllib.error

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

# catlan importado solo por sus funciones BER (su base de datos va a una carpeta temporal)
os.environ["CATLAN_DATA"] = tempfile.mkdtemp()
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import catlan  # noqa: E402
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
        _, msg, _ = catlan.ber_read(data, 0)
        _, _, i = catlan.ber_read(msg, 0)
        _, comm, i = catlan.ber_read(msg, i)
        mib = {b"secreta": MIB, b"switch": SW}.get(comm)
        if mib is None:
            return  # comunidad incorrecta: silencio, como un equipo real
        tag, pdu, _ = catlan.ber_read(msg, i)
        _, rid, j = catlan.ber_read(pdu, 0)
        _, _, j = catlan.ber_read(pdu, j)
        _, rep, j = catlan.ber_read(pdu, j)
        _, vbl, _ = catlan.ber_read(pdu, j)
        oids, k = [], 0
        while k < len(vbl):
            _, vb, k = catlan.ber_read(vbl, k)
            oids.append(catlan.oid_str(catlan.ber_read(vb, 0)[1]))
        out = []
        for o in oids:
            if tag == 0xA0:
                out.append((o, mib.get(o, (0x80, None))))
            else:
                nxt = [x for x in sorted(mib, key=KEY) if KEY(x) > KEY(o)][:int.from_bytes(rep, "big")]
                out += [(x, mib[x]) for x in nxt] or [(o, (0x82, None))]
        enc = lambda t, v: bytes([t, 0]) if v is None else catlan.tlv(4, v if isinstance(v, bytes) else v.encode()) if t == 4 else catlan.ber_oid(v) if t == 6 else catlan.ber_int(v, t)
        vbs = b"".join(catlan.tlv(0x30, catlan.ber_oid(o) + enc(*tv)) for o, tv in out)
        sock.sendto(catlan.tlv(0x30, catlan.ber_int(1) + catlan.tlv(4, comm) + catlan.tlv(0xA2, catlan.tlv(2, rid) + catlan.ber_int(0)
                    + catlan.ber_int(0) + catlan.tlv(0x30, vbs))), self.client_address)


# Switch de mentira para la auto-topología: Gi1/0/1 servidor por LLDP, Gi1/0/2 router por CDP, Gi1/0/3 un PC por su MAC (IP por ARP),
# Gi1/0/4 dos MAC sin IP y Gi1/0/5 un enlace con 6 MAC detrás (no es «un equipo»)
SW = {f"{catlan.IF['name']}.{n}": (S, f"Gi1/0/{n}") for n in range(1, 6)}
SW.update({f"{catlan.BRIDGE_IF}.{n}": (2, n) for n in range(1, 6)})
L, LM, LL, C, F = catlan.LLDP_REM, catlan.LLDP_MAN, catlan.LLDP_LOC, catlan.CDP, catlan.FDB_Q
SW.update({f"{LL}.3.1": (S, "Gi1/0/1"), f"{L}.5.0.1.1": (S, bytes.fromhex("0050569a0001")), f"{L}.7.0.1.1": (S, "eth0"), f"{L}.8.0.1.1": (S, "eth0"),
           f"{L}.9.0.1.1": (S, "srv-web.empresa.lan"), f"{L}.12.0.1.1": (S, bytes([0x01, 0])), f"{LM}.3.0.1.1.1.4.10.0.0.10": (2, 2),
           f"{C}.4.2.1": (S, bytes([10, 0, 0, 1])), f"{C}.6.2.1": (S, "core-rtr"), f"{C}.7.2.1": (S, "Gi0/0"), f"{C}.9.2.1": (S, bytes([0, 0, 0, 1])),
           f"{catlan.ARP}.3.10.0.1.15": (S, bytes.fromhex("aabbcc000003"))})
for port, macs in ((3, ["aabbcc000003"]), (4, ["aabbcc000041", "aabbcc000042"]), (5, [f"aabbcc0000{i:02x}" for i in range(0x50, 0x56)])):
    SW.update({F + ".1." + ".".join(str(b) for b in bytes.fromhex(m)): (2, port) for m in macs})

agent = socketserver.ThreadingUDPServer(("127.0.0.1", 0), FakeAgent)
threading.Thread(target=agent.serve_forever, daemon=True).start()
APORT = agent.server_address[1]

PORT = "18099"
env = {**os.environ, "CATLAN_DATA": tempfile.mkdtemp(), "CATLAN_PORT": PORT, "CATLAN_PASSWORD": "miau",
       "CATLAN_SMTP_HOST": "127.0.0.1", "CATLAN_SMTP_PORT": str(smtp.server_address[1]), "CATLAN_MAIL_TO": "it@example.com", "CATLAN_WEBHOOK_URL": WEB + "/hook"}
srv = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(__file__), "catlan.py")], env=env)
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
    assert st == 200 and adm.startswith(f"catlan_{catlan.sha(str(Path(env['CATLAN_DATA']).resolve()))[:10]}=") and me == {"id": 1, "name": "admin", "admin": 1, "must_change": 0, "readonly": False, "groups": []}
    assert raw("/api/pages", cookie=adm)[0] == 200 and raw("/api/login", "POST", {"name": "admin", "pass": "mal"})[0] == 401
    # Instalación nueva: la wiki trae la «Guía de catlan» (uso, funciones y qué hace con los datos), una sola vez
    guia = call("/api/pages")[1]
    assert [g["title"] for g in guia] == ["Guía de catlan"], guia
    body = call(f"/api/pages/{guia[0]['id']}")[1]["body"]
    assert not body.startswith("# ") and all(t in body for t in ("## Primeros pasos", "## Qué hace cada sección", "## Tus datos", "## Qué no hace", "telemetría", "api.telegram.org"))
    # Dos catlan en la misma máquina: el navegador comparte cookies entre puertos; entrar en uno no debe echar del otro
    import http.cookiejar
    otro = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(__file__), "catlan.py")],
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
    assert call(f"/api/maps/{m['id']}", "PUT", {"name": "P1", "data": esquema})[0] == 204
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
    assert call(f"/api/items/{i['id'] + 100}/refs")[1] == {"pages": [], "items": [], "maps": [], "incidents": []}
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
    assert call(f"/api/maps/{rk}", "PUT", {"data": good})[0] == 204
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
    ctx = ssl.create_default_context()  # caducidad leída a mano = la que lee Python, en todas las CA del sistema
    assert ctx.get_ca_certs() and all(catlan.cert_expiry(d) == ssl.cert_time_to_seconds(i["notAfter"])
                                      for d, i in zip(ctx.get_ca_certs(True), ctx.get_ca_certs()))
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
    # SNMP: la codificación coincide byte a byte con un GetRequest calculado a mano
    assert catlan.snmp_msg("public", 0xA0, 1, ["1.3.6.1.2.1.1.1.0"]).hex() == (
        "3026020101" "04067075626c6963" "a019" "020101" "020100" "020100" "300e" "300c" "06082b06010201010100" "0500")
    assert catlan.oid_str(catlan.ber_oid("1.3.6.1.4.1.14988.1")[2:]) == "1.3.6.1.4.1.14988.1"  # arcos grandes
    # SNMPv3: vectores oficiales de AES (FIPS-197, NIST SP 800-38A) y de las claves USM (RFC 3414 A.3)
    assert catlan.aes_block(catlan.aes_keys(bytes(range(16))), bytes.fromhex("00112233445566778899aabbccddeeff")).hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    k, iv = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"), bytes(range(16))
    pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
    assert catlan.aes_cfb(k, iv, pt, True).hex() == "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"
    assert catlan.aes_cfb(k, iv, catlan.aes_cfb(k, iv, pt[:20], True), False) == pt[:20]  # bloque final incompleto
    e = bytes.fromhex("000000000000000000000002")
    assert catlan.usm_key("md5", "maplesyrup", e).hex() == "526f5eed9fcce26f8964c2930787d82b"
    assert catlan.usm_key("sha", "maplesyrup", e).hex() == "6695febc9288e36282235fc7151f128497b38f3f"
    # SNMPv3 con firma y cifrado: solo vale una respuesta con esa misma seguridad
    s = catlan.SNMP("127.0.0.1", v3={"user": "lector", "auth": "sha", "pass": "clave-larga", "priv": "aes", "priv_pass": "otra-clave"})
    s.eng, s.boots, s.etime, s.at = e, 1, 100, time.monotonic()
    s.ka, s.kp = catlan.usm_key("sha", "clave-larga", e), catlan.usm_key("sha", "otra-clave", e)[:16]
    ok = s._v3_msg(0xA2, ["1.3.6.1.2.1.1.5.0"], 0)
    assert s._v3_parse(ok) == (s.rid, 0xA2, 0, [("1.3.6.1.2.1.1.5.0", 5, None)])
    assert s._v3_parse(ok[:-1] + bytes([ok[-1] ^ 1])) is None  # un bit cambiado: la firma ya no vale
    for lvl in (0, 1):  # respuesta falsa sin firma, o firmada pero sin cifrar
        s.lvl = lvl
        forged = s._v3_msg(0xA2, ["1.3.6.1.2.1.1.5.0"], 0)
        s.lvl = 3
        assert s._v3_parse(forged) is None, lvl
    v3 = {"host": "127.0.0.1", "v3": True, "user": "lector", "auth": "sha", "pass": "clave-larga", "priv": "aes", "priv_pass": "otra-clave"}
    for bad in [{**v3, "user": ""}, {**v3, "auth": "none"}, {**v3, "pass": "corta"}, {**v3, "auth": "sha1"}, {**v3, "priv": "des"}, {**v3, "v3": 2}]:
        assert call("/api/sources", "POST", bad)[0] == 400, bad
    s3, r3 = call("/api/sources", "POST", {**v3, "label": "v3 sin equipo"})
    assert s3 == 201 and r3["v3"] == 1 and r3["auth"] == "sha" and not set(catlan.SECRET) & set(r3), r3  # contraseñas fuera
    assert call(f"/api/sources/{r3['id']}", "DELETE")[0] == 204
    hist3 = call(f"/api/log?kind=source&ref={r3['id']}")[1]
    assert len(hist3) == 2 and all(not set(catlan.SECRET) & set(json.loads(h["data"])) for h in hist3)  # ni en el historial
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
    # Grabador Hikvision: disco con error y uso calculado
    hik = b"""<hddList xmlns="http://www.hikvision.com/ver20/XMLSchema"><hdd><id>1</id><hddName>hdd1</hddName><status>ok</status>
      <capacity>1000</capacity><freeSpace>250</freeSpace></hdd><hdd><id>2</id><hddName>hdd2</hddName><status>error</status>
      <capacity>1000</capacity><freeSpace>1000</freeSpace></hdd></hddList>"""
    assert catlan.parse_hik(hik) == ([("disk:hdd1", "hdd1", 75.0, "%"), ("disk:hdd2", "hdd2", 0.0, "%")], ["hdd2: error"])
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
    # Interfaces: Mbps a partir de dos lecturas; contador reiniciado = sin dato; vuelta del contador de 32 bits
    class FakeIf:  # walk() como el de catlan: {ifIndex: valor}
        def __init__(self, d): self.d = d
        def walk(self, oid): return self.d.get(oid, {})
    I, t0 = catlan.IF, time.time()
    sw = {I["type"]: {"1": 6, "2": 6, "3": 24, "4": 6}, I["name"]: {"1": "Gi1", "2": "Gi2", "3": "lo", "4": "Gi4"}, I["alias"]: {"1": "UPLINK", "4": "SRV"},
          I["oper"]: {"1": 1, "2": 1, "3": 1, "4": 2}, I["admin"]: {"1": 1, "2": 1, "3": 1, "4": 1}, I["speed"]: {"1": 1000, "2": 100, "4": 1000},
          I["hin"]: {"1": 10 ** 12 + 7_500_000_000, "2": 100, "4": 0}, I["hout"]: {"1": 10 ** 12, "2": 100, "4": 0}}
    catlan.IF_PREV[99] = {"1": (t0 - 60, 10 ** 12, 10 ** 12, 0), "2": (t0 - 60, 200, 100, 0)}  # Gi2: el contador bajó (reinicio)
    out, probs = [], []
    ports = catlan.interfaces(FakeIf(sw), 99, out, probs)
    assert [x["name"] for x in ports] == ["Gi1", "Gi2", "Gi4"] and abs(ports[0]["rx"] - 1000) < 2 and ports[0]["tx"] == 0, ports
    assert "rx" not in ports[1] and {k for k, *_ in out} == {"rx:Gi1", "tx:Gi1", "err:Gi1"}, out  # sin dato inventado; Gi4 caído no guarda tráfico
    assert probs == ["Gi1: al 100 % de su capacidad", "Gi4 (SRV): caído"], probs
    catlan.IF_PREV[98] = {"1": (t0 - 1, 2 ** 32 - 1000, 0, 0)}
    old = {I["type"]: {"1": 6}, I["oper"]: {"1": 1}, "1.3.6.1.2.1.2.2.1.10": {"1": 1000}, "1.3.6.1.2.1.2.2.1.16": {"1": 0}}
    assert abs(catlan.interfaces(FakeIf(old), 98, [], [])[0]["rx"] - 0.016) < .002  # 2000 bytes en ~1 s, pese a la vuelta
    # Historial por horas y disponibilidad (en la BD del catlan importado, con horas fijas de enero)
    Q = catlan.q
    cid = Q("INSERT INTO checks(host, every) VALUES('sla', 60)").lastrowid
    for ts, up, rtt in [("10:01", 1, 10), ("10:20", 1, 20), ("10:40", 1, 30), ("10:59", 1, 40), ("11:05", 0, None), ("11:06", 0, None)]:
        Q("INSERT INTO pings(check_id, ts, up, rtt) VALUES(?, ?, ?, ?)", [cid, f"2026-01-15 {ts}:00", up, rtt])
    Q("INSERT INTO pings(check_id, ts, up, rtt) VALUES(?, '2026-02-01 12:00:00', 0, NULL)", [cid])  # otro mes
    for ts, v in [("10:05", 50), ("10:35", 70)]:
        Q("INSERT INTO metrics(source_id, ts, key, label, value, unit) VALUES(7, ?, 'disk:/', '/', ?, '%')", [f"2026-01-15 {ts}:00", v])
    catlan.rollup(); catlan.rollup()  # repetir no duplica
    assert [tuple(r) for r in Q("SELECT hour, n, up, rtt, rtt_min, rtt_max FROM pings_h WHERE check_id=? ORDER BY hour", [cid])] == [
        ("2026-01-15 10:00:00", 4, 4, 25, 10, 40), ("2026-01-15 11:00:00", 2, 0, None, None, None), ("2026-02-01 12:00:00", 1, 0, None, None, None)]
    assert tuple(Q("SELECT v, v_min, v_max FROM metrics_h WHERE source_id=7").fetchone()) == (60, 50, 70)
    assert catlan.series(7, catlan.MAX_HOURS)["disk:/"]["points"] == [["2026-01-15 10:00:00", 60]]  # más de 7 días: sale de los resúmenes
    r = next(x for x in catlan.sla("2026-01")["checks"] if x["id"] == cid)
    assert (r["n"], r["up"], r["down_min"], r["hours"], r["rtt"]) == (6, 4, 2, 2, 25) and abs(r["uptime"] - 4 / 6) < 1e-9, r
    assert catlan.sla("2026-01")["hours"] == 31 * 24 and catlan.sla("2099-01")["checks"][0]["uptime"] is None
    assert call("/api/sla?month=2026-13")[0] == 400 and call("/api/sla")[0] == 200
    # Descubrir red: solo IPv4 pequeñas; marca lo que ya está en el inventario y en el monitor
    for bad in [{"net": "nada"}, {"net": "10.0.0.0/16"}, {"net": "::1/128"}, {"net": "127.0.0.1/32", "community": 5}]:
        assert call("/api/discover", "POST", bad)[0] == 400, bad
    loc = call("/api/items", "POST", {"name": "este", "ip": "127.0.0.1"})[1]
    st, found = call("/api/discover", "POST", {"net": "127.0.0.1/32"})
    assert st == 200 and len(found) == 1 and found[0]["ip"] == "127.0.0.1" and found[0]["item"] == loc["id"] and found[0]["watched"] is True, found
    assert catlan.guess("HP LaserJet Pro M404", "1.3.6.1.4.1.11.2.3.9.1") == ("HP", "printer")  # HP: la descripción decide
    assert catlan.guess("ProCurve J9773A Switch 2530", "1.3.6.1.4.1.11.2.3.7.11.160") == ("HP", "switch")
    assert catlan.guess("Linux nas 4.4", "1.3.6.1.4.1.6574.1") == ("Synology", "nas") and catlan.guess("", None) == ("", "")
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
    assert any("incidencia crítica #%d" % inc["id"] in h["text"] for h in hooks)  # lo crítico avisa por los canales
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
    assert call(f"/api/incidents/{nieta}")[1]["history"][-1]["text"] == f"pasó a «resuelta» con su incidencia padre #{hija}"
    assert call(f"/api/incidents/{padre}", "DELETE")[0] == 204 and call(f"/api/incidents/{hija}")[1]["parent"] is None  # las hijas quedan sueltas
    assert call(f"/api/groups/{n1['id']}", "DELETE")[0] == 204 and call(f"/api/incidents/{inc['id']}")[1]["grp"] is None
    assert call(f"/api/incidents/{inc['id']}", "DELETE", auth=LEC)[0] == 403 and call(f"/api/incidents/{inc['id']}", "DELETE")[0] == 204
    assert {("incident", "crear"), ("incident", "borrar"), ("group", "crear")} <= {(h["kind"], h["action"]) for h in call("/api/log")[1]}
    call(f"/api/groups/{vista['id']}", "DELETE")
    # Kitty: el instalador de PowerShell lleva esta dirección y el id de esta instalación (al que queda atado);
    # se presenta sin sesión, queda pendiente y, aceptado, catlan mantiene su ficha
    st, ps = call("/kitty.ps1", auth="")
    ps = ps.decode()
    CAT = ps.split("$Catlan = '")[1][:32]
    assert st == 200 and f"$Url = 'http://127.0.0.1:{PORT}'" in ps and all(c in "0123456789abcdef" for c in CAT) and "{{" not in ps
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
    assert "key" not in ag and ag["code"] == catlan.sha(K1)[:8] and ag["state"] == "pendiente"
    kitty("c" * 64, name="pc-sin-ip", ip="")  # el Kitty de PowerShell no manda IP: la de su conexión
    assert next(a for a in call("/api/agents")[1] if a["name"] == "pc-sin-ip")["ip"] == "127.0.0.1"
    assert call("/api/agents", auth=LEC)[0] == 403 and call(f"/api/agents/{ag['id']}", "PUT", {"state": "adoptado"}, auth=LEC)[0] == 403
    it = call(f"/api/items/{call(f'/api/agents/{ag['id']}', 'PUT', {'state': 'adoptado'})[1]['item']}")[1]  # la ficha sale ya al aceptar
    assert (it["name"], it["ip"], it["serial"], it["kind"], it["status"]) == ("pc-kitty", "10.0.0.50", "KSN1", "pc", "activo")
    assert kitty(K1) == (200, {"state": "adoptado", "item": it["id"], "catlan": CAT}) and len(call("/api/items")[1]) == n_items + 1
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
    # expulsado: fuera de Salud con su historial; la ficha del inventario se queda
    assert call(f"/api/agents/{ag['id']}", "PUT", {"state": "rechazado"})[0] == 200 and not [h for h in call("/api/health")[1] if h["kind"] == "kitty"]
    assert call(f"/api/metrics?source={hk['id']}&hours=1")[1] == {} and len(call("/api/items")[1]) == n_items + 1
    assert {("agent", "aceptar"), ("agent", "rechazar"), ("agent", "olvidar")} <= {(h["kind"], h["action"]) for h in call("/api/log")[1]}
    assert call("/api/nope")[0] == 404
    # Auto-topología: LLDP, CDP y tabla MAC del switch -> quién está en qué puerto, casado con el inventario y dibujado
    nb = catlan.topology(catlan.SNMP("127.0.0.1", "switch", APORT))
    got = [(n["port"], n["via"], n["name"], n["ip"], n["mac"], n["rport"], n["icon"]) for n in nb]
    assert got == [("Gi1/0/1", "lldp", "srv-web.empresa.lan", "10.0.0.10", "00:50:56:9a:00:01", "eth0", "pc"),
                   ("Gi1/0/2", "cdp", "core-rtr", "10.0.0.1", None, "Gi0/0", "router"),
                   ("Gi1/0/3", "mac", "", "10.0.1.15", "aa:bb:cc:00:00:03", "", None),
                   ("Gi1/0/4", "mac", "", None, "aa:bb:cc:00:00:41", "", None),
                   ("Gi1/0/4", "mac", "", None, "aa:bb:cc:00:00:42", "", None)], got  # Gi1/0/5 (6 MAC) es un enlace: fuera
    srv_it = call("/api/items", "POST", {"name": "srv-web", "kind": "servidor", "ip": "192.168.99.10"})[1]  # por nombre (sin dominio)
    pc = call("/api/items", "POST", {"name": "pc-topo", "kind": "pc", "ip": "10.0.1.15"})[1]  # por la IP de la ARP
    sw_src = call("/api/sources", "POST", {"host": "127.0.0.1", "port": APORT, "community": "switch", "kind": "generic", "label": "sw-planta"})[1]
    st, tp = call(f"/api/sources/{sw_src['id']}/topology", "POST")
    assert st == 200 and tp["name"] == "Topología · sw-planta" and len(tp["neighbors"]) == 5, (st, tp)
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
            INSERT INTO log(who, action, kind, ref, name, data) VALUES('admin', 'borrar', 'item', 7, 'viejo', '{}');""")
    vieja = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(__file__), "catlan.py")],
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
    # Ediciones a la vez: con _seen, si otro lo cambió desde entonces, 409 con quién; sin _seen, como siempre
    pg = call("/api/pages", "POST", {"title": "Conflicto", "body": "v1"})[1]
    assert call(f"/api/pages/{pg['id']}", "PUT", {"body": "v2", "_seen": pg["updated"]})[0] == 200  # nadie en medio: guarda
    time.sleep(1.1)  # updated tiene resolución de segundos
    call(f"/api/pages/{pg['id']}", "PUT", {"body": "v3 de otro"})
    st, body = call(f"/api/pages/{pg['id']}", "PUT", {"body": "v2 tardía", "_seen": pg["updated"]})
    assert st == 409 and call(f"/api/pages/{pg['id']}")[1]["body"] == "v3 de otro", (st, body)
    assert call(f"/api/pages/{pg['id']}", "PUT", {"body": "la mía"})[1]["body"] == "la mía"  # «Guardar igualmente»
    # Aviso de garantías: una vez al día, solo las que caducan hoy o dentro de 30 días
    sent = []
    catlan.notify, catlan.channels = (lambda subject, text: sent.append(text)), (lambda: ["correo"])
    catlan.q("DELETE FROM meta WHERE k='warranty_day'")
    for name, days in (("caduca-hoy", 0), ("caduca-en-30", 30), ("caduca-en-31", 31)):
        catlan.q("INSERT INTO items(name, warranty) VALUES(?, date('now', 'localtime', ?))", [name, f"+{days} days"])
    catlan.warranties(), catlan.warranties()
    assert len(sent) == 1 and "caduca-hoy: hoy" in sent[0] and "caduca-en-30: el " in sent[0] and "caduca-en-31" not in sent[0], sent
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
    # Fuerza bruta: 10 fallos en 15 min desde una IP y esa IP espera, aunque luego acierte (va al final: bloquea 127.0.0.1)
    codes = [raw("/api/login", "POST", {"name": "admin", "pass": f"intento{i}"})[0] for i in range(12)]
    assert codes[-1] == 429 and raw("/api/login", "POST", {"name": "admin", "pass": "miau"})[0] == 429, codes
    assert b"catlan" in call("/")[1]
    print("OK")
finally:
    srv.terminate()
