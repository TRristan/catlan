"""Prueba de carga: N Kitty enviando su estado a catlan cada 15 s, por HTTPS como los de verdad.

    python tests/carga.py [equipos=500] [segundos=120]

Arranca un catlan con datos temporales (cargo build --release; o CATLAN_BIN=ruta), mide la latencia de cada envío y,
si está psutil, la CPU, memoria e hilos de catlan. No es parte de tests/test_catlan.py: tarda y depende de la máquina.
"""
from pathlib import Path
import json, os, random, socket, ssl, statistics, subprocess, sys, tempfile, threading, time, urllib.request, urllib.error

HERE = Path(__file__).resolve().parent.parent
BIN = os.environ.get("CATLAN_BIN") or str(HERE / "target" / "release" / ("catlan.exe" if os.name == "nt" else "catlan"))
N = int(sys.argv[1]) if len(sys.argv) > 1 else 500
SECS = int(sys.argv[2]) if len(sys.argv) > 2 else 120
EVERY = 15

with socket.socket() as s:
    s.bind(("127.0.0.1", 0)); PORT = s.getsockname()[1]
data = tempfile.mkdtemp()
env = {**os.environ, "CATLAN_DATA": data, "CATLAN_PORT": str(PORT), "CATLAN_PASSWORD": "carga-carga", "CATLAN_SYSLOG_PORT": "0"}
srv = subprocess.Popen([BIN], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
URL = f"https://127.0.0.1:{PORT}"

def post(body):
    req = urllib.request.Request(f"{URL}/api/agent", json.dumps(body).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
        return r.status

for _ in range(100):
    try: urllib.request.urlopen(f"{URL}/kitty.json", context=ctx, timeout=2); break
    except OSError: time.sleep(0.1)

import base64
AUTH = {"Authorization": "Basic " + base64.b64encode(b"admin:carga-carga").decode(), "Content-Type": "application/json"}

def admin(path, method="GET", body=None):
    req = urllib.request.Request(f"{URL}/api/{path}", None if body is None else json.dumps(body).encode(), AUTH, method=method)
    with urllib.request.urlopen(req, context=ctx, timeout=30) as r:
        return json.loads(r.read() or b"null")

def hello(i):  # primer envío: queda pendiente de aceptar
    k = f"{i:064x}"
    post({"key": k, "ukey": k, "name": f"PC-{i:04d}", "ip": "", "serial": f"S{i}", "os": "windows/amd64", "kind": "pc", "every": 1, "secs": EVERY, "facts": {}, "events": []})

# Como en la realidad, los Kitty ya aceptados (lo pesado: ficha, Salud y métricas). Se aceptan de 100 en 100: catlan no
# deja más pendientes a la vez.
t0 = time.time()
for lo in range(0, N, 100):
    for i in range(lo, min(N, lo + 100)): hello(i)
    for a in admin("agents"):
        if a["state"] == "pendiente": admin(f"agents/{a['id']}", "PUT", {"state": "adoptado"})
print(f"{N} Kitty dados de alta y aceptados en {time.time() - t0:.0f} s")

lat, errors, lock, stop = [], [], threading.Lock(), time.time() + SECS

def kitty(i):
    key = f"{i:064x}"
    facts = {"osver": "Windows 11 Pro", "model": "Prueba", "cpu": "x86", "cores": 8, "load": 0, "mem_total": 16 << 30, "mem_free": 8 << 30,
             "uptime": 3600, "disks": [{"name": "C:", "total": 512 << 30, "free": 200 << 30}], "ips": [f"10.0.{i // 250}.{i % 250 + 1}"]}
    time.sleep(random.uniform(0, EVERY))  # repartidos, como PCs que arrancan a horas distintas
    while time.time() < stop:
        facts["load"] = random.randint(0, 100)
        body = {"key": key, "ukey": key, "name": f"PC-{i:04d}", "ip": "", "serial": f"S{i}", "os": "windows/amd64", "kind": "pc",
                "every": 1, "secs": EVERY, "facts": facts, "events": [], "apps": {}}
        t0 = time.perf_counter()
        try:
            post(body)
            with lock: lat.append((time.perf_counter() - t0) * 1000)
        except (OSError, urllib.error.HTTPError) as e:
            with lock: errors.append(str(e)[:80])
        time.sleep(max(0, EVERY - (time.perf_counter() - t0)))

try:
    import psutil
    proc = psutil.Process(srv.pid); proc.cpu_percent()
except ImportError:
    proc = None
samples = []
threads = [threading.Thread(target=kitty, args=(i,), daemon=True) for i in range(N)]
for t in threads: t.start()
print(f"{N} Kitty cada {EVERY} s durante {SECS} s contra {URL} ({N / EVERY:.0f} envíos/s)…")
while time.time() < stop:
    time.sleep(5)
    if proc: samples.append((proc.cpu_percent(), proc.memory_info().rss >> 20, proc.num_threads()))
for t in threads: t.join(timeout=40)
srv.terminate()

lat.sort()
pct = lambda p: lat[min(len(lat) - 1, int(len(lat) * p))] if lat else float("nan")
print(f"envíos: {len(lat)} bien, {len(errors)} con error" + (f" (p. ej. {errors[0]})" if errors else ""))
print(f"latencia ms: mediana {pct(.5):.0f} · p95 {pct(.95):.0f} · p99 {pct(.99):.0f} · máx {lat[-1] if lat else 0:.0f}")
if samples:
    print(f"catlan: CPU media {statistics.mean(s[0] for s in samples):.0f} % (máx {max(s[0] for s in samples):.0f} %, de un núcleo = 100 %) · "
          f"memoria máx {max(s[1] for s in samples)} MB · hilos máx {max(s[2] for s in samples)}")
sys.exit(1 if errors else 0)
