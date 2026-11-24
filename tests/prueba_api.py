"""Arranca el ejecutable de catlan en una carpeta temporal y habla con su API (para test_snmpv3.py y test_topologia.py)."""
import base64, json, os, subprocess, sys, tempfile, time, urllib.error, urllib.request
from pathlib import Path

BIN = os.environ.get("CATLAN_BIN") or str(Path(__file__).parent.parent / "target" / "release" / ("catlan.exe" if os.name == "nt" else "catlan"))
AUTH = "Basic " + base64.b64encode(b"admin:prueba-api").decode()


class Catlan:
    def __init__(self, port):
        if not Path(BIN).exists():
            sys.exit(f"No encuentro {BIN}: compila con «cargo build --release» o indica la ruta en CATLAN_BIN")
        self.url = f"http://127.0.0.1:{port}"
        env = {**os.environ, "CATLAN_DATA": tempfile.mkdtemp(), "CATLAN_PORT": str(port), "CATLAN_PASSWORD": "prueba-api", "CATLAN_SYSLOG_PORT": "0"}
        self.proc = subprocess.Popen([BIN], env=env, stdout=subprocess.DEVNULL)
        for _ in range(100):
            try:
                self.call("/api/me")
                return
            except OSError:
                time.sleep(0.1)

    def call(self, path, method="GET", body=None):
        """(código, JSON de la respuesta)"""
        req = urllib.request.Request(self.url + path, None if body is None else json.dumps(body).encode(), method=method,
                                     headers={"Authorization": AUTH, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    def stop(self):
        self.proc.terminate()
