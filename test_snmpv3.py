#!/usr/bin/env python3
"""catlan contra un agente SNMPv3 de verdad (snmpsim, de LeXtudio). Aparte de test_catlan.py porque necesita instalarlo:

    pip install snmpsim pysmi cryptography

Si el ejecutable no está en el PATH, indica su ruta en SNMPSIM_RESPONDER.
"""
import os, shutil, subprocess, sys, tempfile, time

os.environ["CATLAN_DATA"] = tempfile.mkdtemp()  # catlan importado solo por su cliente SNMP
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import catlan  # noqa: E402

exe = os.environ.get("SNMPSIM_RESPONDER") or shutil.which("snmpsim-command-responder")
if not exe:
    sys.exit("No encuentro snmpsim-command-responder: pip install snmpsim pysmi cryptography (o SNMPSIM_RESPONDER=ruta)")

# Un servidor con 8 GB de RAM al 75 %, / al 50 % y /datos al 95 %. Archivo «.snmprec» = contexto vacío, como en los equipos reales.
data = tempfile.mkdtemp()
with open(os.path.join(data, ".snmprec"), "w") as f:
    f.write("""1.3.6.1.2.1.1.1.0|4|Linux srv-v3 6.1.0
1.3.6.1.2.1.1.3.0|67|123456700
1.3.6.1.2.1.1.5.0|4|srv-v3
1.3.6.1.2.1.25.2.3.1.2.1|6|1.3.6.1.2.1.25.2.1.2
1.3.6.1.2.1.25.2.3.1.2.31|6|1.3.6.1.2.1.25.2.1.4
1.3.6.1.2.1.25.2.3.1.2.32|6|1.3.6.1.2.1.25.2.1.4
1.3.6.1.2.1.25.2.3.1.3.1|4|Physical memory
1.3.6.1.2.1.25.2.3.1.3.31|4|/
1.3.6.1.2.1.25.2.3.1.3.32|4|/datos
1.3.6.1.2.1.25.2.3.1.4.1|2|1024
1.3.6.1.2.1.25.2.3.1.4.31|2|4096
1.3.6.1.2.1.25.2.3.1.4.32|2|4096
1.3.6.1.2.1.25.2.3.1.5.1|2|8000000
1.3.6.1.2.1.25.2.3.1.5.31|2|1000000
1.3.6.1.2.1.25.2.3.1.5.32|2|1000000
1.3.6.1.2.1.25.2.3.1.6.1|2|6000000
1.3.6.1.2.1.25.2.3.1.6.31|2|500000
1.3.6.1.2.1.25.2.3.1.6.32|2|950000
1.3.6.1.2.1.25.3.3.1.2.196608|2|30
""")

PORT = 17161
CASES = [("sha", "aes"), ("md5", "none"), ("sha224", "aes"), ("sha256", "aes"), ("sha384", "aes"), ("sha512", "aes"), ("none", "none")]
args = [exe]
for n, (a, p) in enumerate(CASES):
    args += ["--v3-engine-id", "auto", "--v3-user", f"u{n}", "--data-dir", data, f"--agent-udpv4-endpoint=127.0.0.1:{PORT + n}"]
    args += ["--v3-auth-key", f"clave-auth-{n}", "--v3-auth-proto", a.upper()] if a != "none" else []
    args += ["--v3-priv-key", f"clave-priv-{n}", "--v3-priv-proto", "AES"] if p != "none" else []
sim = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def src(n, **chg):
    a, p = CASES[n]
    return {"host": "127.0.0.1", "port": PORT + n, "kind": "generic", "v3": 1, "user": f"u{n}", "auth": a, "priv": p,
            "pass": f"clave-auth-{n}", "priv_pass": f"clave-priv-{n}", **chg}


def fails(s):
    try:
        catlan.collect(s)
    except Exception as e:
        return str(e)
    return None


try:
    deadline = time.time() + 90  # snmpsim tarda en indexar los datos al arrancar
    while fails(src(len(CASES) - 1)) and time.time() < deadline:
        time.sleep(1)
    for n, (a, p) in enumerate(CASES):
        out, probs, info = catlan.collect(src(n))
        got = {k: v for k, _, v, _ in out}
        assert info["name"] == "srv-v3" and info["uptime"] == 1234567, (a, p, info)
        assert got == {"mem": 75, "disk:/": 50, "disk:/datos": 95, "cpu": 30}, (a, p, got)
        assert probs == ["/datos: 95 % lleno (límite 90 %)"], probs
        print(f"  {a}/{p}: OK")
    s = catlan.SNMP("127.0.0.1", port=PORT, v3=src(0))  # recorrer tablas y resincronizar el reloj del equipo
    assert len(s.walk("1.3.6.1.2.1.25.2.3.1.3")) == 3
    s.etime += 5000
    assert s.get("1.3.6.1.2.1.1.5.0")["1.3.6.1.2.1.1.5.0"] == "srv-v3"
    assert "usuario SNMPv3 desconocido" in fails(src(0, user="nadie"))
    assert "la firma no coincide" in fails(src(0, **{"pass": "otra-clave-mala"}))
    assert "la firma no coincide" in fails(src(0, auth="md5"))
    assert "no se pudo descifrar" in fails(src(0, priv_pass="otra-clave-mala"))
    assert "nivel de seguridad" in fails(src(0, priv="none"))
    assert "sin respuesta SNMP" in fails(src(0, port=PORT + 50))  # puerto cerrado: mensaje claro también en Windows
    print("OK")
finally:
    sim.terminate()
