#!/usr/bin/env python3
"""Auto-topología contra un agente SNMP de verdad (snmpsim, de LeXtudio) con un switch grabado: LLDP, CDP, tabla MAC con VLAN y ARP,
con la numeración de un Cisco (ifIndex 10101…, puerto de bridge distinto del ifIndex, LLDP por número de puerto). Por v2c y por v3.

    pip install snmpsim pysmi cryptography     (como test_snmpv3.py; si no está en el PATH: SNMPSIM_RESPONDER=ruta)
"""
import os, shutil, subprocess, sys, tempfile, time
from prueba_api import Catlan

exe = os.environ.get("SNMPSIM_RESPONDER") or shutil.which("snmpsim-command-responder")
if not exe:
    sys.exit("No encuentro snmpsim-command-responder: pip install snmpsim pysmi cryptography (o SNMPSIM_RESPONDER=ruta)")
L, LM, LL, C, F, A = ("1.0.8802.1.1.2.1.4.1.1", "1.0.8802.1.1.2.1.4.2.1", "1.0.8802.1.1.2.1.3.7.1", "1.3.6.1.4.1.9.9.23.1.2.1.1",
                      "1.3.6.1.2.1.17.7.1.2.2.1.2", "1.3.6.1.2.1.4.22.1.2")
hexs = lambda b: "4x|" + b.hex()
rec = {f"1.3.6.1.2.1.1.1.0": "4|Cisco IOS Software, C2960X", f"1.3.6.1.2.1.1.5.0": "4|sw-core-01"}
rec.update({f"1.3.6.1.2.1.31.1.1.1.1.{10100 + n}": f"4|Gi1/0/{n}" for n in range(1, 11)})  # ifIndex «de Cisco»: 10101…
rec.update({f"1.3.6.1.2.1.17.1.4.1.2.{n}": f"2|{10100 + n}" for n in range(1, 11)})          # puerto del bridge != ifIndex
rec.update({
    f"{LL}.3.1": "4|Gi1/0/1", f"{LL}.3.2": "4|Gi1/0/2",  # LLDP numera sus puertos 1, 2… y da el nombre: hay que traducir
    f"{L}.5.0.1.1": hexs(bytes.fromhex("0050569a0001")), f"{L}.7.0.1.1": "4|eth0", f"{L}.9.0.1.1": "4|srv-web.empresa.lan",
    f"{L}.12.0.1.1": hexs(bytes([0x01, 0x00])), f"{LM}.3.0.1.1.1.4.10.0.0.10": "2|2",
    f"{L}.5.0.2.1": hexs(bytes.fromhex("0050569a0002")), f"{L}.7.0.2.1": "4|Gi1/0/48", f"{L}.9.0.2.1": "4|sw-planta-2",
    f"{L}.12.0.2.1": hexs(bytes([0x20, 0x00])),
    f"{C}.4.10103.1": hexs(bytes([10, 0, 0, 1])), f"{C}.6.10103.1": "4|core-rtr", f"{C}.7.10103.1": "4|GigabitEthernet0/0",
    f"{C}.9.10103.1": hexs(bytes([0, 0, 0, 0x29])),  # router + switch (Cisco) -> router
    f"{A}.10104.10.0.1.15": hexs(bytes.fromhex("aabbcc000004")),
})
for port, macs in ((4, ["aabbcc000004"]), (5, ["aabbcc000051", "aabbcc000052"]), (6, [f"aabbcc0000{i:02x}" for i in range(0x60, 0x66)])):
    for m in macs:
        rec[F + ".10." + ".".join(str(b) for b in bytes.fromhex(m))] = f"2|{port}"  # VLAN 10
key = lambda o: [int(x) for x in o.split(".")]
data = tempfile.mkdtemp()
for fn in ("switch.snmprec", ".snmprec"):  # comunidad «switch» (v2c) y contexto vacío (v3, como los equipos reales)
    with open(os.path.join(data, fn), "w") as f:
        f.write("".join(f"{o}|{rec[o]}\n" for o in sorted(rec, key=key)))

PORT = 17261
sim = subprocess.Popen([exe, "--v3-engine-id", "auto", "--v3-user", "topo", "--v3-auth-key", "clave-auth-topo", "--v3-auth-proto", "SHA",
                        "--v3-priv-key", "clave-priv-topo", "--v3-priv-proto", "AES", "--data-dir", data, f"--agent-udpv4-endpoint=127.0.0.1:{PORT}"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # los v3 antes de --data-dir: snmpsim los lee en orden
cat = Catlan(18202)
try:
    v2 = {"host": "127.0.0.1", "port": PORT, "kind": "generic", "community": "switch", "label": "v2c"}
    v3 = {"host": "127.0.0.1", "port": PORT, "kind": "generic", "v3": 1, "user": "topo", "auth": "sha", "pass": "clave-auth-topo",
          "priv": "aes", "priv_pass": "clave-priv-topo", "label": "v3"}
    t0 = time.time()
    while cat.call("/api/sources/test", "POST", v2)[0] != 200:  # snmpsim tarda en indexar los datos al arrancar
        if time.time() - t0 > 120:
            raise TimeoutError("snmpsim no contesta")
        time.sleep(0.5)
    want = [("Gi1/0/1", "lldp", "srv-web.empresa.lan", "10.0.0.10", "00:50:56:9a:00:01", "eth0", "pc"),
            ("Gi1/0/2", "lldp", "sw-planta-2", None, "00:50:56:9a:00:02", "Gi1/0/48", "switch"),
            ("Gi1/0/3", "cdp", "core-rtr", "10.0.0.1", None, "GigabitEthernet0/0", "router"),
            ("Gi1/0/4", "mac", "", "10.0.1.15", "aa:bb:cc:00:00:04", "", None),
            ("Gi1/0/5", "mac", "", None, "aa:bb:cc:00:00:51", "", None),
            ("Gi1/0/5", "mac", "", None, "aa:bb:cc:00:00:52", "", None)]
    for src in (v2, v3):
        sid = cat.call("/api/sources", "POST", src)[1]["id"]
        st, tp = cat.call(f"/api/sources/{sid}/topology", "POST")
        got = [(n["port"], n["via"], n["name"], n["ip"], n["mac"], n["rport"], n["icon"]) for n in tp.get("neighbors", [])]
        assert st == 200 and got == want, (src["label"], st, tp)
        print(f"  {src['label']}: OK ({len(got)} vecinos)")
    print("OK")
finally:
    sim.terminate()
    cat.stop()
