"""Pruebas de la web en un navegador de verdad (Playwright, Chromium) contra el ejecutable de catlan.
Hace falta: pip install playwright==1.65.2 && python -m playwright install chromium
Luego: cargo build --release && python tests/test_ui.py (o CATLAN_BIN=ruta)"""
from pathlib import Path
import hashlib, os, re, ssl, subprocess, sys, tempfile, time
from playwright.sync_api import sync_playwright, expect

HERE = Path(__file__).resolve().parent.parent
BIN = os.environ.get("CATLAN_BIN") or str(HERE / "target" / "release" / ("catlan.exe" if os.name == "nt" else "catlan"))
if not Path(BIN).exists():
    sys.exit(f"No encuentro {BIN}: compila con «cargo build --release» o indica la ruta en CATLAN_BIN")
PORT = 18120
BASE = f"https://127.0.0.1:{PORT}"
srv = subprocess.Popen([BIN], env={**os.environ, "CATLAN_DATA": tempfile.mkdtemp(), "CATLAN_PORT": str(PORT), "CATLAN_PASSWORD": "miau"}, stdout=subprocess.DEVNULL)
try:
    for _ in range(100):
        try: pem = ssl.get_server_certificate(("127.0.0.1", PORT)); break
        except OSError: time.sleep(0.1)
    else: raise AssertionError("catlan no arranca")
    PIN = hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest().upper()  # la huella que tiene que enseñar el diálogo de Kitty
    errors = []
    with sync_playwright() as p:
        browser = p.chromium.launch()
        ctx = browser.new_context(ignore_https_errors=True, base_url=BASE)  # certificado autofirmado
        ctx.add_init_script("localStorage.setItem('catlan-tour-1', '1')")  # sin el tutorial de la primera vez
        page = ctx.new_page()
        page.on("pageerror", lambda e: errors.append(str(e)))
        page.on("console", lambda m: m.type == "error" and errors.append(m.text))

        # Login
        page.goto("/")
        page.get_by_label("Usuario").fill("admin")
        page.get_by_label("Contraseña").fill("mal")
        page.get_by_role("button", name="Entrar").click()
        expect(page.locator(".login-err")).not_to_be_empty()
        errors.clear()  # el 401 de la contraseña mala sale en la consola: es lo esperado
        page.get_by_label("Contraseña").fill("miau")
        page.get_by_role("button", name="Entrar").click()
        expect(page.locator("#login")).to_have_count(0)
        expect(page.locator("#user-name")).to_have_text("admin")

        # Alta de equipo desde «Nuevo»
        page.locator("#new").click()
        page.locator(".menu:not(.out)").get_by_role("menuitem", name="Equipo", exact=True).click()
        expect(page).to_have_url(re.compile(r"#/inv/\d+$"))
        expect(page.locator("#app")).to_contain_text("Nuevo equipo")
        assert [i["name"] for i in page.request.get("/api/items").json()] == ["Nuevo equipo"]

        # Abrir una incidencia
        page.locator("#new").click()
        page.locator(".menu:not(.out)").get_by_role("menuitem", name="Incidencia").click()
        page.locator("dialog[open] #i-t").fill("La impresora no imprime")
        page.get_by_role("button", name="Crear incidencia").click()
        expect(page).to_have_url(re.compile(r"#/inc/\d+$"))
        expect(page.locator("#app")).to_contain_text("La impresora no imprime")
        assert page.request.get("/api/incidents").json()[0]["status"] == "abierta"

        # «Añadir con Kitty»: enseña la huella del certificado y la mete en el comando
        page.goto("/#/inv")
        page.get_by_role("button", name="Añadir con Kitty").click()
        dlg = page.locator("dialog[open]")
        expect(dlg).to_contain_text("Añadir un equipo con Kitty")
        expect(dlg).to_contain_text(PIN)
        expect(dlg.locator("code").first).to_contain_text(f"-eq '{PIN}'")
        dlg.get_by_role("button", name="Listo").click()
        expect(page.locator("dialog[open]")).to_have_count(0)

        assert not errors, errors
        browser.close()
    print("OK")
finally:
    srv.terminate()
