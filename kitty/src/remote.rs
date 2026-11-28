//! Control remoto: Kitty pregunta a catlan si IT quiere conectarse y, solo si el usuario lo permite, le envía la pantalla
//! (JPEG, solo cuando cambia) y aplica el ratón y el teclado del técnico. Todo sale del PC hacia catlan: no abre puertos.
use serde_json::{Value, json};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tungstenite::client::IntoClientRequest;
use tungstenite::{Message, WebSocket};
use windows_sys::Win32::Graphics::Gdi::*;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::*;
use windows_sys::Win32::UI::WindowsAndMessaging::{CURSOR_SHOWING, CURSORINFO, DI_NORMAL, DrawIconEx, GetCursorInfo, GetSystemMetrics, SM_CXSCREEN, SM_CYSCREEN};

/// Ancho máximo de lo que se envía: de sobra para leer y ligero en la red.
const MAX_W: i32 = 1600;
/// Como mucho, unos 10 fotogramas por segundo.
const TICK: Duration = Duration::from_millis(100);

/// La pantalla principal, reducida a MAX_W de ancho, con el puntero dibujado: (BGRA, ancho, alto).
fn capture() -> Option<(Vec<u8>, i32, i32)> {
    unsafe {
        let (sw, sh) = (GetSystemMetrics(SM_CXSCREEN), GetSystemMetrics(SM_CYSCREEN));
        if sw <= 0 || sh <= 0 {
            return None;
        }
        let (w, h) = if sw > MAX_W { (MAX_W, sh * MAX_W / sw) } else { (sw, sh) };
        let src = GetDC(std::ptr::null_mut());
        let mem = CreateCompatibleDC(src);
        let mut bi: BITMAPINFO = std::mem::zeroed();
        bi.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
        bi.bmiHeader.biWidth = w;
        bi.bmiHeader.biHeight = -h; // de arriba abajo
        bi.bmiHeader.biPlanes = 1;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = BI_RGB;
        let mut bits = std::ptr::null_mut();
        let bmp = CreateDIBSection(mem, &bi, DIB_RGB_COLORS, &mut bits, std::ptr::null_mut(), 0);
        let old = SelectObject(mem, bmp);
        SetStretchBltMode(mem, HALFTONE);
        SetBrushOrgEx(mem, 0, 0, std::ptr::null_mut());
        let ok = StretchBlt(mem, 0, 0, w, h, src, 0, 0, sw, sh, SRCCOPY | CAPTUREBLT) != 0;
        let mut ci: CURSORINFO = std::mem::zeroed();
        ci.cbSize = size_of::<CURSORINFO>() as u32;
        if ok && GetCursorInfo(&mut ci) != 0 && ci.flags & CURSOR_SHOWING != 0 {
            DrawIconEx(mem, ci.ptScreenPos.x * w / sw, ci.ptScreenPos.y * h / sh, ci.hCursor, 0, 0, 0, std::ptr::null_mut(), DI_NORMAL);
        }
        let out = (ok && !bits.is_null()).then(|| std::slice::from_raw_parts(bits as *const u8, (w * h * 4) as usize).to_vec());
        SelectObject(mem, old);
        DeleteObject(bmp);
        DeleteDC(mem);
        ReleaseDC(std::ptr::null_mut(), src);
        out.map(|px| (px, w, h))
    }
}

/// Una captura de la pantalla principal en JPEG, para adjuntarla a un aviso. None si no se puede.
pub fn screenshot() -> Option<Vec<u8>> {
    let (px, w, h) = capture()?;
    Some(jpeg(&px, w, h)).filter(|j| !j.is_empty())
}

fn jpeg(px: &[u8], w: i32, h: i32) -> Vec<u8> {
    let mut out = Vec::with_capacity(px.len() / 12);
    let enc = jpeg_encoder::Encoder::new(&mut out, 60);
    if enc.encode(px, w as u16, h as u16, jpeg_encoder::ColorType::Bgra).is_err() {
        return vec![];
    }
    out
}

fn send(inputs: &[INPUT]) {
    unsafe {
        SendInput(inputs.len() as u32, inputs.as_ptr(), size_of::<INPUT>() as i32);
    }
}

fn mouse(flags: MOUSE_EVENT_FLAGS, dx: i32, dy: i32, data: i32) -> INPUT {
    INPUT { r#type: INPUT_MOUSE, Anonymous: INPUT_0 { mi: MOUSEINPUT { dx, dy, mouseData: data as _, dwFlags: flags, time: 0, dwExtraInfo: 0 } } }
}

fn key(vk: u16, scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT { r#type: INPUT_KEYBOARD, Anonymous: INPUT_0 { ki: KEYBDINPUT { wVk: vk, wScan: scan, dwFlags: flags, time: 0, dwExtraInfo: 0 } } }
}

/// La tecla de Windows para un `KeyboardEvent.code` del navegador, y si es «extendida» (flechas, Supr, Ctrl y Alt derechos…).
fn vk(code: &str) -> Option<(u16, bool)> {
    let v = match code {
        "Enter" => 0x0D,
        "NumpadEnter" => return Some((0x0D, true)),
        "Backspace" => 0x08,
        "Tab" => 0x09,
        "Escape" => 0x1B,
        "Space" => 0x20,
        "CapsLock" => 0x14,
        "ShiftLeft" => 0xA0,
        "ShiftRight" => 0xA1,
        "ControlLeft" => 0xA2,
        "AltLeft" => 0xA4,
        "ControlRight" => return Some((0xA3, true)),
        "AltRight" => return Some((0xA5, true)),
        "MetaLeft" => return Some((0x5B, true)),
        "MetaRight" => return Some((0x5C, true)),
        "PageUp" => return Some((0x21, true)),
        "PageDown" => return Some((0x22, true)),
        "End" => return Some((0x23, true)),
        "Home" => return Some((0x24, true)),
        "ArrowLeft" => return Some((0x25, true)),
        "ArrowUp" => return Some((0x26, true)),
        "ArrowRight" => return Some((0x27, true)),
        "ArrowDown" => return Some((0x28, true)),
        "Insert" => return Some((0x2D, true)),
        "Delete" => return Some((0x2E, true)),
        c if c.len() == 4 && c.starts_with("Key") => c.as_bytes()[3] as u16, // KeyA → 'A'
        c if c.len() == 6 && c.starts_with("Digit") => c.as_bytes()[5] as u16,
        c if c.starts_with('F') && c[1..].parse::<u16>().is_ok_and(|n| (1..=12).contains(&n)) => 0x6F + c[1..].parse::<u16>().unwrap_or(1),
        _ => return None,
    };
    Some((v, false))
}

/// Teclas mantenidas, para soltarlas al acabar (si no, el PC se quedaría con Ctrl pulsado).
#[derive(Default)]
struct Held(Vec<(u16, bool)>);

impl Held {
    fn mods(&self) -> bool {
        self.0.iter().any(|(v, _)| matches!(v, 0xA2 | 0xA3 | 0xA4 | 0xA5 | 0x5B | 0x5C))
    }
    fn release(&mut self) {
        for (v, ext) in self.0.drain(..) {
            send(&[key(v, 0, KEYEVENTF_KEYUP | if ext { KEYEVENTF_EXTENDEDKEY } else { 0 })]);
        }
    }
}

/// Un evento de la web del técnico. Ratón: x, y de 0 a 1 sobre la pantalla. Teclado: el `code` y el `key` del navegador.
fn apply(e: &Value, held: &mut Held) {
    let f = |k: &str| e.get(k).and_then(Value::as_f64).unwrap_or(0.0);
    let abs = |k: &str| (f(k).clamp(0.0, 1.0) * 65535.0) as i32;
    match e.get("t").and_then(Value::as_str).unwrap_or("") {
        "m" => send(&[mouse(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, abs("x"), abs("y"), 0)]),
        t @ ("d" | "u") => {
            let down = t == "d";
            let fl = match f("b") as i32 {
                1 => {
                    if down {
                        MOUSEEVENTF_MIDDLEDOWN
                    } else {
                        MOUSEEVENTF_MIDDLEUP
                    }
                }
                2 => {
                    if down {
                        MOUSEEVENTF_RIGHTDOWN
                    } else {
                        MOUSEEVENTF_RIGHTUP
                    }
                }
                _ => {
                    if down {
                        MOUSEEVENTF_LEFTDOWN
                    } else {
                        MOUSEEVENTF_LEFTUP
                    }
                }
            };
            send(&[mouse(MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE, abs("x"), abs("y"), 0), mouse(fl, 0, 0, 0)]);
        }
        "w" => send(&[mouse(MOUSEEVENTF_WHEEL, 0, 0, (-f("d") * 1.2).clamp(-1200.0, 1200.0) as i32)]), // 100 del navegador ≈ 120 de Windows
        "k" => {
            let down = e.get("d").and_then(Value::as_bool).unwrap_or(false);
            let code = e.get("c").and_then(Value::as_str).unwrap_or("");
            let text = e.get("k").and_then(Value::as_str).unwrap_or("");
            // un carácter sin Ctrl/Alt/Win: tal cual (vale con cualquier distribución de teclado); con ellos, la tecla (Ctrl+C…)
            if text.chars().count() == 1 && !held.mods() && !matches!(code, "Space" | "Enter" | "Tab") {
                if down {
                    let mut ins = vec![];
                    for u in text.encode_utf16() {
                        ins.push(key(0, u, KEYEVENTF_UNICODE));
                        ins.push(key(0, u, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP));
                    }
                    send(&ins);
                }
                return;
            }
            let Some((v, ext)) = vk(code) else { return };
            let fl = if ext { KEYEVENTF_EXTENDEDKEY } else { 0 };
            if down {
                send(&[key(v, 0, fl)]);
                if !held.0.contains(&(v, ext)) {
                    held.0.push((v, ext));
                }
            } else {
                send(&[key(v, 0, fl | KEYEVENTF_KEYUP)]);
                held.0.retain(|x| *x != (v, ext));
            }
        }
        _ => {}
    }
}

/// El socket con catlan, con lecturas que esperan poco: un tiempo agotado se cuenta como «aún no hay nada» (WouldBlock),
/// que es lo que rustls y tungstenite saben reanudar (Windows dice TimedOut).
struct Sock(TcpStream);

impl Read for Sock {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        self.0.read(b).map_err(|e| if e.kind() == io::ErrorKind::TimedOut { io::ErrorKind::WouldBlock.into() } else { e })
    }
}

impl Write for Sock {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.write(b)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

type Ws = WebSocket<rustls::StreamOwned<rustls::ClientConnection, Sock>>;

/// «https://host:puerto/…» → (host, puerto), también con IPv6 entre corchetes.
fn host_port(url: &str) -> Option<(String, u16)> {
    let hp = url.strip_prefix("https://")?.split('/').next()?;
    let (h, p) = match hp.strip_prefix('[') {
        Some(v6) => {
            let (h, rest) = v6.split_once(']')?;
            (h, rest.strip_prefix(':'))
        }
        None => match hp.rsplit_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (hp, None),
        },
    };
    Some((h.to_string(), p.map_or(Some(443), |p| p.parse().ok())?))
}

/// El WebSocket de la sesión, por el mismo TLS (anclado) que el resto de Kitty.
fn connect(url: &str, ukey: &str, id: &str) -> Result<Ws, String> {
    let (host, port) = host_port(url).ok_or("catlan no está en una dirección https")?;
    let tcp = TcpStream::connect((host.as_str(), port)).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(Duration::from_secs(15))).map_err(|e| e.to_string())?;
    let _ = tcp.set_nodelay(true);
    let cfg = crate::net::tls().ok_or("no hay TLS")?;
    let name = rustls::pki_types::ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
    let conn = rustls::ClientConnection::new(cfg, name).map_err(|e| e.to_string())?;
    let at = url.trim_start_matches("https://").split('/').next().unwrap_or("");
    let mut req = format!("wss://{at}/api/agent/remote/ws").into_client_request().map_err(|e| e.to_string())?;
    req.headers_mut().insert("X-Kitty", ukey.parse().map_err(|_| "clave rara")?);
    req.headers_mut().insert("X-Sesion", id.parse().map_err(|_| "sesión rara")?);
    let (ws, _) = tungstenite::client(req, rustls::StreamOwned::new(conn, Sock(tcp))).map_err(|e| e.to_string())?;
    // ya abierto: leer solo lo que haya, para volver enseguida a por la pantalla
    ws.get_ref().sock.0.set_read_timeout(Some(Duration::from_millis(20))).map_err(|e| e.to_string())?;
    Ok(ws)
}

/// Sin cambios en la pantalla, un fotograma vacío cada tanto: así catlan sabe que Kitty sigue ahí.
const ALIVE: Duration = Duration::from_secs(2);

/// La sesión aceptada: pantalla hacia catlan y ratón y teclado de vuelta, hasta que alguien la corte.
/// Devuelve por qué acabó, para enseñárselo al usuario.
/// `note`: avisos para la ventana mientras dura («IT te ha enviado informe.pdf»).
pub fn session(url: &str, ukey: &str, id: &str, stop: &Arc<AtomicBool>, note: Note) -> String {
    let mut held = Held::default();
    let why = match connect(url, ukey, id) {
        Ok(ws) => run(ws, url, ukey, id, stop, &mut held, note),
        Err(e) => format!("No se pudo conectar con catlan: {e}."),
    };
    held.release();
    why
}

pub type Note = Arc<dyn Fn(String) + Send + Sync>;

/// Como mucho esto por archivo: lo que admite catlan por petición.
const FILE_MAX: u64 = 20 << 20;

/// Lo que llega del técnico y no es ratón ni teclado: un archivo para este PC o uno que pide. En otro hilo, como el
/// usuario del PC (con sus permisos): la pantalla no se para mientras va y viene.
fn file_event(e: &Value, url: &str, ukey: &str, id: &str, note: &Note) -> bool {
    let (url, ukey, id, note) = (url.to_string(), ukey.to_string(), id.to_string(), note.clone());
    match e.get("t").and_then(Value::as_str) {
        Some("file") => {
            let (fid, name) = (e["id"].as_u64().unwrap_or(0), e["name"].as_str().unwrap_or("archivo").to_string());
            std::thread::spawn(move || {
                note(match receive(&url, &ukey, &id, fid, &name) {
                    Ok(p) => format!("IT te ha enviado {name}: está en {}", p.display()),
                    Err(e) => format!("No se pudo recibir {name}: {e}"),
                })
            });
        }
        Some("get") => {
            let path = e["path"].as_str().unwrap_or("").to_string();
            std::thread::spawn(move || {
                let p = std::path::Path::new(&path);
                let name = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "archivo".into());
                let r = match std::fs::metadata(p) {
                    Ok(m) if m.is_file() && m.len() <= FILE_MAX => std::fs::read(p).map_err(|e| e.to_string()),
                    Ok(m) if m.is_file() => Err("pasa de 20 MB".into()),
                    Ok(_) => Err("es una carpeta, no un archivo".into()),
                    Err(e) => Err(e.to_string()),
                };
                let (data, error) = match r {
                    Ok(d) => (d, String::new()),
                    Err(e) => (vec![], e),
                };
                let q = |s: &str| s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"._-~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect::<String>();
                let sent = crate::net::agent()
                    .post(&format!("{url}/api/agent/remote/upload"))
                    .timeout(Duration::from_secs(300))
                    .set("x-kitty", &ukey)
                    .set("x-sesion", &id)
                    .set("x-nombre", &q(&name))
                    .set("x-error", &q(&error))
                    .send_bytes(&data)
                    .is_ok();
                if error.is_empty() && sent {
                    note(format!("IT ha copiado {path}"));
                }
            });
        }
        _ => return false,
    }
    true
}

/// Descarga el archivo del técnico en la carpeta Descargas del usuario, sin pisar otro con el mismo nombre.
fn receive(url: &str, ukey: &str, id: &str, fid: u64, name: &str) -> Result<std::path::PathBuf, String> {
    let r = crate::net::agent()
        .post(&format!("{url}/api/agent/remote/file"))
        .timeout(Duration::from_secs(300))
        .set("Content-Type", "application/json; charset=utf-8")
        .send_string(&json!({"ukey": ukey, "sesion": id, "id": fid}).to_string())
        .map_err(|e| e.to_string())?;
    let mut data = Vec::new();
    r.into_reader().take(FILE_MAX + 1).read_to_end(&mut data).map_err(|e| e.to_string())?;
    let dir = std::env::var_os("USERPROFILE").map(|h| std::path::PathBuf::from(h).join("Downloads")).filter(|d| d.is_dir()).unwrap_or_else(std::env::temp_dir);
    let name: String = name.chars().filter(|c| !c.is_control() && !"<>:\"/\\|?*".contains(*c)).collect();
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (name.clone(), String::new()),
    };
    let mut p = dir.join(&name);
    for n in 1..1000 {
        if !p.exists() {
            break;
        }
        p = dir.join(format!("{stem} ({n}){ext}"));
    }
    std::fs::write(&p, data).map_err(|e| e.to_string())?;
    Ok(p)
}

fn run(mut ws: Ws, url: &str, ukey: &str, id: &str, stop: &Arc<AtomicBool>, held: &mut Held, note: Note) -> String {
    let (mut last, mut sent) = (0u64, Instant::now() - ALIVE);
    let lost = |e: tungstenite::Error| format!("Se perdió la conexión con catlan: {e}.");
    loop {
        if stop.load(Ordering::Relaxed) {
            let _ = crate::net::post(&format!("{url}/api/agent/remote/answer"), &json!({"ukey": ukey, "id": id, "ok": false}));
            let _ = ws.close(None);
            return "Has cortado la conexión.".into();
        }
        let t0 = Instant::now();
        // sin cambios en la pantalla no se envía nada (solo el latido)
        let jpg = capture()
            .map(|(px, w, h)| {
                let mut hs = DefaultHasher::new();
                px.hash(&mut hs);
                let hsh = hs.finish();
                if hsh == last {
                    vec![]
                } else {
                    last = hsh;
                    jpeg(&px, w, h)
                }
            })
            .unwrap_or_default(); // pantalla bloqueada o de UAC: Windows no deja verla
        if !jpg.is_empty() || sent.elapsed() >= ALIVE {
            if let Err(e) = ws.send(Message::Binary(jpg.into())) {
                return lost(e);
            }
            sent = Instant::now();
        }
        // lo que mande catlan (ratón, teclado, el final) hasta que toque el siguiente fotograma
        while t0.elapsed() < TICK {
            match ws.read() {
                Ok(Message::Text(t)) => {
                    let r: Value = serde_json::from_str(t.as_str()).unwrap_or_default();
                    if r.get("state").and_then(Value::as_str).is_some_and(|s| s != "aceptada") {
                        let w = r.get("why").and_then(Value::as_str).unwrap_or("");
                        return if w.is_empty() { "La sesión ha terminado.".into() } else { format!("La sesión ha terminado: {w}.") };
                    }
                    for e in r.get("input").and_then(Value::as_array).into_iter().flatten() {
                        if !file_event(e, url, ukey, id, &note) {
                            apply(e, held);
                        }
                    }
                }
                Ok(Message::Close(_)) => return "La sesión ha terminado.".into(),
                Ok(_) => {}
                Err(tungstenite::Error::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return lost(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direcciones() {
        assert_eq!(host_port("https://192.168.1.5:8080"), Some(("192.168.1.5".into(), 8080)));
        assert_eq!(host_port("https://it.local"), Some(("it.local".into(), 443)));
        assert_eq!(host_port("https://[fd00::5]:9000/x"), Some(("fd00::5".into(), 9000)));
        assert_eq!(host_port("http://catlan:8080"), None);
        assert_eq!(host_port("https://catlan:puerto"), None);
    }

    #[test]
    fn teclas() {
        assert_eq!(vk("KeyC"), Some((0x43, false)));
        assert_eq!(vk("Digit7"), Some((0x37, false)));
        assert_eq!(vk("F12"), Some((0x7B, false)));
        assert_eq!(vk("ArrowLeft"), Some((0x25, true)));
        assert_eq!(vk("IntlBackslash"), None);
    }

    #[test]
    fn captura_y_jpeg() {
        let Some((px, w, h)) = capture() else { return }; // sin escritorio (servicio de CI): nada que probar
        let j = jpeg(&px, w, h);
        assert!(w <= MAX_W && j.starts_with(&[0xFF, 0xD8]) && j.len() < px.len(), "{w}x{h} {}", j.len());
    }
}
