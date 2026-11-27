//! Control remoto: Kitty pregunta a catlan si IT quiere conectarse y, solo si el usuario lo permite, le envía la pantalla
//! (JPEG, solo cuando cambia) y aplica el ratón y el teclado del técnico. Todo sale del PC hacia catlan: no abre puertos.
use serde_json::{Value, json};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
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
                1 => if down { MOUSEEVENTF_MIDDLEDOWN } else { MOUSEEVENTF_MIDDLEUP },
                2 => if down { MOUSEEVENTF_RIGHTDOWN } else { MOUSEEVENTF_RIGHTUP },
                _ => if down { MOUSEEVENTF_LEFTDOWN } else { MOUSEEVENTF_LEFTUP },
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

/// POST con el fotograma; la respuesta trae el estado y lo que ha hecho el técnico.
fn post_frame(url: &str, ukey: &str, id: &str, jpg: &[u8]) -> Result<Value, String> {
    let r = crate::net::agent()
        .post(&format!("{url}/api/agent/remote/frame"))
        .timeout(Duration::from_secs(15))
        .set("X-Kitty", ukey)
        .set("X-Sesion", id)
        .set("Content-Type", "image/jpeg")
        .send_bytes(jpg);
    match r {
        Ok(r) => r.into_string().ok().and_then(|s| serde_json::from_str(&s).ok()).ok_or_else(|| "respuesta rara de catlan".into()),
        Err(ureq::Error::Status(c, _)) => Err(format!("catlan respondió {c}")),
        Err(e) => Err(format!("sin conexión con catlan ({})", e.kind())),
    }
}

/// La sesión aceptada: pantalla hacia catlan y ratón y teclado de vuelta, hasta que alguien la corte.
/// Devuelve por qué acabó, para enseñárselo al usuario.
pub fn session(url: &str, ukey: &str, id: &str, stop: &Arc<AtomicBool>) -> String {
    let mut held = Held::default();
    let (mut last, mut fails) = (0u64, 0);
    let why = loop {
        if stop.load(Ordering::Relaxed) {
            let _ = crate::net::post(&format!("{url}/api/agent/remote/answer"), &json!({"ukey": ukey, "id": id, "ok": false}));
            break "Has cortado la conexión.".to_string();
        }
        let t0 = Instant::now();
        // sin cambios en la pantalla, se envía vacío: solo para recoger el ratón y el teclado
        let jpg = capture()
            .map(|(px, w, h)| {
                let mut hs = DefaultHasher::new();
                px.hash(&mut hs);
                let hsh = hs.finish();
                if hsh == last { vec![] } else { last = hsh; jpeg(&px, w, h) }
            })
            .unwrap_or_default(); // pantalla bloqueada o de UAC: Windows no deja verla
        match post_frame(url, ukey, id, &jpg) {
            Ok(r) => {
                fails = 0;
                if r.get("state").and_then(Value::as_str) != Some("aceptada") {
                    let w = r.get("why").and_then(Value::as_str).unwrap_or("");
                    break if w.is_empty() { "La sesión ha terminado.".into() } else { format!("La sesión ha terminado: {w}.") };
                }
                for e in r.get("input").and_then(Value::as_array).into_iter().flatten() {
                    apply(e, &mut held);
                }
            }
            Err(e) => {
                fails += 1;
                if fails >= 5 {
                    break format!("Se perdió la conexión con catlan: {e}.");
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        std::thread::sleep(TICK.saturating_sub(t0.elapsed()));
    };
    held.release();
    why
}

#[cfg(test)]
mod tests {
    use super::*;

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
