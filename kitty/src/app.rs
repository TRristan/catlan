//! La ventana de Kitty: un icono en la bandeja y una página (ui.html, con el diseño de catlan) en un WebView2.
use crate::{conf, facts, net, remote};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use serde_json::{Value, json};
use std::time::Duration;
use tao::dpi::LogicalSize;
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::platform::windows::WindowBuilderExtWindows;
use tao::window::WindowBuilder;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};

const UI: &str = include_str!("ui.html");

enum Ev {
    Ipc(String),
    Js(String),
    Tray(TrayIconEvent),
    Menu(MenuEvent),
    /// IT pide conectarse: {id, who}
    Ask(Value),
    /// Control remoto en marcha (con quién) o terminado (por qué)
    Remote(Result<String, String>),
    /// Un administrador de catlan ha dado permiso para cerrar Kitty
    Quit,
}

/// El logo de Kitty en naranja (docs/logo/kitty/kit/kitty-symbol-small.svg): n x n píxeles RGBA, con suavizado.
fn icon(n: u32) -> Vec<u8> {
    let inside = |x: f32, y: f32| -> bool {
        let (x, y) = (x * 256.0, y * 256.0); // la misma rejilla de 256 que el SVG
        // la cabeza de catlan (orejas a 45°, mandíbula de radio 56) metida t unidades hacia dentro
        let head = |t: f32| {
            let e = t * std::f32::consts::SQRT_2;
            let top = (88.0 + t).min(x - 8.0 + e).min(248.0 - x + e);
            let jaw = |cx: f32| (x - cx).powi(2) + (y - 164.0).powi(2) <= (56.0 - t).powi(2);
            let bottom = y <= 164.0 || if x < 96.0 { jaw(96.0) } else if x > 160.0 { jaw(160.0) } else { y <= 220.0 - t };
            (40.0 + t..=216.0 - t).contains(&x) && y >= top && bottom
        };
        let eye = |cx: f32| (x - cx).powi(2) + (y - 154.0).powi(2) <= 18f32.powi(2);
        (head(0.0) && !head(30.0)) || eye(102.0) || eye(154.0)
    };
    let mut out = Vec::with_capacity((n * n * 4) as usize);
    for py in 0..n {
        for px in 0..n {
            let mut hits = 0;
            for sy in 0..4 {
                for sx in 0..4 {
                    if inside((px as f32 + (sx as f32 + 0.5) / 4.0) / n as f32, (py as f32 + (sy as f32 + 0.5) / 4.0) / n as f32) {
                        hits += 1;
                    }
                }
            }
            out.extend([0xe8, 0x77, 0x2e, (hits * 255 / 16) as u8]);
        }
    }
    out
}

/// Una sola Kitty por usuario: la segunda se cierra (el candado es un archivo abierto sin compartir).
fn single_instance() -> Option<std::fs::File> {
    use std::os::windows::fs::OpenOptionsExt;
    let d = std::path::PathBuf::from(std::env::var("LOCALAPPDATA").unwrap_or_else(|_| std::env::temp_dir().to_string_lossy().into())).join("Kitty");
    let _ = std::fs::create_dir_all(&d);
    std::fs::OpenOptions::new().write(true).create(true).truncate(true).share_mode(0).open(d.join("kitty.lock")).ok()
}

fn js_call(f: &str, v: &Value) -> String {
    format!("window.kitty && kitty.{f}({v})")
}

/// En otro hilo, para no congelar la ventana; el resultado vuelve como una llamada a la página.
fn ask(proxy: &EventLoopProxy<Ev>, f: &'static str, url: String, body: Value) {
    let p = proxy.clone();
    std::thread::spawn(move || {
        let (status, body) = net::post(&url, &body);
        let _ = p.send_event(Ev::Js(js_call(f, &json!({"status": status, "body": body}))));
    });
}

/// Instala Kitty en este PC con el instalador de ese catlan, como administrador (Windows pide permiso). Mismo instalador
/// que el comando de catlan: deja la clave, el servicio que envía el estado cada minuto y el gato al iniciar sesión, y abre la Kitty
/// instalada (cerrando esta). En catlan aparece en «Kitty pide entrar» hasta que IT lo acepta.
fn install(url: &str) -> Result<(), String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
    use windows_sys::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    let w = |s: &str| s.encode_utf16().chain([0]).collect::<Vec<u16>>();
    let log = conf::dir().join("instalar.log");
    let _ = std::fs::remove_file(&log);
    // url ya validada (sin comillas ni espacios). PowerShell va oculto: el fallo, a un archivo que esta ventana pueda leer
    let args = format!(
        "-NoProfile -ExecutionPolicy Bypass -Command \"try {{ irm '{url}/kitty.ps1' | iex }} catch {{ $d = Join-Path $env:ProgramData 'Kitty'; \
         New-Item -ItemType Directory -Force $d | Out-Null; $_.ToString() | Out-File -Encoding utf8 (Join-Path $d 'instalar.log'); exit 1 }}\""
    );
    let (verb, file, params) = (w("runas"), w("powershell.exe"), w(&args));
    let mut i: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    i.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    i.fMask = SEE_MASK_NOCLOSEPROCESS;
    i.lpVerb = verb.as_ptr();
    i.lpFile = file.as_ptr();
    i.lpParameters = params.as_ptr();
    i.nShow = 0; // SW_HIDE
    if unsafe { ShellExecuteExW(&mut i) } == 0 || i.hProcess.is_null() {
        return Err("Hace falta el permiso de administrador para instalar Kitty.".into());
    }
    let mut code = 1u32;
    unsafe {
        WaitForSingleObject(i.hProcess, INFINITE);
        GetExitCodeProcess(i.hProcess, &mut code);
        CloseHandle(i.hProcess);
    }
    if code == 0 {
        return Ok(());
    }
    let why = std::fs::read_to_string(&log).unwrap_or_default();
    let why = why.trim_start_matches('\u{feff}').trim();
    Err(if why.is_empty() { format!("La instalación ha fallado (código {code}).") } else { why.to_string() })
}

pub fn run(start_hidden: bool, updated: bool) {
    // recién actualizada: la anterior tarda un momento en cerrarse y soltar el candado
    let tries = if updated { 50 } else { 1 };
    let lock = (0..tries).find_map(|i| {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(200));
        }
        single_instance()
    });
    let Some(_lock) = lock else { return };
    let conf = conf::Conf::load();
    let el = EventLoopBuilder::<Ev>::with_user_event().build();
    let proxy = el.create_proxy();
    let win_icon = tao::window::Icon::from_rgba(icon(64), 64, 64).ok();
    let Ok(window) = WindowBuilder::new()
        .with_title("Kitty")
        .with_inner_size(LogicalSize::new(420.0, 660.0))
        .with_min_inner_size(LogicalSize::new(360.0, 520.0))
        .with_decorations(false)
        .with_undecorated_shadow(true)
        .with_visible(false) // se enseña cuando la página está lista: sin destello en blanco
        .with_window_icon(win_icon)
        .build(&el)
    else {
        return;
    };
    let p = proxy.clone();
    let Ok(webview) = wry::WebViewBuilder::new()
        .with_html(UI)
        .with_ipc_handler(move |r: wry::http::Request<String>| {
            let _ = p.send_event(Ev::Ipc(r.into_body()));
        })
        .build(&window)
    else {
        return;
    };

    let menu = Menu::new();
    let open = MenuItem::new("Avisar a IT…", true, None);
    let quit = MenuItem::new("Salir de Kitty", true, None);
    let _ = menu.append_items(&[&open, &PredefinedMenuItem::separator(), &quit]);
    let tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_menu_on_left_click(false)
        .with_tooltip(format!("Kitty · {}", facts::name()))
        .with_icon(tray_icon::Icon::from_rgba(icon(32), 32, 32).expect("icono"))
        .build();
    let p = proxy.clone();
    TrayIconEvent::set_event_handler(Some(move |e| {
        let _ = p.send_event(Ev::Tray(e));
    }));
    let p = proxy.clone();
    MenuEvent::set_event_handler(Some(move |e| {
        let _ = p.send_event(Ev::Menu(e));
    }));

    // cómo va el equipo, cada 2 s
    let p = proxy.clone();
    std::thread::spawn(move || {
        let mut sys = sysinfo::System::new();
        loop {
            if p.send_event(Ev::Js(js_call("stats", &facts::stats(&mut sys)))).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    });

    // ¿quiere IT conectarse? Cada 3 s, una pregunta corta (sin dejar conexiones abiertas en catlan); de paso, el latido
    // que dice a la ventana si llega a catlan
    if let Ok(c) = &conf {
        let (url, ukey, p) = (c.url.clone(), c.ukey.clone(), proxy.clone());
        std::thread::spawn(move || loop {
            let (code, r) = net::post(&format!("{url}/api/agent/remote"), &json!({"ukey": ukey}));
            if p.send_event(Ev::Js(js_call("conn", &json!({"status": code, "body": r})))).is_err() {
                break;
            }
            if r.get("id").is_some() && p.send_event(Ev::Ask(r)).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_secs(if code == 200 { 3 } else { 5 }));
        });
    }

    // ¿el servicio ha instalado un Kitty nuevo? Esta ventana se reabre con él
    if let Some(me) = crate::update::installed() {
        let p = proxy.clone();
        std::thread::spawn(move || {
            let mine = crate::update::sha256(&me);
            loop {
                std::thread::sleep(Duration::from_secs(60));
                let now = crate::update::sha256(&me);
                if now.is_some() && now != mine && std::process::Command::new(&me).arg("--actualizada").spawn().is_ok() {
                    let _ = p.send_event(Ev::Quit);
                    break;
                }
            }
        });
    }

    let (open_id, quit_id) = (open.id().clone(), quit.id().clone());
    let mut remote_stop: Option<Arc<AtomicBool>> = None;
    let mut shown_once = false;
    el.run(move |event, _, flow| {
        *flow = ControlFlow::Wait;
        let _keep = &tray;
        let show = |w: &tao::window::Window, wv: &wry::WebView| {
            w.set_visible(true);
            w.set_minimized(false);
            w.set_focus();
            let _ = wv.evaluate_script("window.kitty && kitty.shown()");
        };
        match event {
            Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => window.set_visible(false),
            Event::UserEvent(Ev::Js(js)) => {
                let _ = webview.evaluate_script(&js);
            }
            Event::UserEvent(Ev::Tray(TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. })) => show(&window, &webview),
            Event::UserEvent(Ev::Tray(TrayIconEvent::DoubleClick { .. })) => show(&window, &webview),
            Event::UserEvent(Ev::Menu(e)) if e.id == open_id => show(&window, &webview),
            // sin instalar, se cierra sin más; instalado, pide un administrador de catlan
            Event::UserEvent(Ev::Menu(e)) if e.id == quit_id && conf.is_err() => *flow = ControlFlow::Exit,
            Event::UserEvent(Ev::Menu(e)) if e.id == quit_id => {
                show(&window, &webview);
                let _ = webview.evaluate_script("kitty.askQuit()");
            }
            Event::UserEvent(Ev::Quit) => *flow = ControlFlow::Exit,
            Event::UserEvent(Ev::Ask(r)) => {
                show(&window, &webview);
                let _ = webview.evaluate_script(&js_call("remoteAsk", &r));
            }
            Event::UserEvent(Ev::Remote(r)) => {
                // mientras dure, también lo dice la bandeja
                let _ = tray.as_ref().map(|t| t.set_tooltip(Some(match &r {
                    Ok(who) => format!("Kitty · {who} (IT) está conectado"),
                    Err(_) => format!("Kitty · {}", facts::name()),
                })));
                let js = match r {
                    Ok(who) => js_call("remoteOn", &json!({"who": who})),
                    Err(why) => {
                        remote_stop = None;
                        js_call("remoteOff", &json!({"why": why}))
                    }
                };
                let _ = webview.evaluate_script(&js);
            }
            Event::UserEvent(Ev::Ipc(msg)) => {
                let m: Value = serde_json::from_str(&msg).unwrap_or_default();
                match m.get("op").and_then(Value::as_str).unwrap_or("") {
                    "ready" => {
                        let init = match &conf {
                            Ok(c) => json!({"name": facts::name(), "configured": true, "server": c.host()}),
                            Err(e) => json!({"name": facts::name(), "configured": false, "error": e}),
                        };
                        let _ = webview.evaluate_script(&js_call("init", &init));
                        if !shown_once && !start_hidden {
                            show(&window, &webview);
                        }
                        shown_once = true;
                    }
                    "drag" => {
                        let _ = window.drag_window();
                    }
                    "hide" => window.set_visible(false),
                    "min" => window.set_minimized(true),
                    "remote-answer" => {
                        let Ok(c) = &conf else { return };
                        let (url, ukey, p) = (c.url.clone(), c.ukey.clone(), proxy.clone());
                        let id = m["id"].as_str().unwrap_or("").to_string();
                        let ok = m["ok"].as_bool().unwrap_or(false);
                        let stop = Arc::new(AtomicBool::new(false));
                        if ok {
                            remote_stop = Some(stop.clone());
                        }
                        std::thread::spawn(move || {
                            let (_, r) = net::post(&format!("{url}/api/agent/remote/answer"), &json!({"ukey": ukey, "id": id, "ok": ok}));
                            if !ok {
                                return;
                            }
                            if r.get("state").and_then(Value::as_str) != Some("aceptada") {
                                let _ = p.send_event(Ev::Remote(Err("IT ya no estaba esperando: no se ha conectado nadie.".into())));
                                return;
                            }
                            let _ = p.send_event(Ev::Remote(Ok(r["who"].as_str().unwrap_or("IT").to_string())));
                            let why = remote::session(&url, &ukey, &id, &stop);
                            let _ = p.send_event(Ev::Remote(Err(why)));
                        });
                    }
                    "quit" => {
                        let Ok(c) = &conf else { return };
                        let (url, p) = (c.url.clone(), proxy.clone());
                        let body = json!({"ukey": c.ukey, "name": m["name"], "pass": m["pass"], "code": m["code"]});
                        std::thread::spawn(move || {
                            let (code, r) = net::post(&format!("{url}/api/agent/quit"), &body);
                            let _ = p.send_event(if code == 200 { Ev::Quit } else { Ev::Js(js_call("quitErr", &json!({"status": code, "body": r}))) });
                        });
                    }
                    "remote-stop" => {
                        if let Some(s) = &remote_stop {
                            s.store(true, Ordering::Relaxed);
                        }
                    }
                    "find" => {
                        let p = proxy.clone();
                        std::thread::spawn(move || {
                            let _ = p.send_event(Ev::Js(js_call("found", &json!({"url": net::find()}))));
                        });
                    }
                    "join" => {
                        let (p, typed) = (proxy.clone(), m["url"].as_str().unwrap_or("").to_string());
                        std::thread::spawn(move || {
                            let r = match net::normalize(&typed) {
                                None => Err("Esa dirección no es válida. Algo como http://catlan:8080".to_string()),
                                Some(u) if net::probe(&u).is_none() => Err(format!("No encuentro catlan en {u}.")),
                                Some(u) => install(&u),
                            };
                            match r {
                                Ok(()) => std::process::exit(0), // ya abre la Kitty instalada
                                Err(e) => {
                                    let _ = p.send_event(Ev::Js(js_call("joined", &json!({"error": e}))));
                                }
                            }
                        });
                    }
                    op @ ("mine" | "send") => match &conf {
                        Ok(c) if op == "mine" => ask(&proxy, "mine", format!("{}/api/agent/mine", c.url), json!({"ukey": c.ukey})),
                        Ok(c) => {
                            let body = json!({"ukey": c.ukey, "title": m["title"], "body": m["body"], "priority": m["priority"]});
                            ask(&proxy, "sent", format!("{}/api/agent/incident", c.url), body);
                        }
                        // sin instalar: la página tiene que saberlo, o el botón se queda esperando
                        Err(e) => {
                            let f = if op == "mine" { "mine" } else { "sent" };
                            let _ = webview.evaluate_script(&js_call(f, &json!({"status": 0, "body": {"error": e}})));
                        }
                    },
                    _ => {}
                }
            }
            _ => {}
        }
    });
}

#[cfg(test)]
mod tests {
    #[test]
    fn icon_es_el_logo() {
        let n = 64;
        let px = super::icon(n);
        let alpha = |x: u32, y: u32| px[((y * n + x) * 4 + 3) as usize];
        assert_eq!(px.len(), (n * n * 4) as usize);
        assert_eq!(alpha(32, 50), 255); // barbilla (contorno)
        assert_eq!(alpha(11, 14), 255); // oreja izquierda
        assert_eq!(alpha(32, 10), 0); // entre las orejas
        assert_eq!(alpha(32, 38), 0); // hueco de la cara, entre los ojos
        assert_eq!(alpha(25, 38), 255); // ojo izquierdo
        assert_eq!(alpha(38, 38), 255); // ojo derecho
        assert_eq!(alpha(2, 62), 0); // esquina
    }
}
