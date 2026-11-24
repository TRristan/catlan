//! La ventana de Kitty: un icono en la bandeja y una página (ui.html, con el diseño de catlan) en un WebView2.
use crate::{conf, facts, net};
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
}

/// El gato de catlan en naranja, dibujado a mano (n x n píxeles RGBA, con suavizado).
fn icon(n: u32) -> Vec<u8> {
    let inside = |x: f32, y: f32| -> bool {
        let (cx, cy, r) = (0.5, 0.58, 0.36);
        let head = (x - cx).powi(2) + (y - cy).powi(2) <= r * r;
        let ear = |ax: f32, bx: f32| {
            // triángulo (ax, 0.42) – (bx, 0.42) – (punta, 0.08)
            let tip = if ax < 0.5 { 0.17 } else { 0.83 };
            let t = (0.42 - y) / (0.42 - 0.08);
            (0.0..=1.0).contains(&t) && x >= ax + (tip - ax) * t && x <= bx + (tip - bx) * t
        };
        let eye = |ex: f32| (x - ex).powi(2) + (y - 0.6).powi(2) <= 0.055f32.powi(2);
        (head || ear(0.15, 0.42) || ear(0.58, 0.85)) && !eye(0.37) && !eye(0.63)
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

pub fn run(start_hidden: bool) {
    let Some(_lock) = single_instance() else { return };
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

    let (open_id, quit_id) = (open.id().clone(), quit.id().clone());
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
            Event::UserEvent(Ev::Menu(e)) if e.id == quit_id => *flow = ControlFlow::Exit,
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
                    "mine" => {
                        if let Ok(c) = &conf {
                            ask(&proxy, "mine", format!("{}/api/agent/mine", c.url), json!({"ukey": c.ukey}));
                        }
                    }
                    "send" => {
                        if let Ok(c) = &conf {
                            let body = json!({"ukey": c.ukey, "title": m["title"], "body": m["body"], "priority": m["priority"]});
                            ask(&proxy, "sent", format!("{}/api/agent/incident", c.url), body);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    });
}
