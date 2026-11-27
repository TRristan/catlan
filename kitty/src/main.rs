//! Kitty: el gato de catlan en cada PC. `kitty servicio` (tarea programada, como SYSTEM) cuenta a catlan cada minuto cómo
//! está el equipo; sin argumentos, vive en la bandeja y abre una ventana para avisar a IT y ver el estado del PC.
#![cfg_attr(windows, windows_subsystem = "windows")] // la ventana, sin consola detrás

#[cfg(windows)]
mod app;
mod apps;
mod conf;
mod facts;
mod net;
#[cfg(windows)]
mod remote;
mod update;

/// Un envío, con lo lento recién sacado o reaprovechado, y su resultado anotado para el instalador.
fn send(ps: &serde_json::Value, fresh: bool) -> bool {
    let r = net::send(ps, fresh);
    let when = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0).to_string();
    let (state, error) = match &r {
        Ok(s) => (s.as_str(), ""),
        Err(e) => ("error", e.as_str()),
    };
    conf::set("state", state);
    conf::set("error", error);
    conf::set("when", &when);
    r.is_ok()
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    match arg.as_str() {
        // un envío y fuera (la tarea de los Kitty instalados antes del servicio)
        "enviar" => std::process::exit(if send(&facts::slow(conf::get("since").as_deref()), true) { 0 } else { 1 }),
        // la tarea programada (SYSTEM, al arrancar): se queda en marcha y envía cada minuto; PowerShell solo cada 5
        "servicio" => {
            use std::time::{Duration, Instant};
            let mut slow: Option<(Instant, serde_json::Value)> = None;
            apps::start();
            loop {
                let t0 = Instant::now();
                let fresh = slow.as_ref().is_none_or(|(at, _)| at.elapsed() >= net::SLOW_EVERY);
                if fresh {
                    slow = Some((t0, facts::slow(conf::get("since").as_deref())));
                }
                let ok = send(&slow.as_ref().expect("recién puesto").1, fresh);
                if fresh && !ok {
                    slow = None; // los eventos no llegaron: el próximo envío los vuelve a sacar
                }
                // cada 5 minutos, ¿hay un Kitty nuevo en catlan? Si se instala, sale: la tarea programada lanza el nuevo
                if fresh && conf::Conf::load().is_ok_and(|c| update::check(&c.url).unwrap_or(false)) {
                    std::process::exit(0);
                }
                std::thread::sleep(net::EVERY.saturating_sub(t0.elapsed()).max(Duration::from_secs(5)));
            }
        }
        #[cfg(windows)]
        // --actualizada: la reabre la Kitty anterior tras actualizarse (oculta, esperando a que la otra suelte la bandeja)
        "" | "--oculto" | "--actualizada" => app::run(!arg.is_empty(), arg == "--actualizada"),
        _ => {
            eprintln!("Uso: kitty [servicio | enviar | --oculto]");
            std::process::exit(2);
        }
    }
}
