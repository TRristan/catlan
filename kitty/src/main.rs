//! Kitty: el gato de catlan en cada PC. `kitty enviar` (tarea programada, cada 5 minutos) cuenta a catlan cómo está el
//! equipo; sin argumentos, vive en la bandeja y abre una ventana para avisar a IT y ver el estado del PC.
#![cfg_attr(windows, windows_subsystem = "windows")] // la ventana, sin consola detrás

mod conf;
mod facts;
mod net;
#[cfg(windows)]
mod app;

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_default();
    match arg.as_str() {
        "enviar" => {
            let r = net::send();
            let when = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0).to_string();
            let (state, error) = match &r {
                Ok(s) => (s.as_str(), ""),
                Err(e) => ("error", e.as_str()),
            };
            conf::set("state", state);
            conf::set("error", error);
            conf::set("when", &when);
            std::process::exit(if r.is_ok() { 0 } else { 1 });
        }
        #[cfg(windows)]
        "" | "--oculto" => app::run(arg == "--oculto"),
        _ => {
            eprintln!("Uso: kitty [enviar | --oculto]");
            std::process::exit(2);
        }
    }
}
