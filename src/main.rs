//! catlan: el gato amigo de los IT. Wiki + inventario + esquemas + racks + monitor, en un solo ejecutable.
mod config;
mod crypto;
mod db;
mod health;
mod monitor;
mod remote;
mod server;
mod snmp;
mod update;
mod util;
mod validate;
mod web;

use config::{DATA, PASSWORD, PORT, SYSLOG_PORT, VERSION, scheme};
use std::io::IsTerminal;

/// La primera página de la wiki en una instalación nueva: cómo se usa catlan y qué hace con los datos.
const GUIDE: &str = include_str!("guide.md");

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 4 && args[1] == "descifrar" {
        std::process::exit(decrypt(&args[2], &args[3])); // antes de abrir ninguna BD
    }
    let _ = rustls::crypto::ring::default_provider().install_default();
    if let Err(e) = start(&args) {
        eprintln!("{e:#}");
        std::process::exit(1);
    }
}

/// `catlan descifrar copia.catlan salida.db`: la contraseña se pide sin eco, o llega por una tubería.
fn decrypt(src: &str, dst: &str) -> i32 {
    let pw = if std::io::stdin().is_terminal() {
        rpassword::prompt_password("Contraseña de la copia: ").unwrap_or_default()
    } else {
        let mut l = String::new();
        let _ = std::io::stdin().read_line(&mut l);
        l.trim_end_matches(['\r', '\n']).to_string()
    };
    let out = std::fs::read(src).map_err(|e| e.to_string()).and_then(|b| crypto::unseal(&b, &pw).map_err(|e| e.0));
    match out.and_then(|d| std::fs::write(dst, d).map_err(|e| e.to_string())) {
        Ok(()) => {
            println!("Descifrada en {dst}");
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn start(args: &[String]) -> anyhow::Result<()> {
    if args.get(1).map(String::as_str) == Some("restablecer") {
        // nunca crea una BD: en otra carpeta saldría una nueva con su admin y la contraseña no valdría en el servidor de verdad
        if !DATA.join("catlan.db").is_file() {
            eprintln!(
                "No hay base de datos de catlan en {}.\nEjecútalo con la misma carpeta de datos que el servidor: la de junto a su ejecutable, o la de CATLAN_DATA.\n\
                 En PowerShell: $env:CATLAN_DATA=\"C:\\ruta\\a\\data\"; catlan restablecer usuario",
                DATA.display()
            );
            std::process::exit(1);
        }
        db::init()?; // no hace falta parar catlan: la BD admite a los dos (WAL)
        std::process::exit(web::reset_password(args.get(2).map_or("", String::as_str))?);
    }
    update::on_start();
    db::init()?;
    monitor::apply_alerts()?;
    if db::q("SELECT 1 FROM users", p![])?.is_empty() {
        // primera vez: admin / admin (o CATLAN_PASSWORD), a cambiar en el primer login
        let pw = if PASSWORD.is_empty() { "admin" } else { PASSWORD.as_str() };
        db::q("INSERT INTO users(name, hash, admin, must_change) VALUES('admin', ?, 1, ?)", p![crypto::pw_hash(pw, None), PASSWORD.is_empty()])?;
        println!("Usuario inicial: admin / {}", if PASSWORD.is_empty() { "admin (se pide cambiarla al entrar)" } else { "CATLAN_PASSWORD" });
        db::q("INSERT INTO pages(title, body) VALUES(?, ?)", p!["Guía de catlan", GUIDE])?; // guía de uso y de datos en la wiki
    }
    std::sync::LazyLock::force(&monitor::STARTED);
    // la IP de este equipo en la red (sin enviar nada): 0.0.0.0 no se puede abrir en el navegador
    let lan = std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|u| u.connect("10.255.255.255:1").and_then(|_| u.local_addr()))
        .map(|a| a.ip().to_string())
        .unwrap_or_default();
    let (s, p) = (scheme(), *PORT);
    let also = if lan.is_empty() || lan == "127.0.0.1" || lan == "0.0.0.0" { String::new() } else { format!(" y {s}://{lan}:{p}") };
    println!("catlan {VERSION} en {s}://localhost:{p}{also}  (datos en {})", DATA.display());
    monitor::start_monitor();
    std::thread::spawn(update::auto_loop);
    if *SYSLOG_PORT != 0 {
        std::thread::spawn(monitor::syslog_server);
    }
    // Ctrl+C o SIGTERM (docker stop): espera a la escritura en curso, no deja empezar otra y vuelca el WAL en catlan.db
    ctrlc::set_handler(|| {
        let c = util::lock(db::writer());
        let _ = c.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()));
        println!("catlan parado");
        std::process::exit(0);
    })?;
    server::serve(web::handle)
}
