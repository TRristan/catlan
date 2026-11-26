//! La API y la página: sesiones, permisos, CRUD con historial y todo lo demás. Misma API que la versión en Python.
use crate::config::{CERT, COOKIE, DATA, scheme};
use crate::crypto::{pw_hash, pw_ok, seal, sha256_hex, token_hex, token_urlsafe, totp_ok};
use crate::db::{self, SqlV, is_constraint, q, val};
use crate::health;
use crate::monitor::{self, SECRET, SOURCES};
use crate::remote;
use crate::server::{Req, Resp};
use crate::util::{Bad, J, Row, Shape, bad, is_int, lock, now, obj, parse_qs, py_str, trunc, truthy};
use crate::validate::*;
use crate::{p, re};
use anyhow::Result;
use flate2::{Compression, write::GzEncoder};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::sync::{LazyLock, Mutex};

const IMAGE_TYPES: &[&str] = &["image/png", "image/jpeg", "image/gif", "image/webp", "image/svg+xml"];
const AUDIO_TYPES: &[&str] =
    &["audio/mpeg", "audio/wav", "audio/x-wav", "audio/wave", "audio/ogg", "audio/webm", "audio/mp4", "audio/aac", "audio/x-m4a"];
/// Lo que Kitty cuenta de su equipo.
const AGENT_FACTS: [&str; 5] = ["name", "ip", "serial", "os", "kind"];
/// Lo que se vacía al «Borrar la base de datos»: todo el contenido. Quedan los usuarios, los grupos, las sesiones y el id
/// de la instalación (los Kitty instalados vuelven a pedir entrar aquí).
const WIPE: &[&str] = &[
    "pages", "items", "maps", "log", "checks", "pings", "pings_h", "sounds", "sources", "metrics", "metrics_h", "dash", "incidents", "notes", "agents",
    "expiries", "syslog", "subnets", "tasks", "apps",
];
/// Columnas del tablero personal.
const TASK_COLS: [&str; 4] = ["notas", "pendiente", "hoy", "hecho"];
const INC_COLS: [&str; 8] = ["title", "body", "status", "priority", "assignee", "grp", "item", "parent"];
const DONE: [&str; 2] = ["resuelta", "cerrada"];
const INC: &str = "SELECT n.*, u.name AS assignee_name, g.name AS grp_name, i.name AS item_name, a.name AS author_name, \
    (SELECT count(*) FROM notes WHERE incident = n.id AND change = 0) AS notes, p.title AS parent_title, \
    (SELECT count(*) FROM incidents h WHERE h.parent = n.id) AS children FROM incidents n LEFT JOIN incidents p ON p.id = n.parent \
    LEFT JOIN users u ON u.id = n.assignee \
    LEFT JOIN groups g ON g.id = n.grp LEFT JOIN items i ON i.id = n.item LEFT JOIN users a ON a.id = n.author";

/// Columnas editables por tabla: lista blanca contra inyección SQL.
fn table_cols(t: &str) -> Option<&'static [&'static str]> {
    Some(match t {
        "pages" => &["title", "body"],
        "items" => &["name", "kind", "ip", "serial", "location", "status", "notes", "warranty"],
        "checks" => &["host", "label", "item", "every", "kind", "port", "url", "expect", "warn_days", "sound"],
        "sources" => &[
            "host", "label", "item", "kind", "community", "port", "user", "pass", "every", "temp_max", "disk_max", "v3", "auth", "priv", "priv_pass",
        ],
        "expiries" => &["name", "kind", "date", "item", "notes"],
        "subnets" => &["name", "cidr", "vlan", "notes"],
        "apps" => &["name", "winget", "notes"],
        _ => return None,
    })
}

fn kind_of(t: &str) -> &'static str {
    match t {
        "pages" => "page",
        "items" => "item",
        "checks" => "check",
        "sources" => "source",
        "expiries" => "expiry",
        "apps" => "app",
        _ => "subnet",
    }
}

fn undo_table(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "page" => "pages",
        "item" => "items",
        "check" => "checks",
        "expiry" => "expiries",
        "subnet" => "subnets",
        "app" => "apps",
        "map" | "rack" => "maps",
        _ => return None,
    })
}

/// index.html en memoria y comprimido una sola vez.
struct Page {
    raw: &'static [u8],
    gz: Vec<u8>,
    etag: String,
}
static PAGE: LazyLock<Page> = LazyLock::new(|| {
    let raw: &'static [u8] = include_bytes!("index.html");
    let mut e = GzEncoder::new(vec![], Compression::best());
    let _ = e.write_all(raw);
    Page { raw, gz: e.finish().unwrap_or_default(), etag: format!("\"{}\"", &crate::crypto::hex(&<sha2::Sha256 as sha2::Digest>::digest(raw))[..20]) }
});
const KITTY_PS1: &str = include_str!("../kitty/kitty.ps1");
const KITTY_SH: &str = include_str!("../kitty/kitty.sh");

fn js(code: u16, v: impl serde::Serialize) -> Resp {
    Resp::new(code, serde_json::to_vec(&v).unwrap_or_default(), "application/json")
}

fn err(code: u16, msg: &str) -> Resp {
    js(code, json!({"error": msg}))
}

fn no_content() -> Resp {
    Resp::new(204, vec![], "application/json")
}

/// El programa de Kitty para Windows: junto al ejecutable de catlan o en la carpeta de datos (Docker).
fn kitty_exe() -> Option<std::path::PathBuf> {
    [crate::config::HERE.join("kitty.exe"), DATA.join("kitty.exe")].into_iter().find(|p| p.is_file())
}

/// sha256 de kitty.exe, recalculado solo si cambia el archivo (cientos de Kitty lo preguntan). "" si no hay.
fn kitty_hash() -> String {
    static CACHE: LazyLock<Mutex<(Option<(std::path::PathBuf, std::time::SystemTime, u64)>, String)>> = LazyLock::new(Default::default);
    let Some(p) = kitty_exe() else { return String::new() };
    let Ok(md) = std::fs::metadata(&p) else { return String::new() };
    let id = Some((p.clone(), md.modified().unwrap_or(std::time::UNIX_EPOCH), md.len()));
    let mut c = lock(&CACHE);
    if c.0 != id {
        let h = std::fs::read(&p).map(|b| crate::crypto::hex(&<sha2::Sha256 as sha2::Digest>::digest(&b))).unwrap_or_default();
        *c = (id, h);
    }
    c.1.clone()
}

/// Fallos de login recientes por IP: 10 en 15 minutos y esa IP espera.
static FAILS: LazyLock<Mutex<HashMap<String, Vec<f64>>>> = LazyLock::new(Default::default);
/// (nombre, sha256 de la contraseña) -> (id, hash): con Basic no se repite PBKDF2 en cada petición.
static BASIC: LazyLock<Mutex<HashMap<(String, String), (i64, String)>>> = LazyLock::new(Default::default);

fn throttled(ip: &str) -> bool {
    let mut f = lock(&FAILS);
    let v = f.entry(ip.to_string()).or_default();
    let t = now() - 900.0;
    v.retain(|x| *x > t);
    v.len() >= 10
}

fn failed(ip: &str) {
    lock(&FAILS).entry(ip.to_string()).or_default().push(now());
}

enum Login {
    No,
    NeedCode,
    Ok(i64),
}

/// Por Basic no hay código: quien tiene 2FA no entra por Basic (para scripts, un usuario sin 2FA).
fn login_ok(name: &str, pw: &str, code: &str) -> Result<Login> {
    let key = (name.to_lowercase(), sha256_hex(pw));
    let Some(u) = q("SELECT id, hash, totp FROM users WHERE name=?", p![name])?.one() else { return Ok(Login::No) };
    let (id, hash, totp) = (u.i("id").unwrap_or(0), u.s("hash").to_string(), u.s("totp").to_string());
    let code_ok = || if totp_ok(&totp, code) { Login::Ok(id) } else { Login::NeedCode };
    // La caché solo vale si el hash guardado sigue siendo el mismo: otro proceso (catlan restablecer) puede haberlo cambiado
    let cached = lock(&BASIC).get(&key) == Some(&(id, hash.clone()));
    if !cached {
        lock(&BASIC).remove(&key);
        if !pw_ok(pw, &hash) {
            return Ok(Login::No);
        }
        if !totp.is_empty() {
            return Ok(code_ok()); // sin caché: cada vez, su código
        }
        lock(&BASIC).insert(key, (id, hash));
    } else if !totp.is_empty() {
        // activó la 2FA en otro proceso después de entrar por aquí
        lock(&BASIC).remove(&key);
        return Ok(code_ok());
    }
    Ok(Login::Ok(id))
}

/// Solo vista: está en algún grupo de solo vista y en ninguno que pueda editar (los administradores siempre editan).
fn readonly(uid: i64) -> Result<bool> {
    let r = q(
        "SELECT u.admin, max(g.role = 'edit') AS e, max(g.role = 'view') AS v FROM users u LEFT JOIN members m ON m.user_id = u.id \
         LEFT JOIN groups g ON g.id = m.group_id WHERE u.id=?",
        p![uid],
    )?
    .one()
    .unwrap_or_default();
    Ok(!r.t("admin") && r.t("v") && !r.t("e"))
}

fn me(uid: i64) -> Result<Value> {
    let mut u = q("SELECT id, name, admin, must_change, totp != '' AS totp FROM users WHERE id=?", p![uid])?.one().unwrap_or_default();
    u.insert("readonly".into(), readonly(uid)?.into());
    u.insert("groups".into(), q("SELECT group_id FROM members WHERE user_id=?", p![uid])?.into_iter().map(|r| r["group_id"].clone()).collect::<Vec<_>>().into());
    Ok(u.into())
}

/// Sin los secretos: nunca salen por la API ni al historial.
fn public(mut r: Row) -> Row {
    for k in SECRET {
        r.shift_remove(k);
    }
    r
}

fn netloc(url: &str) -> &str {
    url.split_once("://").map(|(_, r)| r.split(['/', '?', '#']).next().unwrap_or("")).unwrap_or("")
}

fn cookie<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').filter_map(|c| c.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v.trim_matches('"'))
}

pub fn handle(req: &Req) -> Resp {
    let mut c = Ctx { req, uid: None, user: String::new(), admin: false, token: String::new() };
    c.route()
}

struct Ctx<'a> {
    req: &'a Req,
    uid: Option<i64>,
    user: String,
    admin: bool,
    token: String,
}

impl Ctx<'_> {
    fn body(&self) -> Result<Value> {
        if self.req.body.is_empty() { Ok(json!({})) } else { Ok(serde_json::from_slice(&self.req.body)?) }
    }

    fn uid(&self) -> i64 {
        self.uid.unwrap_or(0)
    }

    fn log(&self, action: &str, kind: &str, r: impl db::IntoSql, name: impl db::IntoSql, data: &Value) -> Result<()> {
        let r = r.sql();
        let snap = data.to_string();
        let last = q(
            "SELECT id, action, who, ts > datetime('now', '-60 seconds') AS fresh FROM log WHERE kind=? AND ref=? ORDER BY id DESC LIMIT 1",
            p![kind, r.clone()],
        )?
        .one();
        // esquemas y racks se autoguardan al arrastrar: agrupa ediciones seguidas en una sola entrada
        if let Some(l) = last.filter(|l| ["map", "rack"].contains(&kind) && action == "editar" && l.s("action") == "editar" && l.s("who") == self.user && l.t("fresh")) {
            q("UPDATE log SET ts=CURRENT_TIMESTAMP, name=?, data=? WHERE id=?", p![name, snap, &l["id"]])?;
        } else {
            q("INSERT INTO log(who, action, kind, ref, name, data) VALUES(?,?,?,?,?,?)", p![&self.user, action, kind, r, name, snap])?;
        }
        Ok(())
    }

    /// Sesión por cookie (navegador) o Basic (scripts). Sin WWW-Authenticate: el login es la página de catlan.
    fn authed(&mut self, free: bool, pending: bool) -> Result<Option<Resp>> {
        let ip = self.req.ip.clone();
        let h = self.req.header("authorization");
        let u = if let Some(v) = cookie(self.req.header("cookie"), &COOKIE).filter(|v| !v.is_empty()) {
            self.token = sha256_hex(v);
            q("SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token=? AND s.expires > datetime('now')", p![&self.token])?.one()
        } else if let (Some(b64), false) = (h.strip_prefix("Basic "), throttled(&ip)) {
            let decoded = data_encoding::BASE64.decode(b64.trim().as_bytes()).ok().and_then(|b| String::from_utf8(b).ok());
            let uid = match decoded.as_deref().and_then(|s| s.split_once(':')) {
                Some((n, pw)) => match login_ok(&trunc(n, 100), &trunc(pw, 200), "")? {
                    Login::Ok(id) => Some(id),
                    _ => None,
                },
                None => None,
            };
            if uid.is_none() {
                failed(&ip);
            }
            match uid {
                Some(id) => q("SELECT * FROM users WHERE id=?", p![id])?.one(),
                None => None,
            }
        } else {
            None
        };
        let must = u.as_ref().is_some_and(|u| u.t("must_change"));
        if let Some(u) = &u {
            self.uid = u.i("id");
            self.user = u.s("name").to_string();
            self.admin = u.t("admin");
        }
        if free || u.is_some() && (!must || pending) {
            return Ok(None);
        }
        if u.is_some() {
            // contraseña provisional (admin/admin incluido): solo se puede cambiarla o salir
            return Ok(Some(js(403, json!({"error": "cambia tu contraseña para continuar", "must_change": true}))));
        }
        Ok(Some(err(401, "inicia sesión")))
    }

    fn route(&mut self) -> Resp {
        let m = self.req.method.clone();
        // Escrituras desde otra web (CSRF): el navegador pone Origin; si no es este servidor, fuera.
        // Detrás de un proxy, este debe conservar la cabecera Host original.
        if let Some(o) = self.req.opt_header("origin") {
            if m != "GET" && netloc(o) != self.req.header("host") {
                return err(403, "origen no permitido");
            }
        }
        let full = self.req.path.split('#').next().unwrap_or("").to_string();
        let (path, query) = full.split_once('?').unwrap_or((&full, ""));
        let parts: Vec<String> = path.split('/').filter(|p| !p.is_empty()).map(String::from).collect();
        let api = parts.first().is_some_and(|p| p == "api");
        let rest: Vec<&str> = parts.iter().skip(1).map(String::as_str).collect();
        let free = !api || m == "POST" && (rest == ["login"] || rest.first() == Some(&"agent") && (rest.len() <= 2 || rest.get(1) == Some(&"remote"))); // la página, el login y Kitty, sin sesión
        let own = api && rest.first() == Some(&"tasks"); // el tablero personal no toca nada común: también para los de solo vista
        let pending = api && (rest.first() == Some(&"logout") || [&["me"][..], &["me", "password"]].contains(&&rest[..rest.len().min(2)])); // con contraseña provisional
        let r = (|| -> Result<Resp> {
            if let Some(r) = self.authed(free, pending)? {
                return Ok(r);
            }
            if m != "GET" && !free && !pending && !own && self.uid.is_some() && readonly(self.uid())? {
                return Ok(err(403, "tu usuario es de solo vista"));
            }
            self.dispatch(&m, &parts, query)
        })();
        r.unwrap_or_else(|e| {
            if let Some(b) = e.downcast_ref::<Bad>() {
                err(400, &b.0)
            } else if let Some(j) = e.downcast_ref::<serde_json::Error>() {
                err(400, &j.to_string())
            } else if e.downcast_ref::<Shape>().is_some() {
                println!("400 por datos raros en {}", self.req.path);
                err(400, &Shape.to_string())
            } else {
                eprintln!("500 en {} {}: {e:#}", m, self.req.path);
                err(500, &format!("error interno: {e}"))
            }
        })
    }

    fn dispatch(&mut self, m: &str, parts: &[String], query: &str) -> Result<Resp> {
        let at = |i: usize| parts.get(i).map(String::as_str);
        if parts == ["kitty.exe"] && m == "GET" {
            return Ok(match kitty_exe().map(std::fs::read) {
                Some(Ok(b)) => Resp::new(200, b, "application/vnd.microsoft.portable-executable").header("Content-Disposition", "attachment; filename=\"kitty.exe\""),
                _ => Resp::new(404, "catlan no tiene kitty.exe: ponlo junto al ejecutable de catlan o en su carpeta de datos".as_bytes().to_vec(), "text/plain; charset=utf-8"),
            });
        }
        if parts == ["kitty.json"] && m == "GET" {
            // Kitty sin instalar busca catlan en la red: así sabe que aquí hay uno (sin sesión, solo el id público).
            // «kitty»: el sha256 del kitty.exe que reparte; las Kitty instaladas con otro se actualizan solas
            return Ok(js(200, json!({"catlan": db::INSTANCE.get().map_or("", |s| s.as_str()), "kitty": kitty_hash()})));
        }
        if (parts == ["kitty.ps1"] || parts == ["kitty.sh"]) && m == "GET" {
            // instalador de Kitty (Windows o Linux) con esta dirección y este id, sin sesión
            let host = self.req.header("host");
            if !host_ok(host) {
                return Ok(Resp::new(400, b"Host no valido".to_vec(), "text/plain; charset=utf-8")); // va dentro de un script que se ejecuta como administrador
            }
            let ps = if parts[0] == "kitty.sh" { KITTY_SH.replace("\r\n", "\n") } else { KITTY_PS1.to_string() }; // un clon de Git en Windows lo deja con CRLF
            let ps = ps.replace("{{URL}}", &format!("{}://{host}", scheme())).replace("{{ID}}", db::INSTANCE.get().map_or("", |s| s.as_str()));
            return Ok(Resp::new(200, ps.into_bytes(), "text/plain; charset=utf-8"));
        }
        if at(0) != Some("api") {
            let pg = &*PAGE;
            if self.req.header("if-none-match") == pg.etag {
                // ya la tiene: 304 sin cuerpo
                return Ok(Resp { code: 304, headers: vec![], body: vec![] }.header("Cache-Control", "no-cache").header("Vary", "Accept-Encoding").header("ETag", &pg.etag));
            }
            let gz = self.req.header("accept-encoding").contains("gzip");
            let mut r = Resp::new(200, if gz { pg.gz.clone() } else { pg.raw.to_vec() }, "text/html; charset=utf-8")
                .header("Cache-Control", "no-cache")
                .header("Vary", "Accept-Encoding")
                .header("ETag", &pg.etag);
            if gz {
                r = r.header("Content-Encoding", "gzip");
            }
            return Ok(r);
        }
        let res = at(1).unwrap_or("");
        let rid = at(2);
        let rid_i = rid.and_then(|r| r.parse::<i64>().ok()).unwrap_or(-1);
        let qs = parse_qs(query);
        let sub = at(3);
        match (res, m) {
            ("login" | "logout" | "me" | "users", _) => return self.account(m, res, rid),
            ("backup", "GET" | "POST") => return self.backup(m),
            ("alerts", _) => return self.alerts(m),
            ("wipe", "POST") => return self.wipe(),
            ("agent", "POST") => {
                return match rid {
                    None => self.agent_hello(),
                    Some("incident") => self.agent_incident(),
                    Some("mine") => self.agent_mine(),
                    Some("quit") => self.agent_quit(),
                    Some("remote") => self.agent_remote(sub),
                    Some(_) => Ok(err(404, "no existe")),
                };
            }
            ("agents", _) => return self.agents(m, rid_i, rid.is_none()),
            ("remote", _) => return self.remote(m, rid, sub, &qs),
            ("groups", _) => return self.groups(m, rid, rid_i),
            ("incidents", _) => return self.incidents(m, rid, rid_i, parts),
            ("tasks", _) => return self.tasks(m, rid, rid_i),
            ("maps", _) => return self.maps(m, rid, rid_i, sub, &qs),
            ("log", "GET") => {
                let (w, a) = match (qs.get("kind"), qs.get("ref")) {
                    (Some(k), Some(r)) => {
                        let Ok(r) = r[0].parse::<i64>() else { return bad("ref no válido") };
                        ("WHERE kind=? AND ref=?", p![&k[0], r])
                    }
                    _ => ("", p![]),
                };
                return Ok(js(200, q(&format!("SELECT * FROM log {w} ORDER BY id DESC LIMIT 300"), a)?.rows));
            }
            ("items", "GET") if sub == Some("refs") => return Ok(js(200, refs(rid.unwrap_or("").parse().map_err(|_| Bad("id no válido".into()))?)?)),
            ("items", "GET") if sub == Some("syslog") => {
                return Ok(js(200, q("SELECT ts, ip, sev, msg FROM syslog WHERE item=? ORDER BY rowid DESC LIMIT 200", p![rid_i])?.rows));
            }
            ("subnets", _) if rid.is_some() && matches!(sub, Some("ips" | "scan")) => {
                let Some(mut row) = q("SELECT * FROM subnets WHERE id=?", p![rid_i])?.one() else { return Ok(err(404, "no existe")) };
                if sub == Some("scan") && m == "POST" {
                    // ping, DNS y SNMP (public), como «Descubrir red»
                    let Ok(net) = monitor::parse_net(row.s("cidr")) else { return bad("red no válida") };
                    if net.num_addresses() > 1024 {
                        return bad("se escanean redes de hasta 1024 direcciones (/22): divide esta en subredes");
                    }
                    let hosts: Vec<String> = net.hosts().map(|h| std::net::Ipv4Addr::from(h).to_string()).collect();
                    let found: Vec<Value> = health::discover(&hosts, "public")?.into_iter().map(|f| json!({"ip": f["ip"], "name": f["name"]})).collect();
                    q("UPDATE subnets SET scan=?, scanned=CURRENT_TIMESTAMP WHERE id=?", p![json!(found).to_string(), &row["id"]])?;
                    let name = if row.s("name").is_empty() { row.s("cidr") } else { row.s("name") }.to_string();
                    self.log("escanear", "subnet", &row["id"], name, &json!({"responden": found.len()}))?;
                    row = q("SELECT * FROM subnets WHERE id=?", p![&row["id"]])?.one().unwrap_or_default();
                } else if m != "GET" {
                    return Ok(err(405, "método no permitido"));
                }
                return Ok(js(200, monitor::ipam(&row)?));
            }
            ("monitor", "GET") if rid.is_none() => return Ok(js(200, monitor::monitor_state()?)),
            ("monitor", "POST") if rid == Some("test") => {
                if monitor::channels().is_empty() {
                    return Ok(err(400, "ningún canal de aviso configurado: hazlo en Opciones → Avisos"));
                }
                return Ok(js(200, monitor::notify("catlan: aviso de prueba", "Si lees esto, los avisos de catlan llegan por aquí.\n\n-- catlan")));
            }
            ("checks" | "sources", "POST") if sub == Some("mute") => {
                let b = self.body()?;
                let mins = if truthy(&b) { obj(&b)?.get("minutes").cloned().unwrap_or(Value::Null) } else { Value::Null };
                if !(is_int(&mins) && mins.as_i64().is_some_and(|x| (0..=10080).contains(&x))) {
                    return bad("silenciar de 0 minutos a 7 días");
                }
                let mins = mins.as_i64().unwrap_or(0);
                let cur = q(
                    &format!("UPDATE {res} SET mute_from=NULL, mute_until = CASE WHEN ? > 0 THEN datetime('now', '+' || ? || ' minutes') END WHERE id=?"),
                    p![mins, mins, rid_i],
                )?;
                if cur.rowcount == 0 {
                    return Ok(err(404, "no existe"));
                }
                let row = q(&format!("SELECT id, label, host, mute_until FROM {res} WHERE id=?"), p![rid_i])?.one().unwrap_or_default();
                let name = if row.s("label").is_empty() { row.s("host") } else { row.s("label") }.to_string();
                self.log(if mins > 0 { "silenciar" } else { "quitar silencio" }, kind_of(res), &row["id"], name, &json!({"minutes": mins}))?;
                return Ok(js(200, row));
            }
            ("maintenance", "POST") => return self.maintenance(),
            ("log", "POST") if rid.is_some() && parts.len() == 4 && sub == Some("undo") => {
                return self.undo(rid.unwrap_or("").parse().map_err(|_| Bad("id no válido".into()))?);
            }
            ("update", _) => {
                // actualizar catlan desde GitHub: solo administradores
                if !self.admin {
                    return Ok(err(403, "solo para administradores"));
                }
                return Ok(match (m, rid) {
                    ("GET", None) => js(200, crate::update::status()),
                    ("PUT", None) => {
                        let on = self.body()?.get("auto").and_then(Value::as_bool).ok_or(Bad("auto: true o false".into()))?;
                        crate::update::set_auto(on)?;
                        self.log(if on { "activar" } else { "desactivar" }, "update", 0, "Actualizar solo", &json!({}))?;
                        js(200, crate::update::status())
                    }
                    ("POST", Some("check")) => match crate::update::check() {
                        Ok(v) => js(200, v["info"].clone()),
                        Err(e) => err(502, &format!("no he podido preguntar a GitHub: {e}")),
                    },
                    ("POST", Some("apply")) => match crate::update::apply() {
                        Ok(v) => {
                            self.log("actualizar", "update", 0, format!("catlan {v}"), &json!({"antes": crate::update::CURRENT}))?;
                            // la respuesta sale antes de reiniciar
                            std::thread::spawn(|| {
                                std::thread::sleep(std::time::Duration::from_secs(1));
                                crate::update::restart();
                            });
                            js(200, json!({"version": v}))
                        }
                        Err(e) => err(400, &e.to_string()),
                    },
                    _ => err(404, "no existe"),
                });
            }
            ("system", "GET") => {
                // la salud del propio catlan
                if !self.admin {
                    return Ok(err(403, "solo para administradores"));
                }
                return Ok(js(200, monitor::system_health()?));
            }
            ("ping", "POST") => {
                let b = self.body()?;
                let mut d = Row::new();
                d.insert("host".into(), b.as_object().and_then(|o| o.get("host")).cloned().unwrap_or(Value::Null));
                check_host(&d, true)?;
                let (up, rtt) = monitor::ping(d.s("host"));
                return Ok(js(200, json!({"up": up, "rtt": rtt})));
            }
            ("sounds", _) => return self.sounds(m, rid, rid_i, sub, &qs),
            ("dashboard", "GET") => {
                let d = val("SELECT data FROM dash WHERE id=1", p![])?;
                // null: el frontal pone uno por defecto
                return Ok(js(200, d.as_str().and_then(|s| serde_json::from_str::<Value>(s).ok()).unwrap_or(Value::Null)));
            }
            ("dashboard", "PUT") => {
                let d = self.body()?;
                check_dash(&d)?;
                q("INSERT OR REPLACE INTO dash(id, data) VALUES(1, ?)", p![d.to_string()])?;
                return Ok(no_content());
            }
            ("discover", "POST") => {
                let b = self.body()?;
                let b = obj(&b)?;
                let s = b.get("net").map(py_str).unwrap_or_default();
                let net = match monitor::parse_net(s.trim()) {
                    Ok(n) if n.num_addresses() <= 1024 => n,
                    Ok(_) | Err(monitor::NetErr::V6) => return bad("solo redes IPv4 de hasta 1024 direcciones (/22)"),
                    Err(monitor::NetErr::Bad) => return bad("red no válida: escribe algo como 10.0.0.0/24"),
                };
                let community = match b.get("community").filter(|v| truthy(v)) {
                    None => "public".to_string(),
                    Some(Value::String(s)) if s.chars().count() <= 100 => s.clone(),
                    Some(_) => return bad("comunidad no válida"),
                };
                let hosts: Vec<String> = net.hosts().map(|h| std::net::Ipv4Addr::from(h).to_string()).collect();
                return Ok(js(200, health::discover(&hosts, &community)?));
            }
            ("latency", "GET") => return Ok(js(200, monitor::latency(hours(&qs)?)?)),
            ("sla", "GET") => {
                let month = qs.get("month").map(|v| v[0].clone()).unwrap_or_else(|| crate::util::local("%Y-%m"));
                return Ok(js(200, monitor::sla(&month)?));
            }
            ("health", "GET") => return Ok(js(200, monitor::health()?)),
            ("metrics", "GET") => {
                let source = qs.get("source").map(|v| v[0].as_str()).unwrap_or("0").parse::<i64>().map_err(|_| Bad("fuente no válida".into()))?;
                return Ok(js(200, monitor::series(source, hours(&qs)?)?));
            }
            ("sources", "POST") if sub == Some("topology") => {
                let src = q("SELECT * FROM sources WHERE id=?", p![rid_i])?.one();
                let Some(src) = src.filter(|s| !["kitty", "hikvision"].contains(&s.s("kind"))) else {
                    return Ok(if q("SELECT 1 FROM sources WHERE id=?", p![rid_i])?.is_empty() {
                        err(404, "no existe")
                    } else {
                        err(400, "solo los equipos que se leen por SNMP")
                    });
                };
                let (mid, name, nbrs, new) = match health::auto_map(&src) {
                    Ok(x) => x,
                    Err(e) => return Ok(err(400, &e.to_string())),
                };
                if nbrs.is_empty() {
                    return Ok(err(
                        400,
                        "el equipo no ha contado ningún vecino: activa LLDP o CDP en el switch y comprueba que SNMP deja leer las tablas BRIDGE/LLDP",
                    ));
                }
                self.log(if new { "crear" } else { "editar" }, "map", mid, &name, &json!({"auto": true, "vecinos": nbrs.len()}))?;
                return Ok(js(200, json!({"map": mid, "name": name, "neighbors": nbrs})));
            }
            ("sources", "POST") if rid == Some("test") => {
                // probar sin guardar
                let b = self.body()?;
                let Some(b) = b.as_object() else { return bad("envía un objeto") };
                let cols = table_cols("sources").unwrap_or(&[]);
                let mut d: Row = b.iter().filter(|(k, _)| cols.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect();
                if let Some(id) = b.get("id").filter(|v| is_int(v)) {
                    // editando: las credenciales vacías son las guardadas
                    if let Some(old) = q(&format!("SELECT {} FROM sources WHERE id=?", SECRET.join(", ")), p![id])?.one() {
                        for k in SECRET {
                            if !d.t(k) {
                                d.insert(k.into(), old[k].clone());
                            }
                        }
                    }
                }
                check_source(&d, true)?;
                let mut src: Row = Row::new();
                src.insert("kind".into(), "generic".into());
                src.extend(d);
                return Ok(match health::collect(&src) {
                    Ok((out, probs, info)) => js(200, json!({"metrics": health::metrics_json(&out), "problems": probs, "info": info})),
                    Err(e) => err(400, &e.to_string()),
                });
            }
            _ => {}
        }
        self.crud(m, res, rid, rid_i)
    }

    fn crud(&mut self, m: &str, res: &str, rid: Option<&str>, rid_i: i64) -> Result<Resp> {
        let Some(cols) = table_cols(res) else { return Ok(err(404, "no existe")) };
        if res == "apps" && m != "GET" && !self.admin {
            return Ok(err(403, "solo los administradores eligen qué se instala en los PCs"));
        }
        if m == "GET" && rid.is_none() {
            let order = match res {
                "pages" => "title",
                "items" => "name",
                "expiries" => "date",
                "subnets" => "cidr",
                "apps" => "name",
                _ => "id",
            };
            return Ok(js(200, q(&format!("SELECT * FROM {res} ORDER BY {order} COLLATE NOCASE"), p![])?.into_iter().map(public).collect::<Vec<_>>()));
        }
        if m == "POST" && rid.is_none() {
            // un objeto, o una lista para crear en serie
            let body = self.body()?;
            let is_list = body.is_array();
            let mut batch: Vec<Value> = if let Value::Array(a) = body { a } else { vec![body] };
            if batch.is_empty() || batch.len() > 1000 || !batch.iter().all(Value::is_object) {
                return bad("envía un objeto o una lista de 1 a 1000 objetos");
            }
            for b in batch.iter_mut() {
                // todo validado antes de guardar nada
                let b = b.as_object_mut().ok_or(Shape)?;
                let only: Row = b.iter().filter(|(k, _)| cols.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect();
                match res {
                    "items" => check_item(b)?,
                    "expiries" => check_expiry(b, true)?,
                    "subnets" => check_subnet(b, true)?,
                    "apps" => check_app(&only, true)?,
                    "checks" => check_host(&only, true)?,
                    "sources" => check_source(&only, true)?,
                    _ => {}
                }
            }
            let mut out = vec![];
            for b in &batch {
                let d: Vec<(&String, &Value)> = b.as_object().ok_or(Shape)?.iter().filter(|(k, _)| cols.contains(&k.as_str())).collect();
                let (keys, vals): (Vec<String>, Vec<SqlV>) = if d.is_empty() {
                    (vec![cols[0].to_string()], p![""])
                } else {
                    (d.iter().map(|(k, _)| k.to_string()).collect(), d.iter().map(|(_, v)| db::jv(v)).collect())
                };
                let id = q(&format!("INSERT INTO {res}({}) VALUES({})", keys.join(","), vec!["?"; keys.len()].join(",")), vals)?.lastrowid;
                let row = public(q(&format!("SELECT * FROM {res} WHERE id=?"), p![id])?.one().unwrap_or_default());
                self.log("crear", kind_of(res), id, &row[cols[0]], &Value::Object(row.clone()))?;
                out.push(Value::Object(row));
            }
            return Ok(js(201, if is_list { Value::Array(out) } else { out.into_iter().next().unwrap_or_default() }));
        }
        if m == "GET" {
            return Ok(match q(&format!("SELECT * FROM {res} WHERE id=?"), p![rid_i])?.one() {
                Some(r) => js(200, public(r)),
                None => err(404, "no existe"),
            });
        }
        if m == "PUT" {
            let raw = self.body()?;
            let seen = raw.get("_seen").filter(|v| !v.is_null()).cloned(); // la versión que abrió quien guarda
            let mut d: Row = obj(&raw)?.iter().filter(|(k, _)| cols.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect();
            match res {
                "items" => check_item(&d)?,
                "expiries" => check_expiry(&d, false)?,
                "subnets" => check_subnet(&mut d, false)?,
                "apps" => check_app(&d, false)?,
                "checks" => {
                    check_host(&d, false)?;
                    if d.contains_key("host") {
                        d.insert("state".into(), Value::Null); // otro host: su estado anterior no vale
                        d.insert("fails".into(), 0.into());
                    }
                }
                "sources" => {
                    for k in SECRET {
                        if d.get(k).and_then(Value::as_str) == Some("") {
                            d.shift_remove(k); // vacío = conservar la credencial guardada
                        }
                    }
                    check_source(&d, false)?;
                    d.insert("last".into(), Value::Null); // leer ya con la configuración nueva
                }
                _ => {}
            }
            if !d.is_empty() {
                // con _seen, solo si nadie lo cambió desde entonces (en la misma sentencia: atómico)
                let sets: Vec<String> = d.keys().map(|k| format!("{k}=?")).collect();
                let mut args: Vec<SqlV> = d.values().map(db::jv).collect();
                args.push(SqlV::Integer(rid_i));
                if let Some(s) = &seen {
                    args.push(db::jv(s));
                }
                let cur = q(
                    &format!("UPDATE {res} SET {}, updated=CURRENT_TIMESTAMP WHERE id=?{}", sets.join(","), if seen.is_some() { " AND updated=?" } else { "" }),
                    args,
                )?;
                if cur.rowcount == 0 && seen.is_some() {
                    if let Some(now) = q(&format!("SELECT updated FROM {res} WHERE id=?"), p![rid_i])?.one() {
                        let who = q("SELECT who FROM log WHERE kind=? AND ref=? ORDER BY id DESC LIMIT 1", p![kind_of(res), rid_i])?.one();
                        let who = who.map(|w| w.s("who").to_string()).filter(|w| !w.is_empty()).unwrap_or("Alguien".into());
                        return Ok(js(409, json!({"error": format!("{who} lo cambió mientras lo editabas."), "updated": now["updated"]})));
                    }
                }
            }
            let Some(row) = q(&format!("SELECT * FROM {res} WHERE id=?"), p![rid_i])?.one() else { return Ok(err(404, "no existe")) };
            let row = public(row);
            if !d.is_empty() {
                self.log("editar", kind_of(res), &row["id"], &row[cols[0]], &Value::Object(row.clone()))?;
            }
            return Ok(js(200, row));
        }
        if m == "DELETE" {
            let row = q(&format!("SELECT * FROM {res} WHERE id=?"), p![rid_i])?.one();
            q(&format!("DELETE FROM {res} WHERE id=?"), p![rid_i])?;
            if res == "checks" || res == "sources" {
                // su historial de lecturas se va con él
                let (t, col) = if res == "checks" { ("pings", "check_id") } else { ("metrics", "source_id") };
                q(&format!("DELETE FROM {t} WHERE {col}=?"), p![rid_i])?;
                q(&format!("DELETE FROM {t}_h WHERE {col}=?"), p![rid_i])?;
            }
            if let Some(row) = row {
                // la foto del borrado queda en el historial por si hay que recuperarlo
                let row = public(row);
                self.log("borrar", kind_of(res), &row["id"], &row[cols[0]], &Value::Object(row.clone()))?;
            }
            return Ok(no_content());
        }
        Ok(err(405, "método no permitido"))
    }

    /// Vuelve a crear lo borrado con la foto que quedó en Actividad, con su mismo id (los ids no se reutilizan).
    fn undo(&self, lid: i64) -> Result<Resp> {
        let e = q("SELECT * FROM log WHERE id=?", p![lid])?.one();
        let Some((e, t)) = e.filter(|e| e.s("action") == "borrar").and_then(|e| undo_table(e.s("kind")).map(|t| (e, t))) else {
            return Ok(err(400, "eso no se puede deshacer"));
        };
        let d: Value = serde_json::from_str(e.s("data")).unwrap_or(json!({}));
        if !q(&format!("SELECT 1 FROM {t} WHERE id=?"), p![&e["ref"]])?.is_empty() {
            return Ok(err(409, "ya existe otra vez"));
        }
        if t == "maps" {
            // sin la imagen de fondo: esa no queda en Actividad
            let name = d.get("name").and_then(Value::as_str).unwrap_or("Mapa");
            q("INSERT INTO maps(id, name, mime, image, data) VALUES(?, ?, '', ?, ?)", p![&e["ref"], name, Vec::<u8>::new(), d.get("data").cloned().unwrap_or(json!({})).to_string()])?;
        } else {
            let cols: Vec<String> = db::columns(t)?.into_iter().filter(|c| c != "id" && d.get(c).is_some()).collect();
            let mut args = p![&e["ref"]];
            args.extend(cols.iter().map(|c| db::jv(&d[c])));
            q(&format!("INSERT INTO {t}(id{}) VALUES(?{})", cols.iter().map(|c| format!(", {c}")).collect::<String>(), ", ?".repeat(cols.len())), args)?;
        }
        self.log("restaurar", e.s("kind"), &e["ref"], &e["name"], &d)?;
        Ok(js(200, json!({"kind": e["kind"], "id": e["ref"]})))
    }

    /// Copia de seguridad descargable (solo admin); POST {password}: cifrada.
    fn backup(&self, m: &str) -> Result<Resp> {
        if !self.admin {
            return Ok(err(403, "solo para administradores"));
        }
        let pw = if m == "POST" {
            let b = self.body()?;
            let pw = b.as_object().map(|o| o.get("password").cloned().unwrap_or(Value::Null)).unwrap_or(json!(""));
            check_pass(&pw)?; // "" no pasa
            pw.as_str().map(String::from)
        } else {
            None
        };
        let tmp = DATA.join(format!(".descarga-{}.db", token_hex(6)));
        let data = db::backup_to(&tmp).and_then(|_| Ok(std::fs::read(&tmp)?)); // desde su propia conexión: la web sigue mientras se copia
        let _ = std::fs::remove_file(&tmp);
        let data = data?;
        self.log(
            "descargar",
            "db",
            0,
            format!("una copia de seguridad{}", if pw.is_some() { " cifrada" } else { "" }),
            &json!({"bytes": data.len()}),
        )?;
        let name = format!("catlan-{}{}", crate::util::local("%Y%m%d-%H%M"), if pw.is_some() { ".catlan" } else { ".db" });
        Ok(match pw {
            Some(pw) => Resp::new(200, seal(&data, &pw), "application/octet-stream"),
            None => Resp::new(200, data, "application/vnd.sqlite3"),
        }
        .header("Content-Disposition", format!("attachment; filename=\"{name}\"")))
    }

    /// Canales de aviso: solo admin; los secretos ni salen ni se pisan con un campo vacío.
    fn alerts(&self, m: &str) -> Result<Resp> {
        if !self.admin {
            return Ok(err(403, "solo para administradores"));
        }
        if m == "GET" {
            return Ok(js(200, monitor::alerts_view()?));
        }
        if m != "PUT" {
            return Ok(err(405, "método no permitido"));
        }
        let b = self.body()?;
        let Some(b) = b.as_object() else { return bad("envía un objeto") };
        let mut saved = monitor::saved_alerts()?;
        for k in monitor::ALERT_KEYS {
            let Some(v) = b.get(k) else { continue };
            if v.is_null() {
                saved.shift_remove(k); // quitar lo guardado (vuelve la variable de entorno, si la hay)
                continue;
            }
            let Some(v) = v.as_str().filter(|s| s.chars().count() <= 600) else { return bad(format!("{k} no válido")) };
            let v = v.trim();
            if v.is_empty() {
                if !monitor::ALERT_SECRET.contains(&k) {
                    saved.shift_remove(k);
                }
                continue; // secreto vacío = conservar el guardado
            }
            monitor::check_alert(k, v)?;
            saved.insert(k.into(), v.into());
        }
        q("INSERT OR REPLACE INTO meta(k, v) VALUES('alerts', ?)", p![Value::Object(saved).to_string()])?;
        monitor::apply_alerts()?;
        let mut campos: Vec<&str> = b.keys().map(String::as_str).filter(|k| monitor::ALERT_KEYS.contains(k)).collect();
        campos.sort();
        self.log("editar", "alerts", 0, "los avisos", &json!({"campos": campos}))?;
        Ok(js(200, monitor::alerts_view()?))
    }

    /// Mantenimiento programado de equipos o de todo un rack.
    fn maintenance(&self) -> Result<Resp> {
        let b = self.body()?;
        let b = obj(&b)?;
        let rack = b.get("rack").filter(|v| !v.is_null());
        let mut items = b.get("items").filter(|v| truthy(v)).cloned().unwrap_or(json!([]));
        if let Some(rack) = rack {
            let Some(rk) = q("SELECT data FROM maps WHERE id=?", p![rack])?.one() else { return Ok(err(404, "no existe")) };
            let data: Value = serde_json::from_str(rk.s("data")).unwrap_or_default();
            items = data["devices"].as_array().into_iter().flatten().filter_map(|d| d.get("item").filter(|i| is_int(i)).cloned()).collect();
        }
        let items: Vec<i64> = match items.as_array() {
            Some(a) if !a.is_empty() && a.iter().all(is_int) => a.iter().filter_map(Value::as_i64).collect(),
            _ => return bad("elige equipos del inventario (o un rack con equipos enlazados)"),
        };
        let t = |k: &str| health::parse_iso(&b.get(k).map(py_str).unwrap_or_default(), true);
        let (Some(t0), Some(t1)) = (t("from"), t("to")) else { return bad("fechas no válidas") };
        if !(t0 < t1 && t1 > chrono::Utc::now() && t1 - t0 <= chrono::TimeDelta::days(31)) {
            return bad("el mantenimiento acaba después de empezar, en el futuro y dura como mucho 31 días");
        }
        let (f0, f1) = (t0.format("%Y-%m-%d %H:%M:%S").to_string(), t1.format("%Y-%m-%d %H:%M:%S").to_string());
        let marks = vec!["?"; items.len()].join(",");
        let ips: Vec<Value> =
            q(&format!("SELECT ip FROM items WHERE id IN ({marks}) AND ip != ''"), items.iter().map(|i| SqlV::Integer(*i)).collect())?.into_iter().map(|r| r["ip"].clone()).collect();
        let mut n = 0;
        for t in ["checks", "sources"] {
            let mut args = p![&f0, &f1];
            args.extend(items.iter().map(|i| SqlV::Integer(*i)));
            args.extend(ips.iter().map(db::jv));
            let or = if ips.is_empty() { String::new() } else { format!(" OR host IN ({})", vec!["?"; ips.len()].join(",")) };
            n += q(&format!("UPDATE {t} SET mute_from=?, mute_until=? WHERE item IN ({marks}){or}"), args)?.rowcount;
        }
        let (kind, r) = match rack {
            Some(r) => ("rack", db::jv(r)),
            None => ("item", SqlV::Integer(items[0])),
        };
        self.log("programar mantenimiento", kind, r, format!("{} equipos", items.len()), &json!({"desde": f0, "hasta": f1, "items": items}))?;
        Ok(js(200, json!({"muted": n, "from": f0, "to": f1})))
    }

    /// Borra todo el contenido. Solo un admin y con su contraseña; antes, una copia completa en la carpeta de datos.
    fn wipe(&self) -> Result<Resp> {
        if !self.admin {
            return Ok(err(403, "solo para administradores"));
        }
        let ip = &self.req.ip;
        if throttled(ip) {
            return Ok(err(429, "demasiados intentos: espera 15 minutos"));
        }
        let b = self.body()?;
        let pw = b.as_object().and_then(|o| o.get("pass")).and_then(Value::as_str).map(|s| trunc(s, 200));
        let hash = val("SELECT hash FROM users WHERE id=?", p![self.uid()])?;
        if !pw.is_some_and(|pw| pw_ok(&pw, hash.as_str().unwrap_or(""))) {
            failed(ip); // cuenta como intento fallido: nadie prueba contraseñas por aquí
            return Ok(err(403, "contraseña incorrecta"));
        }
        let copy = format!("catlan-antes-de-borrar-{}.db", crate::util::local("%Y%m%d-%H%M%S"));
        {
            let mut c = lock(db::writer());
            db::backup_to(&DATA.join(&copy))?;
            let tx = c.transaction()?;
            for t in WIPE {
                tx.execute_batch(&format!("DELETE FROM {t}"))?;
            }
            tx.commit()?;
        }
        lock(&health::IF_PREV).clear();
        self.log("vaciar", "db", 0, "la base de datos", &json!({"copia": copy}))?;
        Ok(js(200, json!({"copy": copy})))
    }

    /// Kitty se presenta con su clave: pendiente hasta que un admin lo acepta; aceptado, catlan mantiene su ficha.
    fn agent_hello(&mut self) -> Result<Resp> {
        let b = self.body()?;
        let key = b.as_object().and_then(|o| o.get("key")).and_then(Value::as_str).filter(|k| (32..=128).contains(&k.chars().count()));
        let Some(key) = key else { return bad("falta la clave de Kitty") };
        let mut f: Map<String, Value> =
            AGENT_FACTS.iter().map(|k| (k.to_string(), Value::from(trunc(b.get(*k).and_then(Value::as_str).unwrap_or("").trim(), 100)))).collect();
        if f.s("ip").is_empty() {
            f.insert("ip".into(), self.req.ip.clone().into()); // el Kitty de PowerShell no la calcula: la de su conexión
        }
        if f.s("name").is_empty() {
            return bad("falta el nombre del equipo");
        }
        let key = sha256_hex(key);
        // la clave de incidencias: la que usa la ventana de Kitty, con el usuario del PC, para abrir incidencias de este equipo
        let ukey = b.get("ukey").and_then(Value::as_str).filter(|k| (32..=128).contains(&k.chars().count())).map(sha256_hex);
        let save_ukey = || -> Result<()> {
            if let Some(u) = &ukey {
                q("UPDATE agents SET ukey=? WHERE key=?", p![u, &key])?;
            }
            Ok(())
        };
        let instance = db::INSTANCE.get().cloned().unwrap_or_default();
        let fvals: Vec<SqlV> = AGENT_FACTS.iter().map(|k| db::jv(&f[*k])).collect();
        let Some(a) = q("SELECT * FROM agents WHERE key=?", p![&key])?.one() else {
            if val("SELECT COUNT(*) FROM agents WHERE state='pendiente'", p![])?.as_i64().unwrap_or(0) >= 100 {
                return Ok(err(429, "demasiados Kitty pendientes de aceptar")); // sin sesión: que nadie llene la tabla
            }
            let mut args = p![&key];
            args.extend(fvals);
            q(&format!("INSERT INTO agents(key, {}, seen) VALUES(?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)", AGENT_FACTS.join(", ")), args)?;
            save_ukey()?;
            return Ok(js(200, json!({"state": "pendiente", "catlan": instance})));
        };
        let mut args = fvals;
        args.push(db::jv(&a["id"]));
        q(&format!("UPDATE agents SET {}, seen=CURRENT_TIMESTAMP WHERE id=?", AGENT_FACTS.map(|k| format!("{k}=?")).join(", ")), args)?;
        save_ukey()?;
        if a.s("state") != "adoptado" {
            return Ok(js(200, json!({"state": a["state"], "catlan": instance})));
        }
        self.user = format!("Kitty · {}", f.s("name"));
        let item = self.agent_item(&a, &f)?;
        // «secs», el Kitty en Rust (cada minuto); «every», en minutos, el de PowerShell y el de Linux
        let secs = b.get("secs").filter(|e| is_int(e)).and_then(Value::as_i64).filter(|e| (10..=86400).contains(e));
        let every = secs.or_else(|| b.get("every").filter(|e| is_int(e)).and_then(Value::as_i64).filter(|e| (1..=1440).contains(e)).map(|e| e * 60)).unwrap_or(300);
        let host = if f.s("ip").is_empty() { f.s("name") } else { f.s("ip") }.to_string();
        let src = match a.i("source") {
            Some(s) => q(&format!("{SOURCES} WHERE s.id=? AND s.kind='kitty'"), p![s])?.one(),
            None => None,
        };
        let src = match src {
            Some(s) => s,
            None => {
                // su ficha de Salud: la primera vez, o si la borraron
                let sid = q("INSERT INTO sources(host, item, kind, every) VALUES(?, ?, 'kitty', ?)", p![&host, item, every])?.lastrowid;
                q("UPDATE agents SET source=? WHERE id=?", p![sid, &a["id"]])?;
                q(&format!("{SOURCES} WHERE s.id=?"), p![sid])?.one().unwrap_or_default()
            }
        };
        q("UPDATE sources SET host=?, item=?, every=?, last=CURRENT_TIMESTAMP WHERE id=?", p![&host, item, every, &src["id"]])?;
        let (out, mut info) = health::kitty_read(f.s("name"), b.get("facts").unwrap_or(&Value::Null));
        let prev: Value = serde_json::from_str::<Value>(src.s("info")).ok().and_then(|i| i.get("events").cloned()).unwrap_or(Value::Null);
        let (events, mut probs) = health::kitty_events(b.get("events").unwrap_or(&Value::Null), &prev);
        info.insert("events".into(), events.into());
        if let Some(a) = b.get("apps").filter(|a| a.is_object() && a.to_string().len() <= 64 * 1024) {
            info.insert("apps".into(), a.clone()); // cómo le fue a winget con cada programa
        }
        let out = health::limits(&src, out, &mut probs);
        monitor::save_health(&src, &out, &probs, Some(&info), None)?;
        let apps: Vec<Value> = q("SELECT winget FROM apps ORDER BY id", p![])?.into_iter().map(|r| r["winget"].clone()).collect();
        Ok(js(200, json!({"state": "adoptado", "item": item, "catlan": instance, "apps": apps})))
    }

    /// El Kitty de la clave de incidencias, si ya lo aceptaron. Si no, la respuesta que toca.
    fn agent_by_ukey(&self, b: &Value) -> Result<std::result::Result<Row, Resp>> {
        let Some(u) = b.as_object().and_then(|o| o.get("ukey")).and_then(Value::as_str).filter(|k| (32..=128).contains(&k.chars().count())) else {
            return bad("falta la clave de Kitty");
        };
        Ok(match q("SELECT * FROM agents WHERE ukey=? ORDER BY id DESC LIMIT 1", p![sha256_hex(u)])?.one() {
            Some(a) if a.s("state") == "adoptado" => Ok(a),
            Some(a) => Err(js(403, json!({"error": if a.s("state") == "pendiente" { "IT todavía no ha aceptado este equipo en catlan" } else { "catlan ha rechazado este equipo" }, "state": a["state"]}))),
            None => Err(js(404, json!({"error": "este equipo aún no se ha presentado a catlan: espera unos minutos", "state": null}))),
        })
    }

    /// Control remoto, lado de Kitty: preguntar si IT quiere conectarse, responder y enviar la pantalla.
    /// Con la clave de incidencias (la ventana de Kitty corre como el usuario del PC y no puede leer la del equipo).
    fn agent_remote(&mut self, sub: Option<&str>) -> Result<Resp> {
        if sub == Some("frame") {
            // el cuerpo es el JPEG: la clave y la sesión van en cabeceras
            let a = match self.agent_by_ukey(&json!({"ukey": self.req.header("x-kitty")}))? {
                Ok(a) => a,
                Err(r) => return Ok(r),
            };
            let jpg = self.req.body.clone();
            if !jpg.is_empty() && !(jpg.starts_with(&[0xFF, 0xD8]) && jpg.len() <= 8 << 20) {
                return bad("fotograma no válido");
            }
            return Ok(remote::push(a.i("id").unwrap_or(0), self.req.header("x-sesion"), jpg).map_or_else(|| err(404, "no existe"), |v| js(200, v)));
        }
        let b = self.body()?;
        let a = match self.agent_by_ukey(&b)? {
            Ok(a) => a,
            Err(r) => return Ok(r),
        };
        let aid = a.i("id").unwrap_or(0);
        Ok(match sub {
            None => js(200, remote::pending(aid)),
            Some("answer") => {
                let id = b.get("id").and_then(Value::as_str).unwrap_or("");
                let ok = b.get("ok").and_then(Value::as_bool).unwrap_or(false);
                remote::answer(aid, id, ok).map_or_else(|| err(404, "no existe"), |v| js(200, v))
            }
            Some(_) => err(404, "no existe"),
        })
    }

    /// Control remoto, lado del técnico: pedirlo, ver la pantalla, mandar ratón y teclado, y terminar.
    /// Cada sesión es solo de quien la pidió; el usuario del PC tiene que aceptarla.
    fn remote(&mut self, m: &str, rid: Option<&str>, sub: Option<&str>, qs: &HashMap<String, Vec<String>>) -> Result<Resp> {
        let uid = self.uid();
        let gone = || err(404, "esta sesión ya no existe");
        Ok(match (m, rid, sub) {
            ("POST", None, None) => {
                let b = self.body()?;
                let Some(aid) = b.get("agent").and_then(Value::as_i64) else { return bad("¿a qué equipo?") };
                let Some(a) = q("SELECT * FROM agents WHERE id=?", p![aid])?.one() else { return Ok(err(404, "ese Kitty no existe")) };
                if a.s("state") != "adoptado" {
                    return bad("este Kitty aún no está aceptado en catlan");
                }
                match remote::ask(&a, uid, &self.user) {
                    Ok((id, st)) => js(201, json!({"id": id, "status": st})),
                    Err(e) => err(409, &e),
                }
            }
            ("GET", Some(id), None) => remote::get(id, uid).map_or_else(gone, |v| js(200, v)),
            ("GET", Some(id), Some("frame")) => {
                let after = qs.get("after").and_then(|v| v.first()).and_then(|s| s.parse().ok()).unwrap_or(0);
                match remote::frame(id, uid, after) {
                    Some((Some((seq, jpg)), _)) => Resp::new(200, jpg, "image/jpeg").header("X-Seq", seq.to_string()).header("Cache-Control", "no-store"),
                    Some((None, st)) => js(200, st), // sin fotograma nuevo: el estado
                    None => gone(),
                }
            }
            ("POST", Some(id), Some("input")) => {
                if self.req.body.len() > 64 * 1024 {
                    return bad("demasiados eventos de golpe");
                }
                let b = self.body()?;
                let Some(evs) = b.as_array().filter(|a| a.len() <= 500 && a.iter().all(|e| e.get("t").is_some_and(Value::is_string))) else {
                    return bad("eventos no válidos");
                };
                remote::input(id, uid, evs.clone()).map_or_else(gone, |v| js(200, v))
            }
            ("DELETE", Some(id), None) => remote::stop(id, uid, &self.user).map_or_else(gone, |v| js(200, v)),
            _ => err(405, "método no permitido"),
        })
    }

    /// Las incidencias que se abrieron desde la ventana de Kitty de este equipo, con su estado.
    fn agent_mine(&self) -> Result<Resp> {
        let b = self.body()?;
        let a = match self.agent_by_ukey(&b)? {
            Ok(a) => a,
            Err(r) => return Ok(r),
        };
        let rows = q(
            "SELECT n.id, n.title, n.status, n.priority, n.created, n.updated, (SELECT count(*) FROM notes WHERE incident = n.id AND change = 0) AS notes              FROM incidents n WHERE n.item=? AND EXISTS (SELECT 1 FROM notes o WHERE o.incident = n.id AND o.change = 1 AND o.text = 'abrió la incidencia'              AND o.who = 'Kitty · ' || ?) ORDER BY n.status IN ('resuelta', 'cerrada'), n.updated DESC LIMIT 30",
            p![&a["item"], &a["name"]],
        )?;
        Ok(js(200, json!({"state": a["state"], "name": a["name"], "item": a["item"], "incidents": rows.rows})))
    }

    /// Cerrar la Kitty de un PC: solo con un administrador de catlan (el usuario del PC no puede quitarla).
    /// Mismo límite de intentos que el login; no abre sesión.
    fn agent_quit(&mut self) -> Result<Resp> {
        let b = self.body()?;
        let a = match self.agent_by_ukey(&b)? {
            Ok(a) => a,
            Err(r) => return Ok(r),
        };
        let ip = self.req.ip.clone();
        if throttled(&ip) {
            return Ok(err(429, "demasiados intentos: espera 15 minutos"));
        }
        let bs = |k: &str| b.get(k).map(py_str).unwrap_or_default();
        let uid = match login_ok(&trunc(&bs("name"), 100), &trunc(&bs("pass"), 200), &trunc(&bs("code"), 10))? {
            Login::Ok(id) => id,
            other => {
                failed(&ip);
                return Ok(match other {
                    Login::NeedCode => js(401, json!({"error": "escribe el código de la app de autenticación", "totp": true})),
                    _ => err(401, "usuario o contraseña incorrectos"),
                });
            }
        };
        let Some(u) = q("SELECT name, admin FROM users WHERE id=?", p![uid])?.one().filter(|u| u.t("admin")) else {
            return Ok(err(403, "solo un administrador de catlan puede cerrar Kitty"));
        };
        self.user = u.s("name").to_string();
        self.log("cerrar Kitty", "agent", &a["id"], &a["name"], &json!({}))?;
        Ok(js(200, json!({"ok": true})))
    }

    /// Una incidencia que abre el usuario del PC desde Kitty: va al equipo de su ficha y avisa si es urgente.
    fn agent_incident(&mut self) -> Result<Resp> {
        let b = self.body()?;
        let a = match self.agent_by_ukey(&b)? {
            Ok(a) => a,
            Err(r) => return Ok(r),
        };
        let title = b.get("title").and_then(Value::as_str).map(str::trim).filter(|t| (1..=200).contains(&t.chars().count()));
        let Some(title) = title else { return bad("cuenta en una frase qué pasa (hasta 200 caracteres)") };
        let body = b.get("body").and_then(Value::as_str).unwrap_or("").trim();
        if body.chars().count() > 5000 {
            return bad("la descripción es demasiado larga (hasta 5000 caracteres)");
        }
        let prio = b.get("priority").and_then(Value::as_str).unwrap_or("media");
        if !INC_PRIO.contains(&prio) {
            return bad("urgencia no válida");
        }
        self.user = format!("Kitty · {}", a.s("name"));
        // sin sesión: como mucho 10 por hora desde cada equipo
        let recent = val("SELECT COUNT(*) FROM log WHERE who=? AND kind='incident' AND action='crear' AND ts > datetime('now', '-1 hour')", p![&self.user])?;
        if recent.as_i64().unwrap_or(0) >= 10 {
            return Ok(err(429, "demasiados avisos seguidos desde este equipo: espera un rato o llama a IT"));
        }
        let id = q("INSERT INTO incidents(title, body, priority, item) VALUES(?, ?, ?, ?)", p![title, body, prio, &a["item"]])?.lastrowid;
        self.note(id, "abrió la incidencia", true)?;
        self.log("crear", "incident", id, title, &json!({"title": title, "body": body, "priority": prio, "item": a["item"], "desde": "Kitty"}))?;
        if prio == "crítica" {
            monitor::notify(&format!("catlan: incidencia crítica INC-{id}: {title}"), &format!("Abierta desde Kitty en {}.

-- catlan", a.s("name")));
        }
        Ok(js(201, q("SELECT id, title, status, priority, created, updated FROM incidents WHERE id=?", p![id])?.one()))
    }

    /// La ficha de este Kitty: la suya, o una con su nº de serie o su nombre (inventariado a mano), o una nueva.
    /// Solo cambia la IP y el nº de serie: nombre, tipo, ubicación y notas son del usuario.
    fn agent_item(&self, a: &Row, f: &Map<String, Value>) -> Result<i64> {
        let mut it = match a.i("item") {
            Some(i) => q("SELECT * FROM items WHERE id=?", p![i])?.one(),
            None => None,
        };
        if it.is_none() {
            if !f.s("serial").is_empty() {
                it = q("SELECT * FROM items WHERE serial=? ORDER BY id LIMIT 1", p![f.s("serial")])?.one();
            }
            if it.is_none() {
                it = q("SELECT * FROM items WHERE name=? COLLATE NOCASE ORDER BY id LIMIT 1", p![f.s("name")])?.one();
            }
            if it.is_none() {
                let rid = q(
                    "INSERT INTO items(name, kind, ip, serial, status, notes) VALUES(?,?,?,?,'activo',?)",
                    p![f.s("name"), f.s("kind"), f.s("ip"), f.s("serial"), format!("Alta automática de Kitty ({}).", f.s("os"))],
                )?
                .lastrowid;
                let row = q("SELECT * FROM items WHERE id=?", p![rid])?.one().unwrap_or_default();
                self.log("crear", "item", rid, &row["name"], &Value::Object(row.clone()))?;
                it = Some(row);
            }
            q("UPDATE agents SET item=? WHERE id=?", p![&it.as_ref().unwrap()["id"], &a["id"]])?;
        }
        let it = it.unwrap_or_default();
        let id = it.i("id").unwrap_or(0);
        let d: Vec<&str> = ["ip", "serial"].into_iter().filter(|k| !f.s(k).is_empty() && f.s(k) != it.s(k)).collect();
        if !d.is_empty() {
            // sin cambios no se escribe: cada edición deja una entrada en Actividad
            let mut args: Vec<SqlV> = d.iter().map(|k| SqlV::Text(f.s(k).into())).collect();
            args.push(SqlV::Integer(id));
            q(&format!("UPDATE items SET {}, updated=CURRENT_TIMESTAMP WHERE id=?", d.iter().map(|k| format!("{k}=?")).collect::<Vec<_>>().join(", ")), args)?;
            let row = q("SELECT * FROM items WHERE id=?", p![id])?.one().unwrap_or_default();
            self.log("editar", "item", id, &it["name"], &Value::Object(row))?;
        }
        Ok(id)
    }

    /// Kitty rechazado u olvidado: fuera de Salud, con su historial (si no, avisaría de que «no responde»).
    fn drop_source(a: &Row) -> Result<()> {
        if let Some(s) = a.i("source") {
            if !q("SELECT 1 FROM sources WHERE id=? AND kind='kitty'", p![s])?.is_empty() {
                for (t, col) in [("sources", "id"), ("metrics", "source_id"), ("metrics_h", "source_id")] {
                    q(&format!("DELETE FROM {t} WHERE {col}=?"), p![s])?;
                }
            }
        }
        q("UPDATE agents SET source=NULL WHERE id=?", p![&a["id"]])?;
        Ok(())
    }

    fn agents(&mut self, m: &str, rid: i64, list: bool) -> Result<Resp> {
        if !self.admin {
            return Ok(err(403, "solo para administradores")); // aceptar un Kitty es dejar entrar un equipo
        }
        if m == "GET" && list {
            let rows: Vec<Row> = q("SELECT * FROM agents ORDER BY state != 'pendiente', name COLLATE NOCASE", p![])?
                .into_iter()
                .map(|mut r| {
                    let code = trunc(r.s("key"), 8);
                    r.shift_remove("key");
                    r.insert("code".into(), code.into());
                    r
                })
                .collect();
            return Ok(js(200, rows));
        }
        let Some(a) = q("SELECT * FROM agents WHERE id=?", p![rid])?.one() else { return Ok(err(404, "no existe")) };
        let code = trunc(a.s("key"), 8);
        if m == "PUT" {
            let b = self.body()?;
            let st = if truthy(&b) { obj(&b)?.get("state").and_then(Value::as_str).unwrap_or("").to_string() } else { String::new() };
            if st != "adoptado" && st != "rechazado" {
                return bad("estado no válido");
            }
            q("UPDATE agents SET state=? WHERE id=?", p![&st, &a["id"]])?;
            if st == "rechazado" {
                Self::drop_source(&a)?;
            }
            self.log(if st == "adoptado" { "aceptar" } else { "rechazar" }, "agent", &a["id"], &a["name"], &json!({"ip": a["ip"], "code": code}))?;
            let item = if st == "adoptado" {
                // su ficha ya, sin esperar a Kitty
                let f: Map<String, Value> = AGENT_FACTS.iter().map(|k| (k.to_string(), Value::from(a.s(k)))).collect();
                json!(self.agent_item(&a, &f)?)
            } else {
                Value::Null
            };
            return Ok(js(200, json!({"state": st, "item": item})));
        }
        if m == "DELETE" {
            // olvidarlo: si sigue instalado, volverá a pedir entrada
            Self::drop_source(&a)?;
            q("DELETE FROM agents WHERE id=?", p![&a["id"]])?;
            self.log("olvidar", "agent", &a["id"], &a["name"], &json!({"ip": a["ip"], "code": code}))?;
            return Ok(no_content());
        }
        Ok(err(405, "método no permitido"))
    }

    fn groups(&mut self, m: &str, rid: Option<&str>, rid_i: i64) -> Result<Resp> {
        if m == "GET" {
            // todos: hace falta para asignar incidencias
            let mut out = vec![];
            for mut g in q("SELECT * FROM groups ORDER BY name COLLATE NOCASE", p![])? {
                let members: Vec<Value> = q("SELECT user_id FROM members WHERE group_id=?", p![&g["id"]])?.into_iter().map(|r| r["user_id"].clone()).collect();
                g.insert("members".into(), members.into());
                out.push(g);
            }
            return Ok(js(200, out));
        }
        if !self.admin {
            return Ok(err(403, "solo para administradores"));
        }
        let b = if m != "DELETE" { self.body()? } else { json!({}) };
        let users: HashSet<i64> = q("SELECT id FROM users", p![])?.into_iter().filter_map(|r| r.i("id")).collect();
        let check = |x: &Value, new: bool| -> Result<()> {
            let Some(x) = x.as_object() else { return bad("envía un objeto") };
            if (new || x.contains_key("name")) && !x.get("name").and_then(Value::as_str).is_some_and(|n| (1..=60).contains(&n.trim().chars().count())) {
                return bad("el nombre del grupo va de 1 a 60 caracteres");
            }
            if x.get("role").is_some_and(|r| !r.as_str().is_some_and(|r| r == "edit" || r == "view")) {
                return bad("permiso no válido");
            }
            if x.get("members").is_some_and(|ms| !ms.as_array().is_some_and(|a| a.iter().all(|m| is_int(m) && users.contains(&m.as_i64().unwrap_or(-1))))) {
                return bad("miembros no válidos");
            }
            Ok(())
        };
        let members = |x: &Value| -> Vec<i64> {
            let mut v: Vec<i64> = x.get("members").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_i64).collect();
            v.sort();
            v.dedup();
            v
        };
        if m == "POST" && rid.is_none() && b.is_array() {
            // varios grupos de una vez, todo validado antes
            let list = b.as_array().unwrap();
            let taken: HashSet<String> = q("SELECT name FROM groups", p![])?.into_iter().map(|r| r.s("name").to_lowercase()).collect();
            let mut seen = HashSet::new();
            if !(1..=100).contains(&list.len()) {
                return bad("de 1 a 100 grupos a la vez");
            }
            for x in list {
                check(x, true)?;
                let name = x.s("name").trim().to_string();
                let k = name.to_lowercase();
                if taken.contains(&k) || seen.contains(&k) {
                    return bad(format!("{}: {name}", if taken.contains(&k) { "ya existe" } else { "repetido en la lista" }));
                }
                seen.insert(k);
            }
            let mut out = vec![];
            for x in list {
                let name = x.s("name").trim().to_string();
                let gid = q("INSERT INTO groups(name, role) VALUES(?, ?)", p![&name, x.get("role").and_then(Value::as_str).unwrap_or("edit")])?.lastrowid;
                for mm in members(x) {
                    q("INSERT INTO members(group_id, user_id) VALUES(?, ?)", p![gid, mm])?;
                }
                self.log("crear", "group", gid, &name, x)?;
                out.push(q("SELECT * FROM groups WHERE id=?", p![gid])?.one().unwrap_or_default());
            }
            return Ok(js(201, out));
        }
        if m != "DELETE" {
            check(&b, m == "POST")?;
        }
        let gid = if m == "POST" && rid.is_none() {
            let name = b.get("name").map(py_str).unwrap_or_default().trim().to_string();
            match q("INSERT INTO groups(name, role) VALUES(?, ?)", p![name, b.get("role").and_then(Value::as_str).unwrap_or("edit")]) {
                Ok(r) => r.lastrowid,
                Err(e) if is_constraint(&e) => return bad("ese grupo ya existe"),
                Err(e) => return Err(e),
            }
        } else {
            let Some(g) = q("SELECT id FROM groups WHERE id=?", p![rid_i])?.one() else { return Ok(err(404, "no existe")) };
            g.i("id").unwrap_or(0)
        };
        if m == "DELETE" {
            let name = val("SELECT name FROM groups WHERE id=?", p![gid])?;
            q("UPDATE incidents SET grp=NULL WHERE grp=?", p![gid])?;
            q("DELETE FROM members WHERE group_id=?", p![gid])?;
            q("DELETE FROM groups WHERE id=?", p![gid])?;
            self.log("borrar", "group", gid, &name, &json!({}))?;
            return Ok(no_content());
        }
        if m == "PUT" {
            for k in ["name", "role"] {
                if let Some(v) = b.get(k).and_then(Value::as_str) {
                    let v = if k == "name" { v.trim() } else { v };
                    match q(&format!("UPDATE groups SET {k}=? WHERE id=?"), p![v, gid]) {
                        Ok(_) => {}
                        Err(e) if is_constraint(&e) => return bad("ese grupo ya existe"),
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        if b.get("members").is_some() {
            q("DELETE FROM members WHERE group_id=?", p![gid])?;
            for mm in members(&b) {
                q("INSERT INTO members(group_id, user_id) VALUES(?, ?)", p![gid, mm])?;
            }
        }
        let g = q("SELECT * FROM groups WHERE id=?", p![gid])?.one().unwrap_or_default();
        self.log(if m == "POST" { "crear" } else { "editar" }, "group", gid, &g["name"], &b)?;
        Ok(js(if m == "POST" { 201 } else { 200 }, g))
    }

    fn note(&self, inc: i64, text: &str, change: bool) -> Result<()> {
        q("INSERT INTO notes(incident, who, text, change) VALUES(?,?,?,?)", p![inc, &self.user, text, change])?;
        q("UPDATE incidents SET updated=CURRENT_TIMESTAMP WHERE id=?", p![inc])?;
        Ok(())
    }

    /// Resuelta (o cerrada) la padre, sus hijas abiertas también, y las hijas de estas. Devuelve cuántas.
    fn close_children(&self, inc: i64, status: &str) -> Result<i64> {
        let mut n = 0;
        for kid in q("SELECT id, title, status FROM incidents WHERE parent=?", p![inc])? {
            let id = kid.i("id").unwrap_or(0);
            if !DONE.contains(&kid.s("status")) {
                // las ya resueltas se quedan como están, pero se baja igual: sus hijas pueden seguir abiertas
                q("UPDATE incidents SET status=? WHERE id=?", p![status, id])?;
                self.note(id, &format!("pasó a «{status}» con su incidencia padre INC-{inc}"), true)?;
                self.log("editar", "incident", id, &kid["title"], &json!({"status": status, "por la padre": inc}))?;
                n += 1;
            }
            n += self.close_children(id, status)?;
        }
        Ok(n)
    }

    /// Tablero personal: tareas y notas de cada usuario, que solo ve y toca él. Sin Actividad: no son de nadie más.
    fn tasks(&mut self, m: &str, rid: Option<&str>, rid_i: i64) -> Result<Resp> {
        let uid = self.uid();
        const ROW: &str = "SELECT id, text, col, pos, updated FROM tasks";
        if m == "GET" && rid.is_none() {
            return Ok(js(200, q(&format!("{ROW} WHERE user=? ORDER BY pos, id"), p![uid])?.rows));
        }
        if m == "DELETE" && rid.is_some() {
            let n = q("DELETE FROM tasks WHERE id=? AND user=?", p![rid_i, uid])?.rowcount;
            return Ok(if n == 0 { err(404, "no existe") } else { no_content() });
        }
        if !(m == "POST" && rid.is_none() || m == "PUT" && rid.is_some()) {
            return Ok(err(405, "método no permitido"));
        }
        let b = self.body()?;
        let b = obj(&b)?;
        let text = match b.get("text") {
            None => None,
            Some(Value::String(s)) if (1..=2000).contains(&s.trim().chars().count()) => Some(s.trim().to_string()),
            Some(_) => return bad("la tarea va de 1 a 2000 caracteres"),
        };
        let col = match b.get("col") {
            None => None,
            Some(Value::String(s)) if TASK_COLS.contains(&s.as_str()) => Some(s.clone()),
            Some(_) => return bad("columna no válida"),
        };
        let pos = match b.get("pos") {
            None => None,
            Some(v) => match v.as_f64().filter(|f| f.is_finite()) {
                Some(f) => Some(f),
                None => return bad("posición no válida"),
            },
        };
        let id = if m == "POST" {
            let Some(text) = text else { return bad("escribe la tarea") };
            if val("SELECT count(*) FROM tasks WHERE user=?", p![uid])?.as_i64().unwrap_or(0) >= 1000 {
                return bad("como mucho 1000 tareas: borra las hechas");
            }
            let col = col.unwrap_or_else(|| "pendiente".into());
            // sin posición: al final de su columna
            q("INSERT INTO tasks(user, text, col, pos) VALUES(?, ?, ?, COALESCE(?, (SELECT max(pos) + 1 FROM tasks WHERE user=? AND col=?), 0))",
                p![uid, text, col.clone(), pos, uid, col])?
            .lastrowid
        } else {
            let n = q("UPDATE tasks SET text=COALESCE(?, text), col=COALESCE(?, col), pos=COALESCE(?, pos), updated=CURRENT_TIMESTAMP WHERE id=? AND user=?",
                p![text, col, pos, rid_i, uid])?
            .rowcount;
            if n == 0 {
                return Ok(err(404, "no existe"));
            }
            rid_i
        };
        Ok(js(if m == "POST" { 201 } else { 200 }, q(&format!("{ROW} WHERE id=?"), p![id])?.one()))
    }

    fn incidents(&mut self, m: &str, rid: Option<&str>, rid_i: i64, parts: &[String]) -> Result<Resp> {
        if m == "GET" && rid.is_none() {
            let order = " ORDER BY n.status IN ('resuelta', 'cerrada'), CASE n.priority WHEN 'crítica' THEN 0 \
                         WHEN 'alta' THEN 1 WHEN 'media' THEN 2 ELSE 3 END, n.updated DESC";
            return Ok(js(200, q(&format!("{INC}{order}"), p![])?.rows));
        }
        let b = if m == "POST" || m == "PUT" { self.body()? } else { json!({}) };
        let Some(bo) = b.as_object() else { return bad("envía un objeto") };
        let mut d: Row = INC_COLS.iter().filter_map(|k| bo.get(*k).map(|v| (k.to_string(), v.clone()))).collect();
        if m == "POST" && rid.is_none() {
            let mut chk = d.clone();
            chk.entry("title").or_insert("".into());
            check_incident(&chk, None)?;
            let keys: Vec<&String> = d.keys().collect();
            let mut args: Vec<SqlV> = d.values().map(db::jv).collect();
            args.push(SqlV::Integer(self.uid()));
            let id = q(
                &format!(
                    "INSERT INTO incidents({}author) VALUES({}?)",
                    keys.iter().map(|k| format!("{k}, ")).collect::<String>(),
                    "?, ".repeat(keys.len())
                ),
                args,
            )?
            .lastrowid;
            self.note(id, "abrió la incidencia", true)?;
            self.log("crear", "incident", id, &d["title"], &Value::Object(d.clone()))?;
            let row = q(&format!("{INC} WHERE n.id=?"), p![id])?.one().unwrap_or_default();
            if row.s("priority") == "crítica" {
                // lo urgente sale por correo, Telegram o webhook
                let to = if row.t("assignee") || row.t("grp") {
                    format!(", asignada a {}", if row.s("assignee_name").is_empty() { row.s("grp_name") } else { row.s("assignee_name") })
                } else {
                    String::new()
                };
                monitor::notify(&format!("catlan: incidencia crítica INC-{id}: {}", row.s("title")), &format!("Abierta por {}{to}.\n\n-- catlan", self.user));
            }
            return Ok(js(201, row));
        }
        let Some(row) = q(&format!("{INC} WHERE n.id=?"), p![rid_i])?.one() else { return Ok(err(404, "no existe")) };
        let id = row.i("id").unwrap_or(0);
        if m == "GET" && parts.len() == 3 {
            let mut out = row.clone();
            out.insert("history".into(), q("SELECT * FROM notes WHERE incident=? ORDER BY id", p![id])?.rows.into_iter().map(Value::Object).collect::<Vec<_>>().into());
            out.insert("kids".into(), q(&format!("{INC} WHERE n.parent=? ORDER BY n.id"), p![id])?.rows.into_iter().map(Value::Object).collect::<Vec<_>>().into());
            // trazabilidad: dónde se enlaza con [[INC-n]] (páginas, notas de equipos, otras incidencias y su seguimiento)
            let tag = format!("%[[INC-{id}]]%");
            out.insert("mentions".into(), json!({
                "pages": q("SELECT id, title FROM pages WHERE body LIKE ? ORDER BY title", p![&tag])?.rows,
                "items": q("SELECT id, name FROM items WHERE notes LIKE ? ORDER BY name", p![&tag])?.rows,
                "incidents": q("SELECT id, title, status FROM incidents WHERE id != ? AND (body LIKE ? OR id IN (SELECT incident FROM notes WHERE change = 0 AND text LIKE ?)) ORDER BY id DESC",
                    p![id, &tag, &tag])?.rows,
            }));
            return Ok(js(200, out));
        }
        if m == "POST" && parts.get(3).map(String::as_str) == Some("notes") && parts.len() == 4 {
            let t = bo.get("text").and_then(Value::as_str).map(str::trim).filter(|t| (1..=5000).contains(&t.chars().count()));
            let Some(t) = t else { return bad("la nota va de 1 a 5000 caracteres") };
            self.note(id, t, false)?;
            return Ok(js(201, q("SELECT * FROM notes WHERE id = (SELECT max(id) FROM notes WHERE incident=?)", p![id])?.one()));
        }
        if m == "PUT" {
            check_incident(&d, Some(id))?;
            d.retain(|k, v| row.get(k) != Some(v));
            let seen = bo.get("_seen").filter(|v| !v.is_null()); // la versión que abrió quien guarda
            if !d.is_empty() {
                let mut args: Vec<SqlV> = d.values().map(db::jv).collect();
                args.push(SqlV::Integer(id));
                if let Some(s) = seen {
                    args.push(db::jv(s));
                }
                let cur = q(
                    &format!(
                        "UPDATE incidents SET {}, version=version+1 WHERE id=?{}",
                        d.keys().map(|k| format!("{k}=?")).collect::<Vec<_>>().join(", "),
                        if seen.is_some() { " AND version=?" } else { "" }
                    ),
                    args,
                )?;
                if cur.rowcount == 0 {
                    let who = q("SELECT who FROM log WHERE kind='incident' AND ref=? ORDER BY id DESC LIMIT 1", p![id])?.one();
                    let who = who.map(|w| w.s("who").to_string()).filter(|w| !w.is_empty()).unwrap_or("Alguien".into());
                    return Ok(err(409, &format!("{who} la cambió mientras la editabas.")));
                }
                let now = q(&format!("{INC} WHERE n.id=?"), p![id])?.one().unwrap_or_default();
                for k in d.keys() {
                    // cada cambio queda en el historial de la incidencia
                    let say = match k.as_str() {
                        "status" => format!("cambió el estado a «{}»", now.s("status")),
                        "priority" => format!("cambió la prioridad a «{}»", now.s("priority")),
                        "assignee" if now.t("assignee") => format!("asignó a {}", now.s("assignee_name")),
                        "assignee" => "quitó la persona asignada".into(),
                        "grp" if now.t("grp") => format!("pasó al grupo {}", now.s("grp_name")),
                        "grp" => "quitó el grupo".into(),
                        "item" if now.t("item") => format!("enlazó el equipo {}", now.s("item_name")),
                        "item" => "quitó el equipo".into(),
                        "title" => "cambió el título".into(),
                        "body" => "editó la descripción".into(),
                        "parent" if now.t("parent") => format!("la colgó de la incidencia INC-{}", now["parent"]),
                        _ => "la soltó de su incidencia padre".into(),
                    };
                    self.note(id, &say, true)?;
                }
                self.log("editar", "incident", id, &now["title"], &Value::Object(d.clone()))?;
            }
            let closed = match d.get("status").and_then(Value::as_str) {
                Some(s) if DONE.contains(&s) => self.close_children(id, s)?,
                _ => 0,
            };
            let mut out = q(&format!("{INC} WHERE n.id=?"), p![id])?.one().unwrap_or_default();
            out.insert("closed_children".into(), closed.into());
            return Ok(js(200, out));
        }
        if m == "DELETE" {
            if !self.admin {
                return Ok(err(403, "solo un administrador puede borrar incidencias"));
            }
            q("UPDATE incidents SET parent=NULL WHERE parent=?", p![id])?; // las hijas siguen, ya sin padre
            q("DELETE FROM notes WHERE incident=?", p![id])?;
            q("DELETE FROM incidents WHERE id=?", p![id])?;
            self.log("borrar", "incident", id, &row["title"], &Value::Object(row.clone()))?;
            return Ok(no_content());
        }
        Ok(err(405, "método no permitido"))
    }

    /// Uno o muchos (lista). Todo se valida antes de guardar nada. Sin contraseña se genera una provisional,
    /// que solo se devuelve en esta respuesta; con contraseña o sin ella, se pide cambiarla al entrar.
    fn create_users(&self, b: &Value) -> Result<Resp> {
        let batch: Vec<Value> = match b {
            Value::Array(a) => a.clone(),
            other => vec![other.clone()],
        };
        if !(1..=200).contains(&batch.len()) {
            return bad("de 1 a 200 usuarios a la vez");
        }
        let groups: HashSet<i64> = q("SELECT id FROM groups", p![])?.into_iter().filter_map(|r| r.i("id")).collect();
        let taken: HashSet<String> = q("SELECT name FROM users", p![])?.into_iter().map(|r| r.s("name").to_lowercase()).collect();
        let mut seen = HashSet::new();
        let mut names = vec![];
        for x in &batch {
            let name = match x.get("name") {
                Some(Value::String(s)) => s.clone(),
                Some(n @ Value::Number(_)) => n.to_string(),
                _ => String::new(),
            };
            if !re!(r"^[A-Za-z0-9._@-]{1,40}$").is_match(&name) {
                return bad(format!("nombre de usuario no válido: «{}» (letras, números y . _ @ -, hasta 40)", trunc(&name, 40)));
            }
            let k = name.to_lowercase();
            if taken.contains(&k) || seen.contains(&k) {
                return bad(format!("{}: {name}", if taken.contains(&k) { "ya existe" } else { "repetido en la lista" }));
            }
            seen.insert(k);
            if let Some(pw) = x.get("pass").filter(|p| !p.is_null()) {
                check_pass(pw)?;
            }
            let gs = x.get("groups").cloned().unwrap_or(json!([]));
            if !gs.as_array().is_some_and(|a| a.iter().all(|g| g.as_i64().is_some_and(|g| groups.contains(&g)))) {
                return bad(format!("{name}: grupo no válido"));
            }
            names.push(name);
        }
        let pws: Vec<String> = batch
            .iter()
            .map(|x| x.get("pass").and_then(Value::as_str).filter(|p| !p.is_empty()).map(String::from).unwrap_or_else(|| token_urlsafe(9)))
            .collect();
        let hashes = crate::util::par_map(&pws, 8, |pw| pw_hash(pw, None)); // PBKDF2 es lento a propósito: con 50 usuarios, en paralelo
        let mut out = vec![];
        for (((x, name), pw), h) in batch.iter().zip(&names).zip(&pws).zip(&hashes) {
            let admin = x.get("admin") == Some(&Value::Bool(true));
            let uid = match q("INSERT INTO users(name, hash, admin, must_change) VALUES(?,?,?,1)", p![name, h, admin]) {
                Ok(r) => r.lastrowid,
                Err(e) if is_constraint(&e) => return bad(format!("ya existe: {name}")),
                Err(e) => return Err(e),
            };
            let mut gs: Vec<i64> = x.get("groups").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_i64).collect();
            gs.sort();
            gs.dedup();
            for g in gs {
                q("INSERT INTO members(group_id, user_id) VALUES(?, ?)", p![g, uid])?;
            }
            self.log("crear", "user", uid, name, &json!({"admin": admin, "grupos": x.get("groups").cloned().unwrap_or(json!([]))}))?;
            let mut u = me(uid)?;
            u["pass"] = if x.get("pass").is_some_and(truthy) { Value::Null } else { pw.clone().into() };
            out.push(u);
        }
        Ok(js(201, if b.is_array() { Value::Array(out) } else { out.into_iter().next().unwrap_or_default() }))
    }

    fn account(&mut self, m: &str, res: &str, rid: Option<&str>) -> Result<Resp> {
        let ip = self.req.ip.clone();
        let b = if m == "POST" || m == "PUT" { self.body()? } else { json!({}) };
        if !b.is_object() && !(res == "users" && m == "POST" && b.is_array()) {
            return bad("envía un objeto");
        }
        let bs = |k: &str| b.get(k).map(py_str).unwrap_or_default();
        if res == "login" && m == "POST" {
            if throttled(&ip) {
                return Ok(err(429, "demasiados intentos: espera 15 minutos"));
            }
            let uid = match login_ok(&trunc(&bs("name"), 100), &trunc(&bs("pass"), 200), &trunc(&bs("code"), 10))? {
                Login::Ok(id) => id,
                other => {
                    failed(&ip); // también los códigos fallidos: 10 y fuera
                    return Ok(match other {
                        Login::NeedCode => js(
                            401,
                            json!({"error": if b.get("code").is_some_and(truthy) { "código incorrecto" } else { "escribe el código de tu app de autenticación" }, "totp": true}),
                        ),
                        _ => err(401, "usuario o contraseña incorrectos"),
                    });
                }
            };
            let tok = token_urlsafe(32);
            q("DELETE FROM sessions WHERE expires <= datetime('now')", p![])?;
            q("INSERT INTO sessions(token, user_id, expires) VALUES(?, ?, datetime('now', '+30 days'))", p![sha256_hex(&tok), uid])?;
            let secure = if CERT.is_empty() { "" } else { "; Secure" };
            return Ok(js(200, me(uid)?).header("Set-Cookie", format!("{}={tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000{secure}", *COOKIE)));
        }
        if res == "logout" && m == "POST" {
            q("DELETE FROM sessions WHERE token=?", p![&self.token])?;
            return Ok(no_content().header("Set-Cookie", format!("{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0", *COOKIE)));
        }
        let my_hash = || -> Result<String> { Ok(val("SELECT hash FROM users WHERE id=?", p![self.uid()])?.as_str().unwrap_or("").to_string()) };
        if res == "me" && m == "GET" && rid.is_none() {
            return Ok(js(200, me(self.uid())?));
        }
        if res == "me" && m == "POST" && rid == Some("password") {
            if !pw_ok(&bs("old"), &my_hash()?) {
                return Ok(err(400, "la contraseña actual no es correcta"));
            }
            let new = b.get("new").cloned().unwrap_or(Value::Null);
            check_pass(&new)?;
            if b.get("old") == Some(&new) {
                return bad("la nueva contraseña tiene que ser distinta");
            }
            q("UPDATE users SET hash=?, must_change=0 WHERE id=?", p![pw_hash(new.as_str().unwrap_or(""), None), self.uid()])?;
            q("DELETE FROM sessions WHERE user_id=? AND token != ?", p![self.uid(), &self.token])?; // cierra las demás sesiones
            lock(&BASIC).clear();
            self.log("cambiar contraseña", "user", self.uid(), &self.user, &json!({}))?;
            return Ok(no_content());
        }
        if res == "me" && m == "POST" && rid == Some("totp") {
            // verificación en dos pasos (app de autenticación)
            if b.get("off").is_some_and(truthy) {
                if !b.get("pass").and_then(Value::as_str).is_some_and(|p| pw_ok(p, &my_hash().unwrap_or_default())) {
                    return Ok(err(400, "la contraseña no es correcta"));
                }
                q("UPDATE users SET totp='' WHERE id=?", p![self.uid()])?;
                self.log("quitar 2FA", "user", self.uid(), &self.user, &json!({}))?;
                return Ok(js(200, me(self.uid())?));
            }
            let sec = b.get("secret").map(py_str).unwrap_or_default();
            if sec.is_empty() {
                // paso 1: un secreto nuevo para la app; no se guarda hasta confirmar un código
                let sec = data_encoding::BASE32.encode(&crate::crypto::rand_bytes(20));
                return Ok(js(200, json!({"secret": sec, "uri": format!("otpauth://totp/catlan:{}?secret={sec}&issuer=catlan", crate::util::quote(&self.user))})));
            }
            if !re!(r"^[A-Z2-7]{32}$").is_match(&sec) || !totp_ok(&sec, &bs("code")) {
                return Ok(err(400, "el código no coincide: revisa la hora del móvil y vuelve a probar"));
            }
            q("UPDATE users SET totp=? WHERE id=?", p![&sec, self.uid()])?;
            lock(&BASIC).clear(); // Basic ya no le vale
            self.log("activar 2FA", "user", self.uid(), &self.user, &json!({}))?;
            return Ok(js(200, me(self.uid())?));
        }
        if res != "users" {
            return Ok(err(405, "método no permitido"));
        }
        if m == "GET" && !self.admin {
            // para asignar incidencias: solo nombres
            return Ok(js(200, q("SELECT id, name FROM users ORDER BY name COLLATE NOCASE", p![])?.rows));
        }
        if !self.admin {
            return Ok(err(403, "solo para administradores"));
        }
        if m == "GET" {
            return Ok(js(200, q("SELECT id, name, admin, must_change, totp != '' AS totp, created FROM users ORDER BY name COLLATE NOCASE", p![])?.rows));
        }
        if m == "POST" && rid.is_none() {
            return self.create_users(&b);
        }
        let rid_i = rid.and_then(|r| r.parse::<i64>().ok()).unwrap_or(-1);
        let Some(row) = q("SELECT id, name FROM users WHERE id=?", p![rid_i])?.one() else { return Ok(err(404, "no existe")) };
        let id = row.i("id").unwrap_or(0);
        if Some(id) == self.uid && (m == "DELETE" || b.get("admin") == Some(&Value::Bool(false))) {
            return bad("no puedes quitarte el admin ni borrarte a ti mismo"); // así siempre queda un administrador
        }
        if m == "PUT" {
            if let Some(a) = b.get("admin") {
                q("UPDATE users SET admin=? WHERE id=?", p![*a == Value::Bool(true), id])?;
            }
            if b.get("totp") == Some(&Value::Bool(false)) {
                q("UPDATE users SET totp='' WHERE id=?", p![id])?; // perdió el móvil: un admin le quita la 2FA y la vuelve a activar al entrar
            }
            if let Some(pw) = b.get("pass") {
                check_pass(pw)?;
                q("UPDATE users SET hash=?, must_change=1 WHERE id=?", p![pw_hash(pw.as_str().unwrap_or(""), None), id])?;
                q("DELETE FROM sessions WHERE user_id=?", p![id])?;
                lock(&BASIC).clear();
            }
            self.log(
                "editar",
                "user",
                id,
                &row["name"],
                &json!({"admin": b.get("admin"), "contraseña": b.get("pass").is_some(), "quitar 2FA": b.get("totp") == Some(&Value::Bool(false))}),
            )?;
            return Ok(js(200, me(id)?));
        }
        if m == "DELETE" {
            q("DELETE FROM sessions WHERE user_id=?", p![id])?;
            q("DELETE FROM users WHERE id=?", p![id])?;
            q("DELETE FROM members WHERE user_id=?", p![id])?;
            q("DELETE FROM tasks WHERE user=?", p![id])?;
            q("UPDATE incidents SET assignee=NULL WHERE assignee=?", p![id])?;
            lock(&BASIC).clear();
            self.log("borrar", "user", id, &row["name"], &json!({}))?;
            return Ok(no_content());
        }
        Ok(err(405, "método no permitido"))
    }

    fn maps(&mut self, m: &str, rid: Option<&str>, rid_i: i64, sub: Option<&str>, qs: &HashMap<String, Vec<String>>) -> Result<Resp> {
        if m == "GET" && rid.is_none() {
            return Ok(js(
                200,
                q(
                    "SELECT id, name, json_extract(data, '$.type') AS type, json_extract(data, '$.height') AS height, \
                     COALESCE(json_array_length(data, '$.devices'), json_array_length(data, '$.nodes'), 0) AS n \
                     FROM maps ORDER BY name COLLATE NOCASE",
                    p![],
                )?
                .rows,
            ));
        }
        if m == "POST" && rid.is_none() {
            // cuerpo vacío = lienzo en blanco, si no, imagen de fondo
            let mime = self.req.header("content-type").split(';').next().unwrap_or("").trim().to_string();
            let img = self.req.body.clone();
            if !img.is_empty() && !IMAGE_TYPES.contains(&mime.as_str()) {
                return Ok(err(400, "sube una imagen (png, jpg, gif, webp, svg)"));
            }
            let name = trunc(qs.get("name").map_or("Mapa", |v| v[0].as_str()), 200);
            let data = if qs.get("type").is_some_and(|t| t == &["rack"]) { json!({"type": "rack"}) } else { json!({}) };
            let id = q("INSERT INTO maps(name, mime, image, data) VALUES(?,?,?,?)", p![&name, if img.is_empty() { "" } else { &mime }, img, data.to_string()])?.lastrowid;
            self.log("crear", data.get("type").and_then(Value::as_str).unwrap_or("map"), id, &name, &json!({"name": name, "data": data}))?;
            return Ok(js(201, json!({"id": id, "name": name})));
        }
        if m == "GET" && sub == Some("image") {
            let Some((mime, image)) = db::blob("SELECT mime, image FROM maps WHERE id=?", p![rid_i])?.filter(|(_, i)| !i.is_empty()) else {
                return Ok(err(404, "no existe"));
            };
            // CSP bloquea scripts dentro de SVG subidos si se abren directamente
            return Ok(Resp::new(200, image, &mime).header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'"));
        }
        if m == "GET" && rid.is_some() {
            return Ok(match q("SELECT id, name, data, version, length(image) > 0 AS has_image FROM maps WHERE id=?", p![rid_i])?.one() {
                Some(mut r) => {
                    let d: Value = serde_json::from_str(r.s("data")).unwrap_or(json!({}));
                    r.insert("data".into(), d);
                    js(200, r)
                }
                None => err(404, "no existe"),
            });
        }
        if m == "PUT" && rid.is_some() {
            let d = self.body()?;
            let d = obj(&d)?;
            let name = d.get("name").cloned().unwrap_or("".into());
            let data = d.get("data").cloned().unwrap_or(json!({}));
            if !name.is_string() || !data.is_object() {
                return bad("name debe ser texto y data un objeto");
            }
            if data.s("type") == "rack" {
                check_rack(obj(&data)?)?;
            }
            let seen = d.get("_seen").filter(|v| !v.is_null()); // la versión que abrió quien guarda: si otro guardó antes, 409 (atómico)
            let mut sets = vec![];
            let mut args = vec![];
            let name = trunc(name.as_str().unwrap_or(""), 200);
            if !name.is_empty() {
                sets.push("name=?, ");
                args.push(SqlV::Text(name));
            }
            if d.contains_key("data") {
                sets.push("data=?, ");
                args.push(SqlV::Text(data.to_string()));
            }
            args.push(SqlV::Integer(rid_i));
            if let Some(s) = seen {
                args.push(db::jv(s));
            }
            let cur = q(&format!("UPDATE maps SET {}version=version+1 WHERE id=?{}", sets.concat(), if seen.is_some() { " AND version=?" } else { "" }), args)?;
            if cur.rowcount == 0 {
                let Some(row) = q("SELECT version FROM maps WHERE id=?", p![rid_i])?.one() else { return Ok(err(404, "no existe")) };
                let who = q("SELECT who FROM log WHERE kind IN ('map', 'rack') AND ref=? ORDER BY id DESC LIMIT 1", p![rid_i])?.one();
                let who = who.map(|w| w.s("who").to_string()).filter(|w| !w.is_empty()).unwrap_or("Alguien".into());
                return Ok(js(409, json!({"error": format!("{who} lo cambió mientras lo editabas."), "version": row["version"]})));
            }
            self.log_map("editar", rid_i)?;
            return Ok(js(200, json!({"version": val("SELECT version FROM maps WHERE id=?", p![rid_i])?})));
        }
        if m == "DELETE" && rid.is_some() {
            self.log_map("borrar", rid_i)?;
            q("DELETE FROM maps WHERE id=?", p![rid_i])?;
            return Ok(no_content());
        }
        Ok(err(405, "método no permitido"))
    }

    fn sounds(&mut self, m: &str, rid: Option<&str>, rid_i: i64, sub: Option<&str>, qs: &HashMap<String, Vec<String>>) -> Result<Resp> {
        if m == "GET" && rid.is_none() {
            return Ok(js(200, q("SELECT id, name FROM sounds ORDER BY id", p![])?.rows));
        }
        if m == "POST" && rid.is_none() {
            let mime = self.req.header("content-type").split(';').next().unwrap_or("").trim().to_string();
            let data = self.req.body.clone();
            if !AUDIO_TYPES.contains(&mime.as_str()) || data.is_empty() || data.len() > 3 * 1024 * 1024 {
                return Ok(err(400, "sube un audio (mp3, wav, ogg, m4a) de hasta 3 MB"));
            }
            let name = trunc(qs.get("name").map_or("Alerta", |v| v[0].as_str()), 100);
            let id = q("INSERT INTO sounds(name, mime, data) VALUES(?,?,?)", p![&name, &mime, data])?.lastrowid;
            return Ok(js(201, json!({"id": id, "name": name})));
        }
        if m == "GET" && sub == Some("audio") {
            return Ok(match db::blob("SELECT mime, data FROM sounds WHERE id=?", p![rid_i])? {
                Some((mime, data)) => Resp::new(200, data, &mime),
                None => err(404, "no existe"),
            });
        }
        if m == "DELETE" && rid.is_some() {
            q("DELETE FROM sounds WHERE id=?", p![rid_i])?;
            q("UPDATE checks SET sound='' WHERE sound=?", p![format!("u:{}", rid.unwrap_or(""))])?; // quien lo usaba vuelve al sonido general
            return Ok(no_content());
        }
        Ok(err(405, "método no permitido"))
    }

    fn log_map(&self, action: &str, rid: i64) -> Result<()> {
        if let Some(row) = q("SELECT id, name, data FROM maps WHERE id=?", p![rid])?.one() {
            let data: Value = serde_json::from_str(row.s("data")).unwrap_or(json!({}));
            let kind = if data.s("type") == "rack" { "rack" } else { "map" };
            self.log(action, kind, &row["id"], &row["name"], &json!({"name": row["name"], "data": data}))?;
        }
        Ok(())
    }
}

fn hours(qs: &HashMap<String, Vec<String>>) -> Result<i64> {
    let h: i64 = qs.get("hours").map_or("24", |v| v[0].as_str()).parse().map_err(|_| Bad("horas no válidas".into()))?;
    Ok(h.clamp(1, monitor::MAX_HOURS))
}

/// Dónde aparece un equipo: páginas/notas con [[#id]] y esquemas/racks que lo enlazan.
fn refs(item: i64) -> Result<Value> {
    let tag = format!("%[[#{item}]]%");
    let in_map = "EXISTS (SELECT 1 FROM json_each(data, ?) WHERE json_extract(value, '$.item') = ?)";
    Ok(json!({
        "pages": q("SELECT id, title FROM pages WHERE body LIKE ? ORDER BY title", p![&tag])?.rows,
        "items": q("SELECT id, name FROM items WHERE notes LIKE ? AND id != ? ORDER BY name", p![&tag, item])?.rows,
        "maps": q(&format!("SELECT id, name, json_extract(data, '$.type') AS type FROM maps WHERE {in_map} OR {in_map} ORDER BY name"),
                  p!["$.nodes", item, "$.devices", item])?.rows,
        "incidents": q("SELECT id, title, status FROM incidents WHERE item=? ORDER BY id DESC", p![item])?.rows,
        "expiries": q("SELECT id, name, kind, date FROM expiries WHERE item=? ORDER BY date", p![item])?.rows,
        "agent": val("SELECT id FROM agents WHERE item=? AND state='adoptado' ORDER BY id DESC LIMIT 1", p![item])?,
    }))
}

/// `catlan restablecer <usuario>`: contraseña olvidada. Desde el servidor, que ya tiene la base de datos:
/// contraseña provisional (a cambiar al entrar), sin verificación en dos pasos y con sus sesiones cerradas.
pub fn reset_password(name: &str) -> Result<i32> {
    let u = if name.is_empty() { None } else { q("SELECT id, name FROM users WHERE name=?", p![name])?.one() };
    let Some(u) = u else {
        let names: Vec<String> = q("SELECT name, admin FROM users ORDER BY name COLLATE NOCASE", p![])?
            .into_iter()
            .map(|r| format!("{}{}", r.s("name"), if r.t("admin") { " (admin)" } else { "" }))
            .collect();
        let pre = if name.is_empty() { String::new() } else { format!("No existe el usuario «{name}». ") };
        println!("{pre}Usuarios en {}: {}\nUso: catlan restablecer <usuario>", DATA.join("catlan.db").display(), names.join(", "));
        return Ok(1);
    };
    let pw = token_urlsafe(9);
    q("UPDATE users SET hash=?, must_change=1, totp='' WHERE id=?", p![pw_hash(&pw, None), &u["id"]])?;
    q("DELETE FROM sessions WHERE user_id=?", p![&u["id"]])?;
    q(
        "INSERT INTO log(who, action, kind, ref, name, data) VALUES('consola del servidor', 'restablecer contraseña', 'user', ?, ?, '{}')",
        p![&u["id"], &u["name"]],
    )?;
    println!(
        "Contraseña provisional de {}: {pw}\nEntra con ella y catlan te pedirá cambiarla. Su verificación en dos pasos queda quitada.\n(Base de datos: {})",
        u.s("name"),
        DATA.join("catlan.db").display()
    );
    Ok(0)
}
