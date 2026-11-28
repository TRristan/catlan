//! Kitty: el instalador, el programa, lo que envía cada PC (sin sesión, con su clave) y aceptar u olvidar equipos.
use super::{Ctx, Login, Perm, Route, err, failed, js, login_ok, no_content, r, throttled};
use crate::config::{DATA, scheme};
use crate::crypto::sha256_hex;
use crate::db::{self, SqlV, q, val};
use crate::monitor::{self, SOURCES};
use crate::p;
use crate::server::Resp;
use crate::util::{J, Row, bad, is_int, lock, obj, py_str, trunc, truthy};
use crate::validate::{INC_PRIO, host_ok};
use anyhow::Result;
use serde_json::{Map, Value, json};
use std::sync::{LazyLock, Mutex};

/// Lo que Kitty cuenta de su equipo.
const AGENT_FACTS: [&str; 5] = ["name", "ip", "serial", "os", "kind"];
const KITTY_PS1: &str = include_str!("../../kitty/kitty.ps1");
const KITTY_SH: &str = include_str!("../../kitty/kitty.sh");

pub fn routes() -> Vec<Route> {
    vec![
        r("GET", "/kitty.exe", Perm::Free, Ctx::kitty_exe),
        r("GET", "/kitty.json", Perm::Free, Ctx::kitty_json),
        r("GET", "/kitty.ps1", Perm::Free, Ctx::kitty_script),
        r("GET", "/kitty.sh", Perm::Free, Ctx::kitty_script),
        r("POST", "/api/agent", Perm::Free, Ctx::agent_hello),
        r("POST", "/api/agent/incident", Perm::Free, Ctx::agent_incident),
        r("POST", "/api/agent/mine", Perm::Free, Ctx::agent_mine),
        r("POST", "/api/agent/quit", Perm::Free, Ctx::agent_quit),
        r("POST", "/api/agent/thread", Perm::Free, Ctx::agent_thread),
        r("POST", "/api/agent/reply", Perm::Free, Ctx::agent_reply),
        r("POST", "/api/agent/help", Perm::Free, Ctx::agent_help),
        r("POST", "/api/agent/{other}", Perm::Free, |_| Ok(err(404, "no existe"))),
        // aceptar un Kitty es dejar entrar un equipo
        r("GET", "/api/agents", Perm::Admin, Ctx::agents_list),
        r("PUT", "/api/agents/{id}", Perm::Admin, Ctx::agent_state),
        r("DELETE", "/api/agents/{id}", Perm::Admin, Ctx::agent_forget),
        r("POST", "/api/items/{id}/wake", Perm::User, Ctx::item_wake),
        r("GET", "/api/software", Perm::User, Ctx::software_list),
        r("PUT", "/api/software", Perm::Admin, Ctx::software_policy),
    ]
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

/// El Kitty de la clave de incidencias, si ya lo aceptaron. Si no, la respuesta que toca.
pub fn agent_by_ukey(u: &str) -> Result<std::result::Result<Row, Resp>> {
    if !(32..=128).contains(&u.chars().count()) {
        return bad("falta la clave de Kitty");
    }
    Ok(match q("SELECT * FROM agents WHERE ukey=? ORDER BY id DESC LIMIT 1", p![sha256_hex(u)])?.one() {
        Some(a) if a.s("state") == "adoptado" => Ok(a),
        Some(a) => Err(js(403, json!({"error": if a.s("state") == "pendiente" { "IT todavía no ha aceptado este equipo en catlan" } else { "catlan ha rechazado este equipo" }, "state": a["state"]}))),
        None => Err(js(404, json!({"error": "este equipo aún no se ha presentado a catlan: espera unos minutos", "state": null}))),
    })
}

/// Paquete mágico de Wake-on-LAN: 6 × FF y 16 veces la MAC. None si la MAC no es válida.
fn magic(mac: &str) -> Option<Vec<u8>> {
    let b: Vec<u8> = mac.split([':', '-']).map(|h| u8::from_str_radix(h, 16)).collect::<std::result::Result<_, _>>().ok()?;
    (b.len() == 6).then(|| [vec![0xFF; 6], b.repeat(16)].concat())
}

/// Política: ¿Kitty cuenta los programas instalados? Apagado si nadie lo activa.
fn software_on() -> bool {
    val("SELECT v FROM meta WHERE k='software'", p![]).ok().and_then(|v| v.as_str().map(|s| s == "1")).unwrap_or(false)
}

/// Lo que manda Kitty: [{name, version, publisher}], sin vacíos ni repetidos. None si no tiene esa forma.
fn software_rows(v: &Value) -> Option<Vec<(String, String, String)>> {
    let a = v.as_array().filter(|a| a.len() <= 5000)?;
    let mut out: Vec<(String, String, String)> = a
        .iter()
        .filter_map(|x| {
            let s = |k: &str| trunc(x.get(k).and_then(Value::as_str).unwrap_or("").trim(), 200);
            Some((s("name"), s("version"), s("publisher"))).filter(|r| !r.0.is_empty())
        })
        .collect();
    out.sort();
    out.dedup();
    Some(out)
}

/// Las incidencias de «Mis avisos»: las abiertas desde la Kitty de este equipo (?1 el equipo, ?2 el nombre del PC).
const MINE: &str = "EXISTS (SELECT 1 FROM notes o WHERE o.incident = n.id AND o.change = 1 AND o.text = 'abrió la incidencia' AND o.who = 'Kitty · ' || ?2)";
/// Las notas que ve el usuario del PC: las públicas (las suyas lo son siempre).
const SEEN: &str = "change = 0 AND public = 1";

/// La clave de incidencias del cuerpo (la ventana de Kitty corre como el usuario del PC y no puede leer la del equipo).
pub fn ukey(b: &Value) -> &str {
    b.as_object().and_then(|o| o.get("ukey")).and_then(Value::as_str).unwrap_or("")
}

impl Ctx {
    fn kitty_exe(&mut self) -> Result<Resp> {
        if !self.req.secure {
            return Ok(err(403, "kitty.exe solo se reparte por https")); // en claro, cualquiera en la red lo cambiaría por otro
        }
        Ok(match kitty_exe().map(std::fs::read) {
            Some(Ok(b)) => Resp::new(200, b, "application/vnd.microsoft.portable-executable").header("Content-Disposition", "attachment; filename=\"kitty.exe\""),
            _ => Resp::new(404, "catlan no tiene kitty.exe: ponlo junto al ejecutable de catlan o en su carpeta de datos".as_bytes().to_vec(), "text/plain; charset=utf-8"),
        })
    }

    /// Kitty sin instalar busca catlan en la red: así sabe que aquí hay uno (sin sesión, solo el id público).
    /// «kitty»: el sha256 del kitty.exe que reparte; las Kitty instaladas con otro se actualizan solas
    /// «pin» y «spki»: la huella del certificado autofirmado, para anclarlo (vacías por un proxy o con certificado propio).
    /// En claro no se anuncia ningún kitty.exe: una Kitty antigua no se actualiza por http.
    fn kitty_json(&mut self) -> Result<Resp> {
        let (pin, spki) = self.pins();
        let hash = if self.req.secure { kitty_hash() } else { String::new() };
        Ok(js(200, json!({"catlan": db::INSTANCE.get().map_or("", |s| s.as_str()), "kitty": hash, "pin": pin, "spki": spki})))
    }

    /// Instalador de Kitty (Windows o Linux) con esta dirección y este id, sin sesión.
    fn kitty_script(&mut self) -> Result<Resp> {
        let host = self.req.header("host");
        if !host_ok(host) {
            return Ok(Resp::new(400, b"Host no valido".to_vec(), "text/plain; charset=utf-8")); // va dentro de un script que se ejecuta como administrador
        }
        let ps = if self.req.path.starts_with("/kitty.sh") { KITTY_SH.replace("\r\n", "\n") } else { KITTY_PS1.to_string() }; // un clon de Git en Windows lo deja con CRLF
        let (pin, spki) = self.pins();
        let ps = ps
            .replace("{{URL}}", &format!("{}://{host}", scheme()))
            .replace("{{ID}}", db::INSTANCE.get().map_or("", |s| s.as_str()))
            .replace("{{PIN}}", pin)
            .replace("{{SPKI}}", spki)
            .replace("{{SHA}}", &kitty_hash().to_uppercase());
        Ok(Resp::new(200, ps.into_bytes(), "text/plain; charset=utf-8"))
    }

    /// El Kitty de la clave de incidencias del cuerpo.
    fn agent_of(&self, b: &Value) -> Result<std::result::Result<Row, Resp>> {
        agent_by_ukey(ukey(b))
    }

    /// Kitty se presenta con su clave: pendiente hasta que un admin lo acepta; aceptado, catlan mantiene su ficha.
    fn agent_hello(&mut self) -> Result<Resp> {
        let b = self.body()?;
        let key = b.as_object().and_then(|o| o.get("key")).and_then(Value::as_str).filter(|k| (32..=128).contains(&k.chars().count()));
        let Some(key) = key else { return bad("falta la clave de Kitty") };
        let mut f: Map<String, Value> = AGENT_FACTS.iter().map(|k| (k.to_string(), Value::from(trunc(b.get(*k).and_then(Value::as_str).unwrap_or("").trim(), 100)))).collect();
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
        let (out, mut info) = crate::health::kitty_read(f.s("name"), b.get("facts").unwrap_or(&Value::Null));
        let prev: Value = serde_json::from_str::<Value>(src.s("info")).ok().and_then(|i| i.get("events").cloned()).unwrap_or(Value::Null);
        let (events, mut probs) = crate::health::kitty_events(b.get("events").unwrap_or(&Value::Null), &prev);
        info.insert("events".into(), events.into());
        probs.extend(crate::health::kitty_patch_problem(&info));
        let (light, why) = crate::health::kitty_security(&info);
        info.insert("seclight".into(), light.into());
        info.insert("secwhy".into(), why.into());
        if let Some(a) = b.get("apps").filter(|a| a.is_object() && a.to_string().len() <= 64 * 1024) {
            info.insert("apps".into(), a.clone()); // cómo le fue a winget con cada programa
        }
        let on = software_on();
        if on && let Some(rows) = b.get("software").and_then(software_rows) {
            let mut c = lock(db::writer());
            let tx = c.transaction()?;
            tx.execute("DELETE FROM software WHERE item=?", [item])?;
            for r in &rows {
                tx.execute("INSERT INTO software(item, name, version, publisher) VALUES(?, ?, ?, ?)", rusqlite::params![item, r.0, r.1, r.2])?;
            }
            tx.commit()?;
        }
        // «software»: null si la política no lo pide; si no, cuántos tiene catlan de este PC (Kitty los reenvía si no cuadra)
        let have = if on { val("SELECT COUNT(*) FROM software WHERE item=?", p![item])? } else { Value::Null };
        let out = crate::health::limits(&src, out, &mut probs);
        monitor::save_health(&src, &out, &probs, Some(&info), None)?;
        let apps: Vec<Value> = q("SELECT winget FROM apps ORDER BY id", p![])?.into_iter().map(|r| r["winget"].clone()).collect();
        let run = super::pcs::agent_runs(&a["id"], b.get("runs"))?;
        Ok(js(200, json!({"state": "adoptado", "item": item, "catlan": instance, "apps": apps, "software": have, "run": run})))
    }

    /// Encender un PC apagado: el paquete mágico a cada MAC que mandó su Kitty, por difusión general y a la de su /24.
    /// shortcut: solo llega a la red de catlan (o a la /24 del PC si el router reenvía difusiones dirigidas); para otras redes haría falta un relé.
    fn item_wake(&mut self) -> Result<Resp> {
        let Some(it) = q("SELECT id, name, ip FROM items WHERE id=?", p![self.id()])?.one() else { return Ok(err(404, "no existe")) };
        let info = q("SELECT s.info FROM agents a JOIN sources s ON s.id = a.source WHERE a.item=? ORDER BY a.id DESC LIMIT 1", p![&it["id"]])?.one();
        let macs: Vec<String> = info
            .and_then(|r| serde_json::from_str::<Value>(r.s("info")).ok())
            .and_then(|i| i.get("macs").and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect()))
            .unwrap_or_default();
        let packets: Vec<Vec<u8>> = macs.iter().filter_map(|m| magic(m)).collect();
        if packets.is_empty() {
            return bad("no se sabe la MAC de este equipo: hace falta que Kitty la haya enviado al menos una vez");
        }
        let sock = std::net::UdpSocket::bind("0.0.0.0:0")?;
        sock.set_broadcast(true)?;
        let mut to = vec!["255.255.255.255:9".to_string()];
        if let Ok(std::net::IpAddr::V4(ip)) = it.s("ip").parse::<std::net::IpAddr>() {
            let o = ip.octets();
            to.push(format!("{}.{}.{}.255:9", o[0], o[1], o[2]));
        }
        for pk in &packets {
            for t in &to {
                let _ = sock.send_to(pk, t); // una red sin ruta no impide probar la otra
            }
        }
        self.log("encender", "item", &it["id"], &it["name"], &json!({"macs": macs}))?;
        Ok(js(200, json!({"macs": macs})))
    }

    /// Programas instalados: ?item=N los de un PC; ?q=texto, quién tiene un programa (hasta 300). «on»: la política.
    fn software_list(&mut self) -> Result<Resp> {
        let arg = |k: &str| self.qs.get(k).map(|v| v[0].trim().to_string()).unwrap_or_default();
        let (item, text) = (arg("item"), arg("q"));
        let rows = if !item.is_empty() {
            q("SELECT name, version, publisher FROM software WHERE item=? ORDER BY name COLLATE NOCASE", p![item.parse::<i64>().unwrap_or(-1)])?.rows
        } else if text.chars().count() >= 2 {
            let like = format!("%{}%", text.replace('!', "!!").replace('%', "!%").replace('_', "!_"));
            q(
                "SELECT s.item, i.name AS item_name, s.name, s.version FROM software s JOIN items i ON i.id = s.item \
                 WHERE s.name LIKE ? ESCAPE '!' ORDER BY s.name COLLATE NOCASE, i.name COLLATE NOCASE LIMIT 300",
                p![like],
            )?
            .rows
        } else {
            vec![]
        };
        Ok(js(200, json!({"on": software_on(), "rows": rows})))
    }

    /// Activar o apagar el inventario de programas. Al apagarlo se borra lo que había: no se guarda lo que no se pide.
    fn software_policy(&mut self) -> Result<Resp> {
        let on = self.body()?.get("on").and_then(Value::as_bool).ok_or(crate::util::Bad("on: true o false".into()))?;
        q("INSERT OR REPLACE INTO meta(k, v) VALUES('software', ?)", p![if on { "1" } else { "0" }])?;
        if !on {
            q("DELETE FROM software", p![])?;
        }
        self.log(if on { "activar" } else { "desactivar" }, "software", 0, "Inventario de programas", &json!({}))?;
        Ok(js(200, json!({"on": on})))
    }

    /// Las incidencias que se abrieron desde la ventana de Kitty de este equipo, con su estado.
    fn agent_mine(&mut self) -> Result<Resp> {
        let b = self.body()?;
        let a = match self.agent_of(&b)? {
            Ok(a) => a,
            Err(r) => return Ok(r),
        };
        // «notes»: las que ve el usuario; «last_it»: la última de IT (Kitty avisa si no la ha visto)
        let rows = q(
            &format!(
                "SELECT n.id, n.title, n.status, n.priority, n.created, n.updated, (SELECT count(*) FROM notes WHERE incident = n.id AND {SEEN}) AS notes, \
                 (SELECT max(id) FROM notes WHERE incident = n.id AND {SEEN} AND who != 'Kitty · ' || ?2) AS last_it \
                 FROM incidents n WHERE n.item=?1 AND {MINE} ORDER BY n.status IN ('resuelta', 'cerrada'), n.updated DESC LIMIT 30"
            ),
            p![&a["item"], &a["name"]],
        )?;
        let notices = q(
            "SELECT id, text, until, created FROM notices WHERE until > CURRENT_TIMESTAMP AND (items = '[]' OR EXISTS (SELECT 1 FROM json_each(items) WHERE value = ?)) ORDER BY id DESC LIMIT 5",
            p![&a["item"]],
        )?;
        Ok(js(200, json!({"state": a["state"], "name": a["name"], "item": a["item"], "incidents": rows.rows, "notices": notices.rows})))
    }

    /// Una incidencia de «Mis avisos» con lo que ve el usuario: su descripción y las notas públicas (las suyas y las que IT marca).
    fn agent_thread(&mut self) -> Result<Resp> {
        let b = self.body()?;
        let a = match self.agent_of(&b)? {
            Ok(a) => a,
            Err(r) => return Ok(r),
        };
        let Some(inc) = Self::mine_incident(&a, &b)? else { return Ok(err(404, "esa incidencia no es de este equipo")) };
        let notes = q(&format!("SELECT id, who, ts, text FROM notes WHERE incident=? AND {SEEN} ORDER BY id"), p![&inc["id"]])?;
        Ok(js(200, json!({"incident": inc, "notes": notes.rows})))
    }

    /// El usuario del PC contesta desde Kitty: una nota pública en su incidencia (como mucho 30 por hora desde cada equipo).
    fn agent_reply(&mut self) -> Result<Resp> {
        let b = self.body()?;
        let a = match self.agent_of(&b)? {
            Ok(a) => a,
            Err(r) => return Ok(r),
        };
        let Some(inc) = Self::mine_incident(&a, &b)? else { return Ok(err(404, "esa incidencia no es de este equipo")) };
        let text = b.get("text").and_then(Value::as_str).map(str::trim).filter(|t| (1..=5000).contains(&t.chars().count()));
        let Some(text) = text else { return bad("escribe la respuesta (hasta 5000 caracteres)") };
        self.user = format!("Kitty · {}", a.s("name"));
        if val("SELECT COUNT(*) FROM notes WHERE who=? AND change = 0 AND ts > datetime('now', '-1 hour')", p![&self.user])?.as_i64().unwrap_or(0) >= 30 {
            return Ok(err(429, "demasiados mensajes seguidos: espera un rato"));
        }
        q("INSERT INTO notes(incident, who, text, change, public) VALUES(?, ?, ?, 0, 1)", p![&inc["id"], &self.user, text])?;
        q("UPDATE incidents SET updated=CURRENT_TIMESTAMP WHERE id=?", p![&inc["id"]])?;
        Ok(js(201, json!({"ok": true})))
    }

    /// Autoayuda: las páginas de la wiki marcadas para Kitty que hablan de lo que escribe el usuario (hasta 3).
    fn agent_help(&mut self) -> Result<Resp> {
        let b = self.body()?;
        if let Err(r) = self.agent_of(&b)? {
            return Ok(r);
        }
        let text = b.get("q").and_then(Value::as_str).unwrap_or("").to_lowercase();
        let words: Vec<String> = text.split(|c: char| !c.is_alphanumeric()).filter(|w| w.chars().count() >= 4).take(8).map(String::from).collect();
        if words.is_empty() {
            return Ok(js(200, json!({"pages": []})));
        }
        // cada palabra en el título cuenta 3; en el texto, 1
        let score: Vec<&str> = words.iter().map(|_| "(instr(lower(title), ?) > 0) * 3 + (instr(lower(body), ?) > 0)").collect();
        let args: Vec<SqlV> = words.iter().flat_map(|w| [SqlV::Text(w.clone()), SqlV::Text(w.clone())]).collect();
        let sql = format!("SELECT id, title, substr(body, 1, 4000) AS body, {} AS score FROM pages WHERE kitty = 1 AND score > 0 ORDER BY score DESC, title LIMIT 3", score.join(" + "));
        Ok(js(200, json!({"pages": q(&sql, args)?.rows})))
    }

    /// La incidencia del cuerpo («id»), si se abrió desde la Kitty de este equipo.
    fn mine_incident(a: &Row, b: &Value) -> Result<Option<Row>> {
        let id = b.get("id").filter(|v| is_int(v)).and_then(Value::as_i64).unwrap_or(-1);
        Ok(q(&format!("SELECT n.id, n.title, n.body, n.status, n.created, n.updated FROM incidents n WHERE n.id=?3 AND n.item=?1 AND {MINE}"), p![&a["item"], &a["name"], id])?.one())
    }

    /// Cerrar la Kitty de un PC: solo con un administrador de catlan (el usuario del PC no puede quitarla).
    /// Mismo límite de intentos que el login; no abre sesión.
    fn agent_quit(&mut self) -> Result<Resp> {
        let b = self.body()?;
        let a = match self.agent_of(&b)? {
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
        let a = match self.agent_of(&b)? {
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
        // captura de pantalla opcional: un JPEG en base64 (hasta 6 MB)
        let shot = match b.get("shot").and_then(Value::as_str).filter(|s| !s.is_empty()) {
            None => None,
            Some(s) => match data_encoding::BASE64.decode(s.as_bytes()).ok().filter(|j| j.len() <= 6 << 20 && j.starts_with(&[0xFF, 0xD8, 0xFF])) {
                Some(j) => Some(j),
                None => return bad("la captura no es un JPEG válido o pasa de 6 MB"),
            },
        };
        let id = q("INSERT INTO incidents(title, body, priority, item) VALUES(?, ?, ?, ?)", p![title, body, prio, &a["item"]])?.lastrowid;
        self.note(id, "abrió la incidencia", true)?;
        if let Some(j) = shot {
            let fid = q("INSERT INTO files(incident, name, mime, data, who) VALUES(?, ?, 'image/jpeg', ?, ?)", p![id, format!("captura-INC-{id}.jpg"), j, &self.user])?.lastrowid;
            q("INSERT INTO notes(incident, who, text, change, public) VALUES(?, ?, ?, 0, 1)", p![id, &self.user, format!("Captura de pantalla adjunta: [ver captura](/api/files/{fid})")])?;
        }
        self.log("crear", "incident", id, title, &json!({"title": title, "body": body, "priority": prio, "item": a["item"], "desde": "Kitty"}))?;
        if prio == "crítica" {
            monitor::notify(&format!("catlan: incidencia crítica INC-{id}: {title}"), &format!("Abierta desde Kitty en {}.\n\n-- catlan", a.s("name")));
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
        if let Some(s) = a.i("source")
            && !q("SELECT 1 FROM sources WHERE id=? AND kind='kitty'", p![s])?.is_empty()
        {
            for (t, col) in [("sources", "id"), ("metrics", "source_id"), ("metrics_h", "source_id")] {
                q(&format!("DELETE FROM {t} WHERE {col}=?"), p![s])?;
            }
        }
        q("UPDATE agents SET source=NULL WHERE id=?", p![&a["id"]])?;
        Ok(())
    }

    fn agents_list(&mut self) -> Result<Resp> {
        let rows: Vec<Row> = q("SELECT * FROM agents ORDER BY state != 'pendiente', name COLLATE NOCASE", p![])?
            .into_iter()
            .map(|mut r| {
                let code = trunc(r.s("key"), 8);
                r.shift_remove("key");
                r.insert("code".into(), code.into());
                r
            })
            .collect();
        Ok(js(200, rows))
    }

    fn agent_state(&mut self) -> Result<Resp> {
        let Some(a) = q("SELECT * FROM agents WHERE id=?", p![self.id()])?.one() else { return Ok(err(404, "no existe")) };
        let code = trunc(a.s("key"), 8);
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
        Ok(js(200, json!({"state": st, "item": item})))
    }

    /// Olvidarlo: si sigue instalado, volverá a pedir entrada.
    fn agent_forget(&mut self) -> Result<Resp> {
        let Some(a) = q("SELECT * FROM agents WHERE id=?", p![self.id()])?.one() else { return Ok(err(404, "no existe")) };
        let code = trunc(a.s("key"), 8);
        Self::drop_source(&a)?;
        q("DELETE FROM agents WHERE id=?", p![&a["id"]])?;
        self.log("olvidar", "agent", &a["id"], &a["name"], &json!({"ip": a["ip"], "code": code}))?;
        Ok(no_content())
    }
}

#[test]
fn paquete_magico() {
    let m = magic("00:1A:2b:3C:4d:5E").unwrap();
    assert_eq!((m.len(), &m[..6], &m[6..12], &m[96..]), (102, &[0xFF; 6][..], &[0, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E][..], &[0, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E][..]));
    assert!(magic("00-1A-2B-3C-4D-5E").is_some() && magic("zz:1A:2B:3C:4D:5E").is_none() && magic("00:1A").is_none());
}
