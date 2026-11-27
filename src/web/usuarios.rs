//! Usuarios y grupos: entrar y salir, la cuenta propia (contraseña, 2FA) y, para los administradores, gestionar
//! usuarios, grupos, copias de seguridad, borrar la base de datos y actualizar catlan.
use super::{BASIC, Ctx, Login, Perm, Route, err, failed, js, login_ok, no_content, r, readonly, throttled};
use crate::config::{COOKIE, DATA};
use crate::crypto::{pw_hash, pw_ok, seal, sha256_hex, token_hex, token_urlsafe, totp_ok};
use crate::db::{self, is_constraint, q, val};
use crate::health;
use crate::server::Resp;
use crate::util::{J, bad, is_int, lock, py_str, trunc, truthy};
use crate::validate::check_pass;
use crate::{p, re};
use anyhow::Result;
use serde_json::{Value, json};
use std::collections::HashSet;

/// Lo que se vacía al «Borrar la base de datos»: todo el contenido. Quedan los usuarios, los grupos, las sesiones y el id
/// de la instalación (los Kitty instalados vuelven a pedir entrar aquí).
const WIPE: &[&str] = &[
    "pages",
    "items",
    "maps",
    "log",
    "checks",
    "pings",
    "pings_h",
    "sounds",
    "sources",
    "metrics",
    "metrics_h",
    "dash",
    "incidents",
    "notes",
    "agents",
    "expiries",
    "syslog",
    "subnets",
    "tasks",
    "apps",
];

pub fn routes() -> Vec<Route> {
    vec![
        r("POST", "/api/login", Perm::Free, Ctx::login),
        r("POST", "/api/logout", Perm::Pending, Ctx::logout),
        r("GET", "/api/me", Perm::Pending, Ctx::me_get),
        r("POST", "/api/me/password", Perm::Pending, Ctx::me_password),
        r("POST", "/api/me/totp", Perm::User, Ctx::me_totp),
        // todos: para asignar incidencias (sin ser admin, solo los nombres)
        r("GET", "/api/users", Perm::User, Ctx::users_list),
        r("POST", "/api/users", Perm::Admin, Ctx::users_create),
        r("PUT", "/api/users/{id}", Perm::Admin, Ctx::user_put),
        r("DELETE", "/api/users/{id}", Perm::Admin, Ctx::user_delete),
        r("GET", "/api/groups", Perm::User, Ctx::groups_list),
        r("POST", "/api/groups", Perm::Admin, Ctx::groups_create),
        r("PUT", "/api/groups/{id}", Perm::Admin, Ctx::group_put),
        r("DELETE", "/api/groups/{id}", Perm::Admin, Ctx::group_delete),
        r("GET", "/api/backup", Perm::Admin, Ctx::backup),
        r("POST", "/api/backup", Perm::Admin, Ctx::backup),
        r("POST", "/api/wipe", Perm::Admin, Ctx::wipe),
        // actualizar catlan desde GitHub
        r("GET", "/api/update", Perm::Admin, |_| Ok(js(200, crate::update::status()))),
        r("PUT", "/api/update", Perm::Admin, Ctx::update_auto),
        r("POST", "/api/update/check", Perm::Admin, |_| {
            Ok(match crate::update::check() {
                Ok(v) => js(200, v["info"].clone()),
                Err(e) => err(502, &format!("no he podido preguntar a GitHub: {e}")),
            })
        }),
        r("POST", "/api/update/apply", Perm::Admin, Ctx::update_apply),
    ]
}

pub fn me(uid: i64) -> Result<Value> {
    let mut u = q("SELECT id, name, admin, must_change, totp != '' AS totp FROM users WHERE id=?", p![uid])?.one().unwrap_or_default();
    u.insert("readonly".into(), readonly(uid)?.into());
    u.insert("groups".into(), q("SELECT group_id FROM members WHERE user_id=?", p![uid])?.into_iter().map(|r| r["group_id"].clone()).collect::<Vec<_>>().into());
    Ok(u.into())
}

impl Ctx {
    /// El cuerpo, que tiene que ser un objeto.
    fn object(&self) -> Result<Value> {
        let b = self.body()?;
        if !b.is_object() {
            return bad("envía un objeto");
        }
        Ok(b)
    }

    fn my_hash(&self) -> Result<String> {
        Ok(val("SELECT hash FROM users WHERE id=?", p![self.uid()])?.as_str().unwrap_or("").to_string())
    }

    fn login(&mut self) -> Result<Resp> {
        let ip = self.req.ip.clone();
        let b = self.object()?;
        let bs = |k: &str| b.get(k).map(py_str).unwrap_or_default();
        if throttled(&ip) {
            return Ok(err(429, "demasiados intentos: espera 15 minutos"));
        }
        let uid = match login_ok(&trunc(&bs("name"), 100), &trunc(&bs("pass"), 200), &trunc(&bs("code"), 10))? {
            Login::Ok(id) => id,
            other => {
                failed(&ip); // también los códigos fallidos: 10 y fuera
                return Ok(match other {
                    Login::NeedCode => js(401, json!({"error": if b.get("code").is_some_and(truthy) { "código incorrecto" } else { "escribe el código de tu app de autenticación" }, "totp": true})),
                    _ => err(401, "usuario o contraseña incorrectos"),
                });
            }
        };
        let tok = token_urlsafe(32);
        q("DELETE FROM sessions WHERE expires <= datetime('now')", p![])?;
        q("INSERT INTO sessions(token, user_id, expires) VALUES(?, ?, datetime('now', '+30 days'))", p![sha256_hex(&tok), uid])?;
        let secure = if self.req.tls { "; Secure" } else { "" };
        Ok(js(200, me(uid)?).header("Set-Cookie", format!("{}={tok}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000{secure}", *COOKIE)))
    }

    fn logout(&mut self) -> Result<Resp> {
        q("DELETE FROM sessions WHERE token=?", p![&self.token])?;
        Ok(no_content().header("Set-Cookie", format!("{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0", *COOKIE)))
    }

    fn me_get(&mut self) -> Result<Resp> {
        Ok(js(200, me(self.uid())?))
    }

    fn me_password(&mut self) -> Result<Resp> {
        let b = self.object()?;
        if !pw_ok(&b.get("old").map(py_str).unwrap_or_default(), &self.my_hash()?) {
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
        Ok(no_content())
    }

    /// Verificación en dos pasos (app de autenticación).
    fn me_totp(&mut self) -> Result<Resp> {
        let b = self.object()?;
        if b.get("off").is_some_and(truthy) {
            if !b.get("pass").and_then(Value::as_str).is_some_and(|p| pw_ok(p, &self.my_hash().unwrap_or_default())) {
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
        if !re!(r"^[A-Z2-7]{32}$").is_match(&sec) || !totp_ok(&sec, &b.get("code").map(py_str).unwrap_or_default()) {
            return Ok(err(400, "el código no coincide: revisa la hora del móvil y vuelve a probar"));
        }
        q("UPDATE users SET totp=? WHERE id=?", p![&sec, self.uid()])?;
        lock(&BASIC).clear(); // Basic ya no le vale
        self.log("activar 2FA", "user", self.uid(), &self.user, &json!({}))?;
        Ok(js(200, me(self.uid())?))
    }

    fn users_list(&mut self) -> Result<Resp> {
        if !self.admin {
            // para asignar incidencias: solo nombres
            return Ok(js(200, q("SELECT id, name FROM users ORDER BY name COLLATE NOCASE", p![])?.rows));
        }
        Ok(js(200, q("SELECT id, name, admin, must_change, totp != '' AS totp, created FROM users ORDER BY name COLLATE NOCASE", p![])?.rows))
    }

    /// Uno o muchos (lista). Todo se valida antes de guardar nada. Sin contraseña se genera una provisional,
    /// que solo se devuelve en esta respuesta; con contraseña o sin ella, se pide cambiarla al entrar.
    fn users_create(&mut self) -> Result<Resp> {
        let b = self.body()?;
        if !b.is_object() && !b.is_array() {
            return bad("envía un objeto");
        }
        let batch: Vec<Value> = match &b {
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
        let pws: Vec<String> = batch.iter().map(|x| x.get("pass").and_then(Value::as_str).filter(|p| !p.is_empty()).map(String::from).unwrap_or_else(|| token_urlsafe(9))).collect();
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

    /// El usuario de la ruta, si no es uno mismo quitándose el admin o borrándose: así siempre queda un administrador.
    fn other_user(&self, b: &Value, delete: bool) -> Result<std::result::Result<(i64, Value), Resp>> {
        let Some(row) = q("SELECT id, name FROM users WHERE id=?", p![self.id()])?.one() else { return Ok(Err(err(404, "no existe"))) };
        let id = row.i("id").unwrap_or(0);
        if Some(id) == self.uid && (delete || b.get("admin") == Some(&Value::Bool(false))) {
            return bad("no puedes quitarte el admin ni borrarte a ti mismo");
        }
        Ok(Ok((id, row["name"].clone())))
    }

    fn user_put(&mut self) -> Result<Resp> {
        let b = self.object()?;
        let (id, name) = match self.other_user(&b, false)? {
            Ok(x) => x,
            Err(r) => return Ok(r),
        };
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
        self.log("editar", "user", id, &name, &json!({"admin": b.get("admin"), "contraseña": b.get("pass").is_some(), "quitar 2FA": b.get("totp") == Some(&Value::Bool(false))}))?;
        Ok(js(200, me(id)?))
    }

    fn user_delete(&mut self) -> Result<Resp> {
        let (id, name) = match self.other_user(&json!({}), true)? {
            Ok(x) => x,
            Err(r) => return Ok(r),
        };
        q("DELETE FROM sessions WHERE user_id=?", p![id])?;
        q("DELETE FROM users WHERE id=?", p![id])?;
        q("DELETE FROM members WHERE user_id=?", p![id])?;
        q("DELETE FROM tasks WHERE user=?", p![id])?;
        q("UPDATE incidents SET assignee=NULL WHERE assignee=?", p![id])?;
        lock(&BASIC).clear();
        self.log("borrar", "user", id, &name, &json!({}))?;
        Ok(no_content())
    }

    // ── Grupos ──

    /// Todos: hace falta para asignar incidencias.
    fn groups_list(&mut self) -> Result<Resp> {
        let mut out = vec![];
        for mut g in q("SELECT * FROM groups ORDER BY name COLLATE NOCASE", p![])? {
            let members: Vec<Value> = q("SELECT user_id FROM members WHERE group_id=?", p![&g["id"]])?.into_iter().map(|r| r["user_id"].clone()).collect();
            g.insert("members".into(), members.into());
            out.push(g);
        }
        Ok(js(200, out))
    }

    fn check_group(x: &Value, new: bool) -> Result<()> {
        let users: HashSet<i64> = q("SELECT id FROM users", p![])?.into_iter().filter_map(|r| r.i("id")).collect();
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
    }

    fn set_members(gid: i64, x: &Value) -> Result<()> {
        q("DELETE FROM members WHERE group_id=?", p![gid])?;
        let mut v: Vec<i64> = x.get("members").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_i64).collect();
        v.sort();
        v.dedup();
        for mm in v {
            q("INSERT INTO members(group_id, user_id) VALUES(?, ?)", p![gid, mm])?;
        }
        Ok(())
    }

    fn groups_create(&mut self) -> Result<Resp> {
        let b = self.body()?;
        if let Some(list) = b.as_array() {
            // varios grupos de una vez, todo validado antes
            let taken: HashSet<String> = q("SELECT name FROM groups", p![])?.into_iter().map(|r| r.s("name").to_lowercase()).collect();
            let mut seen = HashSet::new();
            if !(1..=100).contains(&list.len()) {
                return bad("de 1 a 100 grupos a la vez");
            }
            for x in list {
                Self::check_group(x, true)?;
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
                Self::set_members(gid, x)?;
                self.log("crear", "group", gid, &name, x)?;
                out.push(q("SELECT * FROM groups WHERE id=?", p![gid])?.one().unwrap_or_default());
            }
            return Ok(js(201, out));
        }
        Self::check_group(&b, true)?;
        let name = b.get("name").map(py_str).unwrap_or_default().trim().to_string();
        let gid = match q("INSERT INTO groups(name, role) VALUES(?, ?)", p![name, b.get("role").and_then(Value::as_str).unwrap_or("edit")]) {
            Ok(r) => r.lastrowid,
            Err(e) if is_constraint(&e) => return bad("ese grupo ya existe"),
            Err(e) => return Err(e),
        };
        if b.get("members").is_some() {
            Self::set_members(gid, &b)?;
        }
        let g = q("SELECT * FROM groups WHERE id=?", p![gid])?.one().unwrap_or_default();
        self.log("crear", "group", gid, &g["name"], &b)?;
        Ok(js(201, g))
    }

    fn group_put(&mut self) -> Result<Resp> {
        let b = self.body()?;
        Self::check_group(&b, false)?;
        let Some(gid) = q("SELECT id FROM groups WHERE id=?", p![self.id()])?.one().and_then(|g| g.i("id")) else { return Ok(err(404, "no existe")) };
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
        if b.get("members").is_some() {
            Self::set_members(gid, &b)?;
        }
        let g = q("SELECT * FROM groups WHERE id=?", p![gid])?.one().unwrap_or_default();
        self.log("editar", "group", gid, &g["name"], &b)?;
        Ok(js(200, g))
    }

    fn group_delete(&mut self) -> Result<Resp> {
        let Some(gid) = q("SELECT id FROM groups WHERE id=?", p![self.id()])?.one().and_then(|g| g.i("id")) else { return Ok(err(404, "no existe")) };
        let name = val("SELECT name FROM groups WHERE id=?", p![gid])?;
        q("UPDATE incidents SET grp=NULL WHERE grp=?", p![gid])?;
        q("DELETE FROM members WHERE group_id=?", p![gid])?;
        q("DELETE FROM groups WHERE id=?", p![gid])?;
        self.log("borrar", "group", gid, &name, &json!({}))?;
        Ok(no_content())
    }

    // ── Administración ──

    /// Copia de seguridad descargable; POST {password}: cifrada.
    fn backup(&mut self) -> Result<Resp> {
        let pw = if self.req.method == "POST" {
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
        self.log("descargar", "db", 0, format!("una copia de seguridad{}", if pw.is_some() { " cifrada" } else { "" }), &json!({"bytes": data.len()}))?;
        let name = format!("catlan-{}{}", crate::util::local("%Y%m%d-%H%M"), if pw.is_some() { ".catlan" } else { ".db" });
        Ok(match pw {
            Some(pw) => Resp::new(200, seal(&data, &pw), "application/octet-stream"),
            None => Resp::new(200, data, "application/vnd.sqlite3"),
        }
        .header("Content-Disposition", format!("attachment; filename=\"{name}\"")))
    }

    /// Borra todo el contenido, con la contraseña del admin; antes, una copia completa en la carpeta de datos.
    fn wipe(&mut self) -> Result<Resp> {
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

    fn update_auto(&mut self) -> Result<Resp> {
        let on = self.body()?.get("auto").and_then(Value::as_bool).ok_or(crate::util::Bad("auto: true o false".into()))?;
        crate::update::set_auto(on)?;
        self.log(if on { "activar" } else { "desactivar" }, "update", 0, "Actualizar solo", &json!({}))?;
        Ok(js(200, crate::update::status()))
    }

    fn update_apply(&mut self) -> Result<Resp> {
        Ok(match crate::update::apply() {
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
        })
    }
}

/// `catlan restablecer <usuario>`: contraseña olvidada. Desde el servidor, que ya tiene la base de datos:
/// contraseña provisional (a cambiar al entrar), sin verificación en dos pasos y con sus sesiones cerradas.
pub fn reset_password(name: &str) -> Result<i32> {
    let u = if name.is_empty() { None } else { q("SELECT id, name FROM users WHERE name=?", p![name])?.one() };
    let Some(u) = u else {
        let names: Vec<String> =
            q("SELECT name, admin FROM users ORDER BY name COLLATE NOCASE", p![])?.into_iter().map(|r| format!("{}{}", r.s("name"), if r.t("admin") { " (admin)" } else { "" })).collect();
        let pre = if name.is_empty() { String::new() } else { format!("No existe el usuario «{name}». ") };
        println!("{pre}Usuarios en {}: {}\nUso: catlan restablecer <usuario>", DATA.join("catlan.db").display(), names.join(", "));
        return Ok(1);
    };
    let pw = token_urlsafe(9);
    q("UPDATE users SET hash=?, must_change=1, totp='' WHERE id=?", p![pw_hash(&pw, None), &u["id"]])?;
    q("DELETE FROM sessions WHERE user_id=?", p![&u["id"]])?;
    q("INSERT INTO log(who, action, kind, ref, name, data) VALUES('consola del servidor', 'restablecer contraseña', 'user', ?, ?, '{}')", p![&u["id"], &u["name"]])?;
    println!(
        "Contraseña provisional de {}: {pw}\nEntra con ella y catlan te pedirá cambiarla. Su verificación en dos pasos queda quitada.\n(Base de datos: {})",
        u.s("name"),
        DATA.join("catlan.db").display()
    );
    Ok(0)
}
