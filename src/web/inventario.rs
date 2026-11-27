//! Inventario: equipos, vencimientos, subredes (IPAM), programas para los PCs, esquemas y racks. Aquí vive también el
//! CRUD con historial que comparten las tablas sencillas (las de la wiki y el monitor incluidas).
use super::{Ctx, Perm, Route, err, js, no_content, public, r};
use crate::db::{self, SqlV, q, val};
use crate::health;
use crate::monitor::{self, SECRET};
use crate::p;
use crate::server::Resp;
use crate::util::{Bad, J, Row, Shape, bad, obj, trunc};
use crate::validate::*;
use anyhow::Result;
use serde_json::{Value, json};

const IMAGE_TYPES: &[&str] = &["image/png", "image/jpeg", "image/gif", "image/webp", "image/svg+xml"];

pub fn routes() -> Vec<Route> {
    vec![
        r("GET", "/api/items", Perm::User, Ctx::crud_list),
        r("POST", "/api/items", Perm::User, Ctx::crud_create),
        r("GET", "/api/items/{id}", Perm::User, Ctx::crud_get),
        r("PUT", "/api/items/{id}", Perm::User, Ctx::crud_put),
        r("DELETE", "/api/items/{id}", Perm::User, Ctx::crud_delete),
        r("GET", "/api/items/{id}/refs", Perm::User, |c| Ok(js(200, refs(c.param("id").unwrap_or("").parse().map_err(|_| Bad("id no válido".into()))?)?))),
        r("GET", "/api/items/{id}/syslog", Perm::User, |c| Ok(js(200, q("SELECT ts, ip, sev, msg FROM syslog WHERE item=? ORDER BY rowid DESC LIMIT 200", p![c.id()])?.rows))),
        r("GET", "/api/expiries", Perm::User, Ctx::crud_list),
        r("POST", "/api/expiries", Perm::User, Ctx::crud_create),
        r("GET", "/api/expiries/{id}", Perm::User, Ctx::crud_get),
        r("PUT", "/api/expiries/{id}", Perm::User, Ctx::crud_put),
        r("DELETE", "/api/expiries/{id}", Perm::User, Ctx::crud_delete),
        r("GET", "/api/subnets", Perm::User, Ctx::crud_list),
        r("POST", "/api/subnets", Perm::User, Ctx::crud_create),
        r("GET", "/api/subnets/{id}", Perm::User, Ctx::crud_get),
        r("PUT", "/api/subnets/{id}", Perm::User, Ctx::crud_put),
        r("DELETE", "/api/subnets/{id}", Perm::User, Ctx::crud_delete),
        r("GET", "/api/subnets/{id}/ips", Perm::User, Ctx::subnet_ips),
        r("GET", "/api/subnets/{id}/scan", Perm::User, Ctx::subnet_ips), // lo último escaneado, sin escanear
        r("POST", "/api/subnets/{id}/scan", Perm::User, Ctx::subnet_ips),
        // solo los administradores eligen qué se instala en los PCs
        r("GET", "/api/apps", Perm::User, Ctx::crud_list),
        r("POST", "/api/apps", Perm::Admin, Ctx::crud_create),
        r("GET", "/api/apps/{id}", Perm::User, Ctx::crud_get),
        r("PUT", "/api/apps/{id}", Perm::Admin, Ctx::crud_put),
        r("DELETE", "/api/apps/{id}", Perm::Admin, Ctx::crud_delete),
        r("GET", "/api/maps", Perm::User, Ctx::maps_list),
        r("POST", "/api/maps", Perm::User, Ctx::map_create),
        r("GET", "/api/maps/{id}", Perm::User, Ctx::map_get),
        r("PUT", "/api/maps/{id}", Perm::User, Ctx::map_put),
        r("DELETE", "/api/maps/{id}", Perm::User, Ctx::map_delete),
        r("GET", "/api/maps/{id}/image", Perm::User, Ctx::map_image),
    ]
}

/// Columnas editables por tabla: lista blanca contra inyección SQL.
pub fn table_cols(t: &str) -> Option<&'static [&'static str]> {
    Some(match t {
        "pages" => &["title", "body"],
        "items" => &["name", "kind", "ip", "serial", "location", "status", "notes", "warranty"],
        "checks" => &["host", "label", "item", "every", "kind", "port", "url", "expect", "warn_days", "sound"],
        "sources" => &["host", "label", "item", "kind", "community", "port", "user", "pass", "every", "temp_max", "disk_max", "v3", "auth", "priv", "priv_pass"],
        "expiries" => &["name", "kind", "date", "item", "notes"],
        "subnets" => &["name", "cidr", "vlan", "notes"],
        "apps" => &["name", "winget", "notes"],
        _ => return None,
    })
}

pub fn kind_of(t: &str) -> &'static str {
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

impl Ctx {
    fn cols(&self) -> Result<&'static [&'static str]> {
        table_cols(self.res()).ok_or_else(|| anyhow::anyhow!("{} no es una tabla del CRUD", self.res()))
    }

    pub fn crud_list(&mut self) -> Result<Resp> {
        let res = self.res();
        self.cols()?;
        let order = match res {
            "pages" => "title",
            "items" => "name",
            "expiries" => "date",
            "subnets" => "cidr",
            "apps" => "name",
            _ => "id",
        };
        Ok(js(200, q(&format!("SELECT * FROM {res} ORDER BY {order} COLLATE NOCASE"), p![])?.into_iter().map(public).collect::<Vec<_>>()))
    }

    /// Un objeto, o una lista para crear en serie.
    pub fn crud_create(&mut self) -> Result<Resp> {
        let (res, cols) = (self.res(), self.cols()?);
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
            let (keys, vals): (Vec<String>, Vec<SqlV>) =
                if d.is_empty() { (vec![cols[0].to_string()], p![""]) } else { (d.iter().map(|(k, _)| k.to_string()).collect(), d.iter().map(|(_, v)| db::jv(v)).collect()) };
            let id = q(&format!("INSERT INTO {res}({}) VALUES({})", keys.join(","), vec!["?"; keys.len()].join(",")), vals)?.lastrowid;
            let row = public(q(&format!("SELECT * FROM {res} WHERE id=?"), p![id])?.one().unwrap_or_default());
            self.log("crear", kind_of(res), id, &row[cols[0]], &Value::Object(row.clone()))?;
            out.push(Value::Object(row));
        }
        Ok(js(201, if is_list { Value::Array(out) } else { out.into_iter().next().unwrap_or_default() }))
    }

    pub fn crud_get(&mut self) -> Result<Resp> {
        let res = self.res();
        self.cols()?;
        Ok(match q(&format!("SELECT * FROM {res} WHERE id=?"), p![self.id()])?.one() {
            Some(r) => js(200, public(r)),
            None => err(404, "no existe"),
        })
    }

    pub fn crud_put(&mut self) -> Result<Resp> {
        let (res, cols, rid) = (self.res(), self.cols()?, self.id());
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
            args.push(SqlV::Integer(rid));
            if let Some(s) = &seen {
                args.push(db::jv(s));
            }
            let cur = q(&format!("UPDATE {res} SET {}, updated=CURRENT_TIMESTAMP WHERE id=?{}", sets.join(","), if seen.is_some() { " AND updated=?" } else { "" }), args)?;
            if cur.rowcount == 0
                && seen.is_some()
                && let Some(now) = q(&format!("SELECT updated FROM {res} WHERE id=?"), p![rid])?.one()
            {
                let who = q("SELECT who FROM log WHERE kind=? AND ref=? ORDER BY id DESC LIMIT 1", p![kind_of(res), rid])?.one();
                let who = who.map(|w| w.s("who").to_string()).filter(|w| !w.is_empty()).unwrap_or("Alguien".into());
                return Ok(js(409, json!({"error": format!("{who} lo cambió mientras lo editabas."), "updated": now["updated"]})));
            }
        }
        let Some(row) = q(&format!("SELECT * FROM {res} WHERE id=?"), p![rid])?.one() else { return Ok(err(404, "no existe")) };
        let row = public(row);
        if !d.is_empty() {
            self.log("editar", kind_of(res), &row["id"], &row[cols[0]], &Value::Object(row.clone()))?;
        }
        Ok(js(200, row))
    }

    pub fn crud_delete(&mut self) -> Result<Resp> {
        let (res, cols, rid) = (self.res(), self.cols()?, self.id());
        let row = q(&format!("SELECT * FROM {res} WHERE id=?"), p![rid])?.one();
        q(&format!("DELETE FROM {res} WHERE id=?"), p![rid])?;
        if res == "checks" || res == "sources" {
            // su historial de lecturas se va con él
            let (t, col) = if res == "checks" { ("pings", "check_id") } else { ("metrics", "source_id") };
            q(&format!("DELETE FROM {t} WHERE {col}=?"), p![rid])?;
            q(&format!("DELETE FROM {t}_h WHERE {col}=?"), p![rid])?;
        }
        if let Some(row) = row {
            // la foto del borrado queda en el historial por si hay que recuperarlo
            let row = public(row);
            self.log("borrar", kind_of(res), &row["id"], &row[cols[0]], &Value::Object(row.clone()))?;
        }
        Ok(no_content())
    }

    /// Las IPs de una subred; POST …/scan la escanea antes (ping, DNS y SNMP public, como «Descubrir red»).
    fn subnet_ips(&mut self) -> Result<Resp> {
        let Some(mut row) = q("SELECT * FROM subnets WHERE id=?", p![self.id()])?.one() else { return Ok(err(404, "no existe")) };
        if self.req.method == "POST" {
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
        }
        Ok(js(200, monitor::ipam(&row)?))
    }

    // ── Esquemas y racks ──

    fn maps_list(&mut self) -> Result<Resp> {
        Ok(js(
            200,
            q(
                "SELECT id, name, json_extract(data, '$.type') AS type, json_extract(data, '$.height') AS height, \
                 COALESCE(json_array_length(data, '$.devices'), json_array_length(data, '$.nodes'), 0) AS n \
                 FROM maps ORDER BY name COLLATE NOCASE",
                p![],
            )?
            .rows,
        ))
    }

    /// Cuerpo vacío = lienzo en blanco, si no, imagen de fondo.
    fn map_create(&mut self) -> Result<Resp> {
        let mime = self.req.header("content-type").split(';').next().unwrap_or("").trim().to_string();
        let img = self.req.body.clone();
        if !img.is_empty() && !IMAGE_TYPES.contains(&mime.as_str()) {
            return Ok(err(400, "sube una imagen (png, jpg, gif, webp, svg)"));
        }
        let name = trunc(self.qs.get("name").map_or("Mapa", |v| v[0].as_str()), 200);
        let data = if self.qs.get("type").is_some_and(|t| t == &["rack"]) { json!({"type": "rack"}) } else { json!({}) };
        let id = q("INSERT INTO maps(name, mime, image, data) VALUES(?,?,?,?)", p![&name, if img.is_empty() { "" } else { &mime }, img, data.to_string()])?.lastrowid;
        self.log("crear", data.get("type").and_then(Value::as_str).unwrap_or("map"), id, &name, &json!({"name": name, "data": data}))?;
        Ok(js(201, json!({"id": id, "name": name})))
    }

    fn map_image(&mut self) -> Result<Resp> {
        let Some((mime, image)) = db::blob("SELECT mime, image FROM maps WHERE id=?", p![self.id()])?.filter(|(_, i)| !i.is_empty()) else {
            return Ok(err(404, "no existe"));
        };
        // CSP bloquea scripts dentro de SVG subidos si se abren directamente
        Ok(Resp::new(200, image, &mime).header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'"))
    }

    fn map_get(&mut self) -> Result<Resp> {
        Ok(match q("SELECT id, name, data, version, length(image) > 0 AS has_image FROM maps WHERE id=?", p![self.id()])?.one() {
            Some(mut r) => {
                let d: Value = serde_json::from_str(r.s("data")).unwrap_or(json!({}));
                r.insert("data".into(), d);
                js(200, r)
            }
            None => err(404, "no existe"),
        })
    }

    fn map_put(&mut self) -> Result<Resp> {
        let rid = self.id();
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
        args.push(SqlV::Integer(rid));
        if let Some(s) = seen {
            args.push(db::jv(s));
        }
        let cur = q(&format!("UPDATE maps SET {}version=version+1 WHERE id=?{}", sets.concat(), if seen.is_some() { " AND version=?" } else { "" }), args)?;
        if cur.rowcount == 0 {
            let Some(row) = q("SELECT version FROM maps WHERE id=?", p![rid])?.one() else { return Ok(err(404, "no existe")) };
            let who = q("SELECT who FROM log WHERE kind IN ('map', 'rack') AND ref=? ORDER BY id DESC LIMIT 1", p![rid])?.one();
            let who = who.map(|w| w.s("who").to_string()).filter(|w| !w.is_empty()).unwrap_or("Alguien".into());
            return Ok(js(409, json!({"error": format!("{who} lo cambió mientras lo editabas."), "version": row["version"]})));
        }
        self.log_map("editar", rid)?;
        Ok(js(200, json!({"version": val("SELECT version FROM maps WHERE id=?", p![rid])?})))
    }

    fn map_delete(&mut self) -> Result<Resp> {
        self.log_map("borrar", self.id())?;
        q("DELETE FROM maps WHERE id=?", p![self.id()])?;
        Ok(no_content())
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
