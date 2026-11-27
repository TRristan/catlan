//! La wiki y Actividad: las páginas, el historial de todo lo que cambia y deshacer un borrado.
use super::{Ctx, Perm, Route, err, js, r};
use crate::db::{self, q};
use crate::p;
use crate::server::Resp;
use crate::util::{Bad, J, bad};
use anyhow::Result;
use serde_json::{Value, json};

pub fn routes() -> Vec<Route> {
    vec![
        r("GET", "/api/pages", Perm::User, Ctx::crud_list),
        r("POST", "/api/pages", Perm::User, Ctx::crud_create),
        r("GET", "/api/pages/{id}", Perm::User, Ctx::crud_get),
        r("PUT", "/api/pages/{id}", Perm::User, Ctx::crud_put),
        r("DELETE", "/api/pages/{id}", Perm::User, Ctx::crud_delete),
        r("GET", "/api/log", Perm::User, Ctx::log_list),
        r("POST", "/api/log/{id}/undo", Perm::User, |c| c.undo(c.param("id").unwrap_or("").parse().map_err(|_| Bad("id no válido".into()))?)),
    ]
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

impl Ctx {
    /// Lo último que ha pasado, o lo de una cosa (?kind=item&ref=3).
    fn log_list(&mut self) -> Result<Resp> {
        let (w, a) = match (self.qs.get("kind"), self.qs.get("ref")) {
            (Some(k), Some(r)) => {
                let Ok(r) = r[0].parse::<i64>() else { return bad("ref no válido") };
                ("WHERE kind=? AND ref=?", p![&k[0], r])
            }
            _ => ("", p![]),
        };
        Ok(js(200, q(&format!("SELECT * FROM log {w} ORDER BY id DESC LIMIT 300"), a)?.rows))
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
}
