//! Lo que IT hace con los PCs con Kitty: avisos masivos, archivos de las incidencias y scripts de PowerShell.
use super::{Ctx, Perm, Route, err, js, no_content, r};
use crate::db::{self, SqlV, q, val};
use crate::p;
use crate::server::Resp;
use crate::util::{Row, bad, is_int, obj, trunc};
use anyhow::Result;
use serde_json::{Value, json};

/// Lo que Kitty devuelve de un script: como mucho esto se guarda.
const MAX_OUT: usize = 64 * 1024;
/// Un script entregado que no contesta en este tiempo se da por perdido (el PC se apagó, Kitty se reinició…).
const LOST_MIN: i64 = 70;

pub fn routes() -> Vec<Route> {
    vec![
        r("GET", "/api/notices", Perm::User, Ctx::notices_list),
        r("POST", "/api/notices", Perm::User, Ctx::notice_create),
        r("DELETE", "/api/notices/{id}", Perm::User, Ctx::notice_delete),
        r("GET", "/api/files/{id}", Perm::User, Ctx::file_get),
        r("POST", "/api/scripts/{id}/run", Perm::Admin, Ctx::script_run),
        r("GET", "/api/runs", Perm::Admin, Ctx::runs_list),
    ]
}

/// Ids de equipos de una lista JSON: todos enteros y existentes. None si la forma no vale.
fn item_ids(v: Option<&Value>) -> Result<Option<Vec<i64>>> {
    let Some(a) = v.and_then(Value::as_array).filter(|a| a.len() <= 1000 && a.iter().all(is_int)) else { return Ok(None) };
    let mut ids: Vec<i64> = a.iter().filter_map(Value::as_i64).collect();
    ids.sort();
    ids.dedup();
    for i in &ids {
        if q("SELECT 1 FROM items WHERE id=?", p![*i])?.is_empty() {
            return Ok(None);
        }
    }
    Ok(Some(ids))
}

/// Para el envío de Kitty: los scripts pendientes de este equipo (pasan a «enviado») y guarda los resultados que trae.
pub fn agent_runs(agent: &Value, results: Option<&Value>) -> Result<Vec<Value>> {
    for r in results.and_then(Value::as_array).map(|a| &a[..a.len().min(50)]).unwrap_or(&[]) {
        let (Some(id), Some(code)) = (r.get("id").filter(|v| is_int(v)).and_then(Value::as_i64), r.get("code").filter(|v| is_int(v)).and_then(Value::as_i64)) else { continue };
        let out = trunc(r.get("out").and_then(Value::as_str).unwrap_or(""), MAX_OUT);
        q("UPDATE runs SET state=?, code=?, output=?, done=CURRENT_TIMESTAMP WHERE id=? AND agent=? AND state='enviado'", p![if code == 0 { "hecho" } else { "error" }, code, out, id, agent])?;
    }
    let pending = q("SELECT id, body FROM runs WHERE agent=? AND state='pendiente' ORDER BY id LIMIT 10", p![agent])?;
    for r in &pending.rows {
        q("UPDATE runs SET state='enviado', done=CURRENT_TIMESTAMP WHERE id=?", p![&r["id"]])?; // «done»: cuándo se entregó, hasta que conteste
    }
    Ok(pending.rows.into_iter().map(Value::Object).collect())
}

impl Ctx {
    fn notices_list(&mut self) -> Result<Resp> {
        Ok(js(200, q("SELECT * FROM notices WHERE until > datetime('now', '-7 days') ORDER BY id DESC", p![])?.rows))
    }

    /// Un aviso para la ventana de Kitty de todos los PCs o de unos equipos: {text, hours (1–168), items?: [ids]}.
    fn notice_create(&mut self) -> Result<Resp> {
        let b = self.body()?;
        let b = obj(&b)?;
        let text = b.get("text").and_then(Value::as_str).map(str::trim).filter(|t| (1..=500).contains(&t.chars().count()));
        let Some(text) = text else { return bad("el aviso va de 1 a 500 caracteres") };
        let hours = b.get("hours").filter(|v| is_int(v)).and_then(Value::as_i64).filter(|h| (1..=168).contains(h));
        let Some(hours) = hours else { return bad("cuántas horas se ve: de 1 a 168") };
        let items = match b.get("items") {
            None | Some(Value::Null) => vec![],
            v => match item_ids(v)? {
                Some(ids) if !ids.is_empty() => ids,
                _ => return bad("equipos no válidos"),
            },
        };
        let id = q("INSERT INTO notices(text, items, until, who) VALUES(?, ?, datetime('now', ?), ?)", p![text, json!(items).to_string(), format!("+{hours} hours"), &self.user])?.lastrowid;
        let row = q("SELECT * FROM notices WHERE id=?", p![id])?.one().unwrap_or_default();
        self.log("crear", "notice", id, text, &Value::Object(row.clone()))?;
        Ok(js(201, row))
    }

    /// Quitarlo ya: deja de verse en los PCs (queda en Actividad).
    fn notice_delete(&mut self) -> Result<Resp> {
        let Some(n) = q("SELECT * FROM notices WHERE id=?", p![self.id()])?.one() else { return Ok(err(404, "no existe")) };
        q("DELETE FROM notices WHERE id=?", p![&n["id"]])?;
        self.log("borrar", "notice", &n["id"], &n["text"], &Value::Object(n.clone()))?;
        Ok(no_content())
    }

    /// Un archivo de una incidencia (las capturas que manda Kitty). Sin scripts aunque sea un SVG o un HTML.
    fn file_get(&mut self) -> Result<Resp> {
        let Some((mime, data)) = db::blob("SELECT mime, data FROM files WHERE id=?", p![self.id()])? else { return Ok(err(404, "no existe")) };
        Ok(Resp::new(200, data, &mime).header("Content-Security-Policy", "default-src 'none'; img-src 'self'").header("X-Content-Type-Options", "nosniff"))
    }

    /// Lanzar un script en unos equipos con Kitty: {items: [ids]}. Se guarda una copia del script en cada ejecución.
    fn script_run(&mut self) -> Result<Resp> {
        let Some(s) = q("SELECT * FROM scripts WHERE id=?", p![self.id()])?.one() else { return Ok(err(404, "no existe")) };
        let b = self.body()?;
        let Some(items) = item_ids(obj(&b)?.get("items"))?.filter(|i| !i.is_empty()) else { return bad("elige uno o más equipos") };
        let mut made = vec![];
        let mut skipped = vec![];
        for it in items {
            let agent = val("SELECT id FROM agents WHERE item=? AND state='adoptado' ORDER BY id DESC LIMIT 1", p![it])?;
            if agent.is_null() {
                skipped.push(it);
                continue;
            }
            let id = q("INSERT INTO runs(script, name, body, item, agent, who) VALUES(?, ?, ?, ?, ?, ?)", p![&s["id"], &s["name"], &s["body"], it, db::jv(&agent), &self.user])?.lastrowid;
            made.push(id);
            let name = val("SELECT name FROM items WHERE id=?", p![it])?;
            self.log("ejecutar", "item", it, db::jv(&name), &json!({"script": s["name"], "run": id}))?;
        }
        if made.is_empty() {
            return bad("ninguno de esos equipos tiene Kitty aceptado");
        }
        Ok(js(201, json!({"runs": made, "skipped": skipped})))
    }

    /// Ejecuciones (?item=N las de un equipo), las 200 últimas. Las entregadas que no contestan pasan a «sin respuesta».
    fn runs_list(&mut self) -> Result<Resp> {
        q(&format!("UPDATE runs SET state='sin respuesta' WHERE state='enviado' AND done < datetime('now', '-{LOST_MIN} minutes')"), p![])?;
        let item = self.qs.get("item").and_then(|v| v[0].parse::<i64>().ok());
        let (cond, args): (&str, Vec<SqlV>) = match item {
            Some(i) => ("WHERE r.item=?", p![i]),
            None => ("", p![]),
        };
        let rows: Vec<Row> = q(&format!("SELECT r.id, r.script, r.name, r.item, i.name AS item_name, r.who, r.state, r.code, r.output, r.created, r.done FROM runs r LEFT JOIN items i ON i.id = r.item {cond} ORDER BY r.id DESC LIMIT 200"), args)?.rows;
        Ok(js(200, rows))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn ids_de_equipos() {
        crate::db::test_init();
        let it = crate::db::q("INSERT INTO items(name) VALUES('pc-ids')", crate::p![]).unwrap().lastrowid;
        assert_eq!(super::item_ids(Some(&serde_json::json!([it, it]))).unwrap(), Some(vec![it]));
        assert_eq!(super::item_ids(Some(&serde_json::json!([it, 999_999]))).unwrap(), None);
        assert_eq!(super::item_ids(Some(&serde_json::json!(["1"]))).unwrap(), None);
    }
}
