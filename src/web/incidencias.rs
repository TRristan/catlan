//! Incidencias (con su seguimiento, padres e hijas) y el tablero personal de cada usuario.
use super::{Ctx, Perm, Route, err, js, no_content, r};
use crate::db::{self, SqlV, q, val};
use crate::monitor;
use crate::p;
use crate::server::Resp;
use crate::util::{J, Row, bad, obj};
use crate::validate::check_incident;
use anyhow::Result;
use serde_json::{Value, json};

/// Columnas del tablero personal.
const TASK_COLS: [&str; 4] = ["notas", "pendiente", "hoy", "hecho"];
const INC_COLS: [&str; 8] = ["title", "body", "status", "priority", "assignee", "grp", "item", "parent"];
const DONE: [&str; 2] = ["resuelta", "cerrada"];
const INC: &str = "SELECT n.*, u.name AS assignee_name, g.name AS grp_name, i.name AS item_name, a.name AS author_name, \
    (SELECT count(*) FROM notes WHERE incident = n.id AND change = 0) AS notes, p.title AS parent_title, \
    (SELECT count(*) FROM incidents h WHERE h.parent = n.id) AS children FROM incidents n LEFT JOIN incidents p ON p.id = n.parent \
    LEFT JOIN users u ON u.id = n.assignee \
    LEFT JOIN groups g ON g.id = n.grp LEFT JOIN items i ON i.id = n.item LEFT JOIN users a ON a.id = n.author";

pub fn routes() -> Vec<Route> {
    vec![
        r("GET", "/api/incidents", Perm::User, Ctx::incidents_list),
        r("POST", "/api/incidents", Perm::User, Ctx::incident_create),
        r("GET", "/api/incidents/{id}", Perm::User, Ctx::incident_get),
        r("PUT", "/api/incidents/{id}", Perm::User, Ctx::incident_put),
        r("DELETE", "/api/incidents/{id}", Perm::Admin, Ctx::incident_delete),
        r("POST", "/api/incidents/{id}/notes", Perm::User, Ctx::incident_note),
        // el tablero personal no toca nada común: también para los de solo vista
        r("GET", "/api/tasks", Perm::Own, Ctx::tasks_list),
        r("POST", "/api/tasks", Perm::Own, Ctx::task_save),
        r("PUT", "/api/tasks/{id}", Perm::Own, Ctx::task_save),
        r("DELETE", "/api/tasks/{id}", Perm::Own, Ctx::task_delete),
    ]
}

impl Ctx {
    pub fn note(&self, inc: i64, text: &str, change: bool) -> Result<()> {
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

    /// Lo editable de una incidencia que llega en el cuerpo (que tiene que ser un objeto).
    fn incident_body(&self) -> Result<(Value, Row)> {
        let b = self.body()?;
        let Some(bo) = b.as_object() else { return bad("envía un objeto") };
        let d: Row = INC_COLS.iter().filter_map(|k| bo.get(*k).map(|v| (k.to_string(), v.clone()))).collect();
        Ok((b, d))
    }

    fn incident(&self) -> Result<Option<Row>> {
        Ok(q(&format!("{INC} WHERE n.id=?"), p![self.id()])?.one())
    }

    fn incidents_list(&mut self) -> Result<Resp> {
        let order = " ORDER BY n.status IN ('resuelta', 'cerrada'), CASE n.priority WHEN 'crítica' THEN 0 \
                     WHEN 'alta' THEN 1 WHEN 'media' THEN 2 ELSE 3 END, n.updated DESC";
        Ok(js(200, q(&format!("{INC}{order}"), p![])?.rows))
    }

    fn incident_create(&mut self) -> Result<Resp> {
        let (_, d) = self.incident_body()?;
        let mut chk = d.clone();
        chk.entry("title").or_insert("".into());
        check_incident(&chk, None)?;
        let keys: Vec<&String> = d.keys().collect();
        let mut args: Vec<SqlV> = d.values().map(db::jv).collect();
        args.push(SqlV::Integer(self.uid()));
        let id = q(&format!("INSERT INTO incidents({}author) VALUES({}?)", keys.iter().map(|k| format!("{k}, ")).collect::<String>(), "?, ".repeat(keys.len())), args)?.lastrowid;
        self.note(id, "abrió la incidencia", true)?;
        self.log("crear", "incident", id, &d["title"], &Value::Object(d.clone()))?;
        let row = q(&format!("{INC} WHERE n.id=?"), p![id])?.one().unwrap_or_default();
        if row.s("priority") == "crítica" {
            // lo urgente sale por correo, Telegram o webhook
            let to =
                if row.t("assignee") || row.t("grp") { format!(", asignada a {}", if row.s("assignee_name").is_empty() { row.s("grp_name") } else { row.s("assignee_name") }) } else { String::new() };
            monitor::notify(&format!("catlan: incidencia crítica INC-{id}: {}", row.s("title")), &format!("Abierta por {}{to}.\n\n-- catlan", self.user));
        }
        Ok(js(201, row))
    }

    fn incident_get(&mut self) -> Result<Resp> {
        let Some(row) = self.incident()? else { return Ok(err(404, "no existe")) };
        let id = row.i("id").unwrap_or(0);
        let mut out = row.clone();
        out.insert("history".into(), q("SELECT * FROM notes WHERE incident=? ORDER BY id", p![id])?.rows.into_iter().map(Value::Object).collect::<Vec<_>>().into());
        out.insert("kids".into(), q(&format!("{INC} WHERE n.parent=? ORDER BY n.id"), p![id])?.rows.into_iter().map(Value::Object).collect::<Vec<_>>().into());
        // trazabilidad: dónde se enlaza con [[INC-n]] (páginas, notas de equipos, otras incidencias y su seguimiento)
        let tag = format!("%[[INC-{id}]]%");
        out.insert(
            "mentions".into(),
            json!({
                "pages": q("SELECT id, title FROM pages WHERE body LIKE ? ORDER BY title", p![&tag])?.rows,
                "items": q("SELECT id, name FROM items WHERE notes LIKE ? ORDER BY name", p![&tag])?.rows,
                "incidents": q("SELECT id, title, status FROM incidents WHERE id != ? AND (body LIKE ? OR id IN (SELECT incident FROM notes WHERE change = 0 AND text LIKE ?)) ORDER BY id DESC",
                    p![id, &tag, &tag])?.rows,
            }),
        );
        Ok(js(200, out))
    }

    fn incident_note(&mut self) -> Result<Resp> {
        let (b, _) = self.incident_body()?;
        let Some(row) = self.incident()? else { return Ok(err(404, "no existe")) };
        let id = row.i("id").unwrap_or(0);
        let t = b.get("text").and_then(Value::as_str).map(str::trim).filter(|t| (1..=5000).contains(&t.chars().count()));
        let Some(t) = t else { return bad("la nota va de 1 a 5000 caracteres") };
        self.note(id, t, false)?;
        Ok(js(201, q("SELECT * FROM notes WHERE id = (SELECT max(id) FROM notes WHERE incident=?)", p![id])?.one()))
    }

    fn incident_put(&mut self) -> Result<Resp> {
        let (b, mut d) = self.incident_body()?;
        let Some(row) = self.incident()? else { return Ok(err(404, "no existe")) };
        let id = row.i("id").unwrap_or(0);
        check_incident(&d, Some(id))?;
        d.retain(|k, v| row.get(k) != Some(v));
        let seen = obj(&b)?.get("_seen").filter(|v| !v.is_null()); // la versión que abrió quien guarda
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
        Ok(js(200, out))
    }

    fn incident_delete(&mut self) -> Result<Resp> {
        let Some(row) = self.incident()? else { return Ok(err(404, "no existe")) };
        let id = row.i("id").unwrap_or(0);
        q("UPDATE incidents SET parent=NULL WHERE parent=?", p![id])?; // las hijas siguen, ya sin padre
        q("DELETE FROM notes WHERE incident=?", p![id])?;
        q("DELETE FROM incidents WHERE id=?", p![id])?;
        self.log("borrar", "incident", id, &row["title"], &Value::Object(row.clone()))?;
        Ok(no_content())
    }

    // ── Tablero personal: tareas y notas de cada usuario, que solo ve y toca él. Sin Actividad: no son de nadie más. ──

    fn tasks_list(&mut self) -> Result<Resp> {
        Ok(js(200, q("SELECT id, text, col, pos, updated FROM tasks WHERE user=? ORDER BY pos, id", p![self.uid()])?.rows))
    }

    fn task_delete(&mut self) -> Result<Resp> {
        let n = q("DELETE FROM tasks WHERE id=? AND user=?", p![self.id(), self.uid()])?.rowcount;
        Ok(if n == 0 { err(404, "no existe") } else { no_content() })
    }

    /// POST crea, PUT con {id} cambia lo que llegue.
    fn task_save(&mut self) -> Result<Resp> {
        let uid = self.uid();
        let new = self.param("id").is_none();
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
        let id = if new {
            let Some(text) = text else { return bad("escribe la tarea") };
            if val("SELECT count(*) FROM tasks WHERE user=?", p![uid])?.as_i64().unwrap_or(0) >= 1000 {
                return bad("como mucho 1000 tareas: borra las hechas");
            }
            let col = col.unwrap_or_else(|| "pendiente".into());
            // sin posición: al final de su columna
            q("INSERT INTO tasks(user, text, col, pos) VALUES(?, ?, ?, COALESCE(?, (SELECT max(pos) + 1 FROM tasks WHERE user=? AND col=?), 0))", p![uid, text, col.clone(), pos, uid, col])?.lastrowid
        } else {
            let n =
                q("UPDATE tasks SET text=COALESCE(?, text), col=COALESCE(?, col), pos=COALESCE(?, pos), updated=CURRENT_TIMESTAMP WHERE id=? AND user=?", p![text, col, pos, self.id(), uid])?.rowcount;
            if n == 0 {
                return Ok(err(404, "no existe"));
            }
            self.id()
        };
        Ok(js(if new { 201 } else { 200 }, q("SELECT id, text, col, pos, updated FROM tasks WHERE id=?", p![id])?.one()))
    }
}
