//! SQLite: una conexión que escribe (con candado) y una de solo lectura por hilo, esquema y migraciones numeradas.
use crate::config::{DATA, db_path};
use crate::util::{Row, local, lock};
use rusqlite::{Connection, params_from_iter, types::ValueRef};
use serde_json::{Number, Value};
use std::cell::RefCell;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

pub use rusqlite::types::Value as SqlV;

/// Lo que puede ir como parámetro de una consulta.
pub trait IntoSql {
    fn sql(self) -> SqlV;
}
macro_rules! into_sql {
    ($($t:ty => |$v:ident| $e:expr),* $(,)?) => { $(impl IntoSql for $t { fn sql(self) -> SqlV { let $v = self; $e } })* };
}
into_sql! {
    SqlV => |v| v,
    i64 => |v| SqlV::Integer(v),
    i32 => |v| SqlV::Integer(v as i64),
    usize => |v| SqlV::Integer(v as i64),
    f64 => |v| SqlV::Real(v),
    bool => |v| SqlV::Integer(v as i64),
    &str => |v| SqlV::Text(v.to_string()),
    String => |v| SqlV::Text(v),
    &String => |v| SqlV::Text(v.clone()),
    Vec<u8> => |v| SqlV::Blob(v),
    &[u8] => |v| SqlV::Blob(v.to_vec()),
    Option<i64> => |v| v.map_or(SqlV::Null, SqlV::Integer),
    Option<f64> => |v| v.map_or(SqlV::Null, SqlV::Real),
    Option<String> => |v| v.map_or(SqlV::Null, SqlV::Text),
    Option<&str> => |v| v.map_or(SqlV::Null, |s| SqlV::Text(s.into())),
    &Value => |v| jv(v),
    Value => |v| jv(&v),
}

/// Parámetros de una consulta: `p![a, b, c]`.
#[macro_export]
macro_rules! p {
    ($($e:expr),* $(,)?) => { vec![$($crate::db::IntoSql::sql($e)),*] };
}

/// Un valor JSON como lo guardaba sqlite3 de Python: booleanos como 0/1; listas y objetos, como texto JSON.
pub fn jv(v: &Value) -> SqlV {
    match v {
        Value::Null => SqlV::Null,
        Value::Bool(b) => SqlV::Integer(*b as i64),
        Value::Number(n) => n.as_i64().map(SqlV::Integer).unwrap_or_else(|| SqlV::Real(n.as_f64().unwrap_or(0.0))),
        Value::String(s) => SqlV::Text(s.clone()),
        other => SqlV::Text(other.to_string()),
    }
}

/// Las filas de una consulta, ya leídas, con lastrowid y rowcount como en el cursor de Python.
#[derive(Default)]
pub struct Rows {
    pub rows: Vec<Row>,
    pub lastrowid: i64,
    pub rowcount: usize,
}
impl Rows {
    pub fn one(self) -> Option<Row> {
        self.rows.into_iter().next()
    }
}
impl std::ops::Deref for Rows {
    type Target = Vec<Row>;
    fn deref(&self) -> &Vec<Row> {
        &self.rows
    }
}
impl IntoIterator for Rows {
    type Item = Row;
    type IntoIter = std::vec::IntoIter<Row>;
    fn into_iter(self) -> Self::IntoIter {
        self.rows.into_iter()
    }
}

/// WAL: los lectores no esperan al que escribe y un corte de luz no deja la BD a medias.
/// busy_timeout: si la BD está ocupada, espera hasta 5 s en vez de fallar con «database is locked».
pub fn connect() -> rusqlite::Result<Connection> {
    connect_at(&db_path())
}

fn connect_at(path: &Path) -> rusqlite::Result<Connection> {
    let c = Connection::open(path)?;
    c.busy_timeout(std::time::Duration::from_secs(5))?;
    c.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
    c.execute_batch("PRAGMA synchronous=NORMAL")?;
    Ok(c)
}

static WRITER: OnceLock<Mutex<Connection>> = OnceLock::new();
thread_local! {
    static READER: RefCell<Option<Connection>> = const { RefCell::new(None) };
}

/// La única conexión que escribe, siempre con el candado.
pub fn writer() -> &'static Mutex<Connection> {
    WRITER.get().expect("base de datos sin abrir")
}

fn read_rows(c: &Connection, sql: &str, args: &[SqlV]) -> rusqlite::Result<Vec<Row>> {
    let mut st = c.prepare_cached(sql)?;
    let names: Vec<String> = st.column_names().map(|s| s.to_string()).collect();
    let mut rs = st.query(params_from_iter(args.iter()))?;
    let mut out = vec![];
    while let Some(r) = rs.next()? {
        let mut m = Row::new();
        for (i, n) in names.iter().enumerate() {
            let v = match r.get_ref(i)? {
                ValueRef::Null | ValueRef::Blob(_) => Value::Null,
                ValueRef::Integer(x) => x.into(),
                ValueRef::Real(f) => Number::from_f64(f).map(Value::Number).unwrap_or(Value::Null),
                ValueRef::Text(t) => String::from_utf8_lossy(t).into_owned().into(),
            };
            m.insert(n.clone(), v);
        }
        out.push(m);
    }
    Ok(out)
}

/// Conexión de solo lectura de este hilo: una exportación o una copia larga no congelan al resto.
fn with_reader<T>(f: impl FnOnce(&Connection) -> anyhow::Result<T>) -> anyhow::Result<T> {
    READER.with(|r| {
        let mut r = r.borrow_mut();
        if r.is_none() {
            let c = connect()?;
            c.execute_batch("PRAGMA query_only=1")?;
            *r = Some(c);
        }
        f(r.as_ref().unwrap())
    })
}

/// Lecturas con la conexión de solo lectura de este hilo (WAL, sin esperar al candado); escrituras dentro del candado.
pub fn q(sql: &str, args: Vec<SqlV>) -> anyhow::Result<Rows> {
    if sql.trim_start().get(..6).is_some_and(|s| s.eq_ignore_ascii_case("select")) {
        return with_reader(|c| Ok(Rows { rows: read_rows(c, sql, &args)?, ..Default::default() }));
    }
    let c = lock(writer());
    let n = c.prepare_cached(sql)?.execute(params_from_iter(args.iter()))?;
    Ok(Rows { rows: vec![], lastrowid: c.last_insert_rowid(), rowcount: n })
}

/// La primera columna de la primera fila (null si no hay).
pub fn val(sql: &str, args: Vec<SqlV>) -> anyhow::Result<Value> {
    Ok(q(sql, args)?.one().and_then(|r| r.into_iter().next().map(|(_, v)| v)).unwrap_or(Value::Null))
}

/// Un BLOB y su tipo: imágenes de esquemas y sonidos (no caben en JSON).
pub fn blob(sql: &str, args: Vec<SqlV>) -> anyhow::Result<Option<(String, Vec<u8>)>> {
    with_reader(|c| {
        let mut st = c.prepare_cached(sql)?;
        let mut rs = st.query(params_from_iter(args.iter()))?;
        Ok(match rs.next()? {
            Some(r) => Some((r.get::<_, Option<String>>(0)?.unwrap_or_default(), r.get::<_, Option<Vec<u8>>>(1)?.unwrap_or_default())),
            None => None,
        })
    })
}

/// `PRAGMA user_version` y `PRAGMA table_info`, que no empiezan por SELECT pero solo leen.
pub fn user_version() -> anyhow::Result<i64> {
    with_reader(|c| Ok(c.query_row("PRAGMA user_version", [], |r| r.get(0))?))
}

pub fn columns(table: &str) -> anyhow::Result<Vec<String>> {
    with_reader(|c| Ok(c.prepare(&format!("PRAGMA table_info({table})"))?.query_map([], |r| r.get(1))?.collect::<Result<_, _>>()?))
}

/// ¿Es un error de restricción (UNIQUE) de SQLite?
pub fn is_constraint(e: &anyhow::Error) -> bool {
    matches!(e.downcast_ref::<rusqlite::Error>(), Some(rusqlite::Error::SqliteFailure(f, _)) if f.code == rusqlite::ErrorCode::ConstraintViolation)
}

/// Copia completa y consistente de la BD a path, desde su propia conexión: no para a nadie.
pub fn backup_to(path: &Path) -> anyhow::Result<()> {
    let src = connect()?;
    let mut dst = Connection::open(path)?;
    rusqlite::backup::Backup::new(&src, &mut dst)?.run_to_completion(1000, std::time::Duration::ZERO, None)?;
    Ok(())
}

pub static INTEGRITY: OnceLock<String> = OnceLock::new();
pub static INSTANCE: OnceLock<String> = OnceLock::new();

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS pages(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL DEFAULT '', body TEXT NOT NULL DEFAULT '',
  updated TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL DEFAULT '', kind TEXT DEFAULT '', ip TEXT DEFAULT '',
  serial TEXT DEFAULT '', location TEXT DEFAULT '', status TEXT DEFAULT '', notes TEXT DEFAULT '',
  updated TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS maps(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, mime TEXT NOT NULL, image BLOB NOT NULL,
  data TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS log(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT DEFAULT CURRENT_TIMESTAMP, who TEXT, action TEXT,
  kind TEXT, ref INTEGER, name TEXT, data TEXT);
CREATE INDEX IF NOT EXISTS log_ref ON log(kind, ref);
CREATE TABLE IF NOT EXISTS checks(id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL DEFAULT '', label TEXT DEFAULT '', item INTEGER,
  every INTEGER DEFAULT 30, state TEXT, fails INTEGER DEFAULT 0, rtt REAL, last TEXT, since TEXT, updated TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS pings(check_id INTEGER, ts TEXT DEFAULT CURRENT_TIMESTAMP, up INTEGER, rtt REAL);
CREATE INDEX IF NOT EXISTS pings_c ON pings(check_id, ts);
CREATE TABLE IF NOT EXISTS sounds(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, mime TEXT NOT NULL, data BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS sources(id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT NOT NULL DEFAULT '', label TEXT DEFAULT '', item INTEGER,
  kind TEXT DEFAULT 'generic', community TEXT DEFAULT 'public', port INTEGER DEFAULT 161, user TEXT DEFAULT '', pass TEXT DEFAULT '',
  every INTEGER DEFAULT 300, temp_max REAL DEFAULT 65, disk_max REAL DEFAULT 90,
  v3 INTEGER DEFAULT 0, auth TEXT DEFAULT 'sha', priv TEXT DEFAULT 'aes', priv_pass TEXT DEFAULT '',
  state TEXT, problems TEXT, error TEXT, info TEXT, last TEXT, since TEXT, updated TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS metrics(source_id INTEGER, ts TEXT DEFAULT CURRENT_TIMESTAMP, key TEXT, label TEXT, value REAL, unit TEXT);
CREATE INDEX IF NOT EXISTS metrics_s ON metrics(source_id, ts);
CREATE TABLE IF NOT EXISTS pings_h(check_id INTEGER, hour TEXT, n INTEGER, up INTEGER, rtt REAL, rtt_min REAL, rtt_max REAL,
  PRIMARY KEY(check_id, hour));
CREATE TABLE IF NOT EXISTS metrics_h(source_id INTEGER, key TEXT, hour TEXT, label TEXT, unit TEXT, v REAL, v_min REAL, v_max REAL,
  PRIMARY KEY(source_id, key, hour));
CREATE TABLE IF NOT EXISTS dash(id INTEGER PRIMARY KEY CHECK(id = 1), data TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE, hash TEXT NOT NULL,
  admin INTEGER DEFAULT 0, must_change INTEGER DEFAULT 0, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL, expires TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS groups(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE COLLATE NOCASE, role TEXT NOT NULL DEFAULT 'edit');
CREATE TABLE IF NOT EXISTS members(group_id INTEGER NOT NULL, user_id INTEGER NOT NULL, PRIMARY KEY(group_id, user_id));
CREATE TABLE IF NOT EXISTS incidents(id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, body TEXT DEFAULT '', status TEXT DEFAULT 'abierta',
  priority TEXT DEFAULT 'media', assignee INTEGER, grp INTEGER, item INTEGER, author INTEGER,
  created TEXT DEFAULT CURRENT_TIMESTAMP, updated TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY AUTOINCREMENT, incident INTEGER NOT NULL, who TEXT, ts TEXT DEFAULT CURRENT_TIMESTAMP,
  text TEXT NOT NULL, change INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS agents(id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT NOT NULL UNIQUE /*sha256 de la clave de Kitty*/, name TEXT, ip TEXT,
  serial TEXT, os TEXT, kind TEXT, state TEXT NOT NULL DEFAULT 'pendiente', item INTEGER, seen TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);
";

/// Migraciones numeradas: la BD guarda por cuál va (PRAGMA user_version). Nunca cambies ni reordenes las que hay: añade al final.
pub const MIGRATIONS: &[&str] = &[
    "ALTER TABLE maps ADD COLUMN data TEXT NOT NULL DEFAULT '{}'",
    "ALTER TABLE sources ADD COLUMN v3 INTEGER DEFAULT 0",
    "ALTER TABLE sources ADD COLUMN auth TEXT DEFAULT 'sha'",
    "ALTER TABLE sources ADD COLUMN priv TEXT DEFAULT 'aes'",
    "ALTER TABLE sources ADD COLUMN priv_pass TEXT DEFAULT ''",
    "ALTER TABLE sources ADD COLUMN alerted TEXT",
    "ALTER TABLE sources ADD COLUMN mute_until TEXT",
    "ALTER TABLE checks ADD COLUMN kind TEXT DEFAULT 'ping'",
    "ALTER TABLE checks ADD COLUMN port INTEGER",
    "ALTER TABLE checks ADD COLUMN url TEXT DEFAULT ''",
    "ALTER TABLE checks ADD COLUMN expect TEXT DEFAULT ''",
    "ALTER TABLE checks ADD COLUMN warn_days INTEGER DEFAULT 30",
    "ALTER TABLE checks ADD COLUMN detail TEXT",
    "ALTER TABLE checks ADD COLUMN alerted TEXT",
    "ALTER TABLE checks ADD COLUMN mute_until TEXT",
    "ALTER TABLE incidents ADD COLUMN parent INTEGER",
    "ALTER TABLE agents ADD COLUMN source INTEGER",
    "ALTER TABLE items ADD COLUMN warranty TEXT DEFAULT ''",
    "ALTER TABLE checks ADD COLUMN sound TEXT DEFAULT ''",
    // 19: desde aquí, numeradas desde el principio
    "ALTER TABLE maps ADD COLUMN version INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE incidents ADD COLUMN version INTEGER NOT NULL DEFAULT 0",
    "ALTER TABLE users ADD COLUMN totp TEXT NOT NULL DEFAULT ''",
    "CREATE TABLE expiries(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL DEFAULT '', kind TEXT DEFAULT 'licencia', date TEXT DEFAULT '', \
     item INTEGER, notes TEXT DEFAULT '', updated TEXT DEFAULT CURRENT_TIMESTAMP)",
    "CREATE TABLE syslog(ts TEXT DEFAULT CURRENT_TIMESTAMP, item INTEGER, ip TEXT, sev INTEGER, msg TEXT)",
    "CREATE INDEX syslog_i ON syslog(item, ts)",
    "CREATE TABLE subnets(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL DEFAULT '', cidr TEXT NOT NULL DEFAULT '', vlan TEXT DEFAULT '', \
     notes TEXT DEFAULT '', scan TEXT, scanned TEXT, updated TEXT DEFAULT CURRENT_TIMESTAMP)",
    "ALTER TABLE checks ADD COLUMN mute_from TEXT",
    "ALTER TABLE sources ADD COLUMN mute_from TEXT",
    "ALTER TABLE agents ADD COLUMN ukey TEXT /*sha256 de la clave de incidencias de Kitty, que pueden leer los usuarios del PC*/",
    "CREATE TABLE tasks(id INTEGER PRIMARY KEY AUTOINCREMENT, user INTEGER NOT NULL, text TEXT NOT NULL, col TEXT NOT NULL DEFAULT 'pendiente',      pos REAL NOT NULL DEFAULT 0, updated TEXT DEFAULT CURRENT_TIMESTAMP)",
    "CREATE TABLE apps(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL DEFAULT '', winget TEXT NOT NULL DEFAULT '',      notes TEXT DEFAULT '', updated TEXT DEFAULT CURRENT_TIMESTAMP) /*programas que Kitty instala y mantiene al día con winget*/",
    "ALTER TABLE users ADD COLUMN ext TEXT NOT NULL DEFAULT '' /*usuario del dominio: ldap:sAMAccountName u oidc:emisor|sub; vacío, local*/",
    "CREATE TABLE software(item INTEGER NOT NULL, name TEXT NOT NULL, version TEXT DEFAULT '', publisher TEXT DEFAULT '') /*programas instalados que cuenta Kitty, si la política lo permite*/;      CREATE INDEX software_item ON software(item)",
    "ALTER TABLE notes ADD COLUMN public INTEGER DEFAULT 0 /*la ve el usuario del PC en Kitty*/;      ALTER TABLE pages ADD COLUMN kitty INTEGER DEFAULT 0 /*la sugiere Kitty antes de abrir un aviso*/;      CREATE TABLE notices(id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT NOT NULL, items TEXT NOT NULL DEFAULT '[]' /*ids de equipos; vacío = todos*/,        until TEXT NOT NULL, who TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);      CREATE TABLE files(id INTEGER PRIMARY KEY AUTOINCREMENT, incident INTEGER, name TEXT NOT NULL, mime TEXT NOT NULL, data BLOB NOT NULL,        who TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);      CREATE TABLE scripts(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL DEFAULT '', body TEXT NOT NULL DEFAULT '', notes TEXT DEFAULT '',        updated TEXT DEFAULT CURRENT_TIMESTAMP);      CREATE TABLE runs(id INTEGER PRIMARY KEY AUTOINCREMENT, script INTEGER, name TEXT NOT NULL, body TEXT NOT NULL, item INTEGER NOT NULL,        agent INTEGER NOT NULL, who TEXT, state TEXT NOT NULL DEFAULT 'pendiente', code INTEGER, output TEXT DEFAULT '',        created TEXT DEFAULT CURRENT_TIMESTAMP, done TEXT);      CREATE INDEX runs_agent ON runs(agent, state)",
];
/// Las de antes de numerarlas: una BD vieja (user_version 0) puede tener ya cualquiera de ellas.
const LEGACY: usize = 19;

fn migrate(c: &Connection, fresh: bool) -> anyhow::Result<()> {
    let ver = c.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0))?.max(0) as usize;
    if ver > MIGRATIONS.len() {
        anyhow::bail!("Esta base de datos es de un catlan más nuevo (migración {ver}; este llega a la {}). Actualiza catlan.", MIGRATIONS.len());
    }
    if ver < MIGRATIONS.len() && !fresh {
        // copia completa antes de tocar nada
        backup_to(&DATA.join(format!("catlan-antes-de-v{}-{}.db", MIGRATIONS.len(), local("%Y%m%d-%H%M%S"))))?;
    }
    for (n, sql) in MIGRATIONS.iter().enumerate().skip(ver) {
        if let Err(e) = c.execute_batch(sql)
            && !(n < LEGACY && e.to_string().contains("duplicate column"))
        {
            return Err(e.into());
        }
        c.execute_batch(&format!("PRAGMA user_version={}", n + 1))?;
    }
    Ok(())
}

/// Ids que nunca se reutilizan. Sin AUTOINCREMENT, SQLite da a lo nuevo el id del último borrado, y lo nuevo heredaba
/// su historial en Actividad y sus enlaces ([[#id]], esquemas, racks, incidencias). Las BDs de antes se reconstruyen una vez.
fn rebuild_ids(c: &mut Connection) -> anyhow::Result<()> {
    let old: Vec<String> = c.prepare("SELECT name FROM sqlite_master WHERE type='table' AND sql LIKE '%(id INTEGER PRIMARY KEY,%'")?.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;
    if old.is_empty() {
        return Ok(());
    }
    backup_to(&DATA.join(format!("catlan-antes-de-ids-{}.db", local("%Y%m%d-%H%M%S"))))?;
    let kinds = |t: &str| -> &'static [&'static str] {
        match t {
            "pages" => &["page"],
            "items" => &["item"],
            "maps" => &["map", "rack"],
            "checks" => &["check"],
            "sources" => &["source"],
            "users" => &["user"],
            "groups" => &["group"],
            "incidents" => &["incident"],
            "agents" => &["agent"],
            _ => &[],
        }
    };
    let tx = c.transaction()?;
    for t in &old {
        let sql: String = tx.query_row("SELECT sql FROM sqlite_master WHERE name=?", [t], |r| r.get(0))?;
        let new = crate::re!(r#"^CREATE TABLE (?:IF NOT EXISTS )?"?\w+"?"#).replacen(&sql, 1, format!("CREATE TABLE {t}_new").as_str()).replacen(
            "(id INTEGER PRIMARY KEY,",
            "(id INTEGER PRIMARY KEY AUTOINCREMENT,",
            1,
        );
        tx.execute_batch(&new)?;
        tx.execute_batch(&format!("INSERT INTO {t}_new SELECT * FROM {t}; DROP TABLE {t}; ALTER TABLE {t}_new RENAME TO {t};"))?;
    }
    for t in &old {
        // el contador empieza por encima de lo que se ve en Actividad: tampoco vuelven los ids ya borrados
        let k = kinds(t);
        let marks = if k.is_empty() { "NULL".to_string() } else { vec!["?"; k.len()].join(",") };
        let top: Option<i64> =
            tx.query_row(&format!("SELECT MAX(x) FROM (SELECT MAX(id) AS x FROM {t} UNION ALL SELECT MAX(ref) FROM log WHERE kind IN ({marks}))"), params_from_iter(k.iter()), |r| r.get(0))?;
        tx.execute("DELETE FROM sqlite_sequence WHERE name=?", [t])?;
        tx.execute("INSERT INTO sqlite_sequence(name, seq) VALUES(?, ?)", rusqlite::params![t, top.unwrap_or(0)])?;
    }
    tx.commit()?;
    c.execute_batch(SCHEMA)?; // los índices se fueron con las tablas viejas
    println!("ids sin reutilizar: tablas reconstruidas (copia en {})", DATA.display());
    Ok(())
}

/// Abre (o crea) la base de datos, la pone al día y deja lista la instalación.
pub fn init() -> anyhow::Result<()> {
    std::fs::create_dir_all(&*DATA)?;
    let mut c = connect()?;
    let integrity: String = c.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
    if integrity != "ok" {
        println!("ATENCIÓN: la base de datos tiene daños (PRAGMA integrity_check): {integrity}\nRestaura la última copia de data/backups/ con catlan parado.");
    }
    let _ = INTEGRITY.set(integrity);
    let fresh = c.query_row("SELECT 1 FROM sqlite_master", [], |_| Ok(())).is_err();
    c.execute_batch(SCHEMA)?;
    migrate(&c, fresh)?;
    rebuild_ids(&mut c)?;
    let _ = WRITER.set(Mutex::new(c));
    // Id de esta instalación (va en la BD, así sobrevive a copias y cambios de IP): un Kitty aceptado solo habla con ella
    q("INSERT OR IGNORE INTO meta(k, v) VALUES('instance', ?)", crate::p![crate::crypto::token_hex(16)])?;
    let _ = INSTANCE.set(val("SELECT v FROM meta WHERE k='instance'", vec![])?.as_str().unwrap_or_default().to_string());
    Ok(())
}

#[cfg(test)]
pub fn test_init() {
    // Una BD temporal para las pruebas de este proceso
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let d = std::env::temp_dir().join(format!("catlan-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        unsafe { std::env::set_var("CATLAN_DATA", &d) };
        init().unwrap();
    });
}
