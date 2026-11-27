//! Une la web de src/web/ en una sola página: index.html con todo el CSS en su <style> y todo el JS en su <script>.
//! Los archivos se pegan en orden de nombre (10-…, 20-…), así que el número decide el orden. Sale en $OUT_DIR/index.html.
use std::{env, fs, path::Path};

// Un clon de Git en Windows deja CRLF: se pasa a LF y la página sale igual (y con el mismo ETag) en cualquier sistema
fn read(p: &Path) -> String {
    fs::read_to_string(p).unwrap().replace("\r\n", "\n")
}

fn join(dir: &Path, ext: &str) -> String {
    let mut files: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|e| e == ext)).collect();
    files.sort();
    files.iter().map(|p| read(p)).collect()
}

fn main() {
    let web = Path::new("src/web");
    println!("cargo:rerun-if-changed=src/web");
    let page = read(&web.join("index.html"));
    assert!(page.matches("/* @css */\n").count() == 1 && page.matches("/* @js */\n").count() == 1, "src/web/index.html necesita /* @css */ y /* @js */ una vez cada uno");
    let page = page.replace("/* @css */\n", &join(&web.join("css"), "css")).replace("/* @js */\n", &join(&web.join("js"), "js"));
    fs::write(Path::new(&env::var("OUT_DIR").unwrap()).join("index.html"), page).unwrap();
}
