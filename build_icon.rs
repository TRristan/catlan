// Icono del .exe en Windows, para los build.rs de catlan y de Kitty (con include!). Sin rc.exe ni dependencias:
// se escribe a mano el .res con el icono (RT_ICON por tamaño y un RT_GROUP_ICON) y el enlazador de MSVC lo mete en el .exe.

/// Un recurso en un .res: cabecera de 32 bytes (tipo y nombre por número) y los datos, alineados a 4.
fn res_entry(out: &mut Vec<u8>, kind: u16, id: u16, flags: u16, data: &[u8]) {
    out.extend((data.len() as u32).to_le_bytes());
    out.extend(32u32.to_le_bytes());
    out.extend([0xFFFF, kind, 0xFFFF, id].iter().flat_map(|v: &u16| v.to_le_bytes()));
    out.extend([0u8; 4]); // DataVersion
    out.extend(flags.to_le_bytes());
    out.extend(0x0409u16.to_le_bytes()); // idioma
    out.extend([0u8; 8]); // Version, Characteristics
    out.extend(data);
    out.resize(out.len().next_multiple_of(4), 0);
}

/// El .res con las imágenes de un .ico (que puede llevarlas en PNG). Panics si el .ico no es válido: mejor no compilar.
fn ico_to_res(ico: &[u8]) -> Vec<u8> {
    let u16_at = |o: usize| u16::from_le_bytes([ico[o], ico[o + 1]]);
    let u32_at = |o: usize| u32::from_le_bytes([ico[o], ico[o + 1], ico[o + 2], ico[o + 3]]) as usize;
    assert!(ico.len() > 6 && u16_at(0) == 0 && u16_at(2) == 1, "no es un .ico");
    let n = u16_at(4) as usize;
    let mut res = Vec::new();
    res_entry(&mut res, 0, 0, 0, &[]); // el .res empieza con una entrada vacía
    let mut group = [0u16, 1, n as u16].iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<u8>>();
    for i in 0..n {
        let e = 6 + 16 * i;
        let (size, off) = (u32_at(e + 8), u32_at(e + 12));
        res_entry(&mut res, 3, i as u16 + 1, 0x1010, &ico[off..off + size]); // RT_ICON
        group.extend(&ico[e..e + 12]); // ancho, alto, colores, reservado, planos, bits y tamaño, como en el .ico
        group.extend((i as u16 + 1).to_le_bytes()); // y el id de su RT_ICON en vez del desplazamiento
    }
    res_entry(&mut res, 14, 1, 0x1030, &group); // RT_GROUP_ICON: el primero es el icono del .exe
    res
}

/// Mete `ico` como icono del ejecutable (solo Windows con MSVC; en lo demás no hace nada).
fn exe_icon(ico: &str) {
    println!("cargo:rerun-if-changed={ico}");
    let target = |k: &str| std::env::var(k).unwrap_or_default();
    if target("CARGO_CFG_TARGET_OS") != "windows" || target("CARGO_CFG_TARGET_ENV") != "msvc" {
        return;
    }
    let res = std::path::Path::new(&target("OUT_DIR")).join("icono.res");
    std::fs::write(&res, ico_to_res(&std::fs::read(ico).expect("falta el .ico"))).unwrap();
    println!("cargo:rustc-link-arg-bins={}", res.display());
}
