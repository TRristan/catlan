#!/bin/sh
# Kitty para catlan, versión Linux: instalador. catlan lo sirve en /kitty.sh con su dirección y su id ya puestos.
# En el equipo, como root: el comando de catlan (Inventario → Añadir con Kitty). Va por https y, con el certificado
# autofirmado de catlan, solo acepta ese (curl --pinnedpubkey con la huella de SPKI).
# Deja un temporizador (systemd, o cron si no hay systemd) que cada 5 minutos envía a catlan lo mismo que el Kitty de
# Windows: nombre, sistema, modelo, CPU, memoria, discos, IPs, tiempo encendido, nº de serie y los errores y críticos
# del journal. Nada de usuarios, programas, procesos ni archivos. Necesita curl.
# Para quitarlo: sh /usr/local/lib/kitty-agent.sh quitar
set -eu
URL='{{URL}}'
CATLAN='{{ID}}'
SPKI='{{SPKI}}' # sha256 de la clave pública de catlan; vacío si tiene un certificado propio de una CA
DIR=${KITTY_DIR:-/etc/kitty} # KITTY_DIR: para probarlo sin root
AGENT=/usr/local/lib/kitty-agent.sh

[ "$(id -u)" = 0 ] || { echo "Kitty: ejecútalo como root (curl ... | sudo sh)." >&2; exit 1; }
command -v curl >/dev/null || { echo "Kitty: necesita curl." >&2; exit 1; }
umask 077 # la clave, solo para root: quien la tenga se hace pasar por este equipo
mkdir -p "$DIR" "$(dirname "$AGENT")"
[ -s "$DIR/key" ] || od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "$DIR/key" # 256 bits aleatorios
KEY=$(cat "$DIR/key")

# Lo que corre cada 5 minutos
cat > "$AGENT" <<'AGENT'
#!/bin/sh
URL='{{URL}}'
CATLAN='{{ID}}'
SPKI='{{SPKI}}' # sha256 de la clave pública de catlan; vacío si tiene un certificado propio de una CA
DIR=${KITTY_DIR:-/etc/kitty} # KITTY_DIR: para probarlo sin root
if [ "${1:-}" = quitar ]; then
    systemctl disable --now kitty.timer 2>/dev/null || true
    rm -rf /etc/systemd/system/kitty.service /etc/systemd/system/kitty.timer /etc/cron.d/kitty "$DIR" "$0"
    echo "Kitty quitado."; exit 0
fi
note() { printf '%s\n%s\n%s\n' "$1" "$(date +%Y-%m-%dT%H:%M:%S)" "$2" > "$DIR/state"; }
j() { printf '"%s"' "$(printf %s "$1" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g')"; } # texto JSON
cpu() { awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5+$6}' /proc/stat; }
set -- $(cpu); t1=$1 i1=$2; sleep 1; set -- $(cpu)
load=$(( ($1 - t1) > 0 ? 100 * (($1 - t1) - ($2 - i1)) / ($1 - t1) : 0 ))
. /etc/os-release 2>/dev/null || PRETTY_NAME=Linux
serial=$(cat /sys/class/dmi/id/product_serial 2>/dev/null || true)
case "$(printf %s "$serial" | tr A-Z a-z)" in ''|0|none|default*|to\ be\ filled*|system\ serial*|not\ *) serial='' ;; esac
mem() { awk -v k="$1:" '$1 == k {print $2 * 1024}' /proc/meminfo; }
disks=$(df -P -k 2>/dev/null | awk 'NR > 1 && $1 ~ /^\/dev\// && !s[$1]++ {printf "%s{\"name\":\"%s\",\"total\":%d,\"free\":%d}", n++ ? "," : "", $6, $2 * 1024, $4 * 1024}')
ips=$(ip -o addr show scope global 2>/dev/null | awk '{split($4, a, "/"); printf "%s\"%s\"", n++ ? "," : "", a[1]}')
since=$(cat "$DIR/since" 2>/dev/null || echo $(( $(date +%s) - 86400 )))
now=$(date +%s)
events=$(for p in 0..2 3..3; do # críticos (nivel 1) y errores (nivel 2) del journal desde el último envío, sin rutas de usuario
    journalctl -q --no-pager -p "$p" --since "@$since" -o short-unix -n 10 2>/dev/null | while read -r ts host who msg; do
        printf '{"rec":%s,"log":"journal","time":"%s","level":%s,"source":%s,"code":0,"msg":%s}\n' "$(printf %s "$ts" | tr -d .)" \
            "$(date -u -d "@${ts%.*}" +%Y-%m-%dT%H:%M:%SZ)" "$([ "$p" = 3..3 ] && echo 2 || echo 1)" "$(j "$(printf %s "$who" | cut -d'[' -f1 | tr -d :)")" \
            "$(j "$(printf %s "$msg" | sed 's#/home/[^/ ]*#/home/(usuario)#g' | cut -c1-400)")"
    done
done | paste -sd, -)
body="{\"key\":\"$(cat "$DIR/key")\",\"name\":$(j "$(hostname)"),\"ip\":\"\",\"serial\":$(j "$serial"),\"os\":\"linux/$(uname -m)\",\"kind\":\"servidor\",\"every\":5,
\"facts\":{\"osver\":$(j "$PRETTY_NAME $(uname -r)"),\"model\":$(j "$(cat /sys/class/dmi/id/sys_vendor /sys/class/dmi/id/product_name 2>/dev/null | paste -sd' ' -)"),
\"cpu\":$(j "$(awk -F': ' '/^model name/ {print $2; exit}' /proc/cpuinfo)"),\"cores\":$(nproc),\"load\":$load,\"mem_total\":$(mem MemTotal),
\"mem_free\":$(mem MemAvailable),\"uptime\":$(cut -d. -f1 /proc/uptime),\"serial\":$(j "$serial"),\"disks\":[$disks],\"ips\":[$ips]},\"events\":[$events]}"
if ! res=$(printf %s "$body" | curl -fsS -m 20 ${SPKI:+-k --pinnedpubkey sha256//$SPKI} -H 'Content-Type: application/json; charset=utf-8' --data-binary @- "$URL/api/agent" 2>&1); then
    note error "$res"; exit 1
fi
[ "$(printf %s "$res" | sed -n 's/.*"catlan": *"\([^"]*\)".*/\1/p')" = "$CATLAN" ] || { note error "$URL no es el catlan que lo instaló"; exit 1; } # atado a este catlan
state=$(printf %s "$res" | sed -n 's/.*"state": *"\([^"]*\)".*/\1/p')
[ "$state" = adoptado ] && echo "$now" > "$DIR/since" # pendiente: los eventos esperan a que lo acepten
note "$state" ''
AGENT
chmod 700 "$AGENT"

if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then
    cat > /etc/systemd/system/kitty.service <<EOF
[Unit]
Description=Kitty: envía a catlan ($URL) el estado de este equipo
[Service]
Type=oneshot
ExecStart=$AGENT
TimeoutStartSec=120
EOF
    cat > /etc/systemd/system/kitty.timer <<EOF
[Unit]
Description=Kitty cada 5 minutos y al arrancar
[Timer]
OnBootSec=1min
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now kitty.timer >/dev/null
else
    printf '*/5 * * * * root %s >/dev/null 2>&1\n@reboot root %s >/dev/null 2>&1\n' "$AGENT" "$AGENT" > /etc/cron.d/kitty
fi
rm -f "$DIR/state"
"$AGENT" || true

code=$(printf %s "$KEY" | sha256sum | cut -c1-8 | tr a-f A-F | sed 's/^\(....\)/\1-/')
echo "Kitty instalado en $(hostname) (código $code)."
state=$(head -n1 "$DIR/state" 2>/dev/null || true)
case "$state" in
    pendiente) echo "Acéptalo en catlan: Inventario → Kitty pide entrar (código $code)." ;;
    error) echo "Primer envío con error: $(sed -n 3p "$DIR/state")" ;;
    ?*) echo "Primer envío: $state." ;;
esac
