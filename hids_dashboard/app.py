from flask import Flask, render_template, jsonify, request, Response
from datetime import datetime, timedelta
from pathlib import Path
import json, os, re, random, csv, io

app = Flask(__name__)

# 1. Detecta la carpeta actual (hids_dashboard)
CARPETA_DASHBOARD = Path(__file__).resolve().parent

# 2. SUBE UN NIVEL a la carpeta raíz (hids) para corregir el desvío
RAIZ_PROYECTO = CARPETA_DASHBOARD.parent

ALERTS_FILE = os.environ.get("ALERTS_FILE", str(RAIZ_PROYECTO / "logs" / "events.log"))
print(f"\n[DEBUG] El Dashboard está buscando los logs en: {ALERTS_FILE}\n")
# ─── Parser ──────────────────────────────────────────────────────────────────

def normalizar_criticidad(c):
    mapa = {
        "CRITICAL": "CRITICA", "CRITICA": "CRITICA",
        "HIGH": "ALTA",        "ALTA": "ALTA",
        "MEDIUM": "MEDIA",     "MEDIA": "MEDIA", "WARNING": "MEDIA",
        "LOW": "BAJA",         "BAJA": "BAJA",   "INFO": "BAJA",
    }
    return mapa.get((c or "").upper(), "BAJA")

TIPO_A_MODULO = {
    "ALERTA_INTEGRIDAD": ("file_integrity",  "CRITICA"),
    "ALERTA_CRITICA":    ("process_monitor", "CRITICA"),
    "ALERTA_WATCHDOG":   ("file_monitor",    "ALTA"),
    "ALERTA_MONITOR":    ("file_monitor",    "MEDIA"),
    "ALERTA_RED":        ("network_monitor", "ALTA"),
    "ALERTA_AUTH":       ("auth_monitor",    "ALTA"),
    "ALERTA_PROCESO":    ("process_monitor", "MEDIA"),
}

_RE_PLAIN = re.compile(
    r"^\[(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]\s+\[(?P<tipo>[^\]]+)\]\s+(?P<msg>.+)$"
)

def parsear_linea_texto(line):
    m = _RE_PLAIN.match(line)
    if not m:
        return None
    tipo = m.group("tipo").strip()
    modulo, crit = TIPO_A_MODULO.get(tipo, ("desconocido", "BAJA"))
    return {
        "timestamp":  m.group("ts"),
        "id_alerta":  tipo,
        "modulo":     modulo,
        "criticidad": crit,
        "mensaje":    m.group("msg").strip(),
        "host":       "localhost",
    }

def load_alerts():
    if not os.path.exists(ALERTS_FILE):
        return []
    alerts = []
    with open(ALERTS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                try:
                    a = json.loads(line)
                    a["criticidad"] = normalizar_criticidad(a.get("criticidad"))
                    a.setdefault("host", "localhost")
                    alerts.append(a)
                    continue
                except json.JSONDecodeError:
                    pass
            parsed = parsear_linea_texto(line)
            if parsed:
                alerts.append(parsed)
    return alerts

# ─── Filtros ─────────────────────────────────────────────────────────────────

def aplicar_filtros(alerts, args):
    """Filtra la lista de alertas según los parámetros de query string."""
    fecha_desde = args.get("desde")       # "YYYY-MM-DD"
    fecha_hasta = args.get("hasta")       # "YYYY-MM-DD"
    criticidad  = args.get("criticidad")  # "CRITICA,ALTA" o vacio
    modulos     = args.get("modulo")      # "file_integrity,auth_monitor" o vacio
    texto       = args.get("q", "").strip().lower()

    crits   = {c.strip().upper() for c in criticidad.split(",") if c.strip()} if criticidad else set()
    mods    = {m.strip() for m in modulos.split(",") if m.strip()} if modulos else set()

    result = []
    for a in alerts:
        ts_str = a.get("timestamp", "")

        # Filtro fecha desde
        if fecha_desde:
            try:
                if ts_str[:10] < fecha_desde:
                    continue
            except Exception:
                pass

        # Filtro fecha hasta
        if fecha_hasta:
            try:
                if ts_str[:10] > fecha_hasta:
                    continue
            except Exception:
                pass

        # Filtro criticidad
        if crits and a.get("criticidad", "").upper() not in crits:
            continue

        # Filtro modulo
        if mods and a.get("modulo", "") not in mods:
            continue

        # Busqueda de texto libre en mensaje, modulo y host
        if texto:
            haystack = " ".join([
                a.get("mensaje", ""),
                a.get("modulo", ""),
                a.get("host", ""),
                a.get("id_alerta", ""),
            ]).lower()
            if texto not in haystack:
                continue

        result.append(a)
    return result

# ─── Stats ────────────────────────────────────────────────────────────────────

def compute_stats(alerts):
    total = len(alerts)
    by_crit = {"CRITICA": 0, "ALTA": 0, "MEDIA": 0, "BAJA": 0}
    for a in alerts:
        c = (a.get("criticidad") or "BAJA").upper()
        if c in by_crit:
            by_crit[c] += 1

    by_module = {}
    for a in alerts:
        m = a.get("modulo", "desconocido")
        by_module[m] = by_module.get(m, 0) + 1

    now = datetime.now()
    hourly = {str(i): 0 for i in range(24)}
    for a in alerts:
        try:
            ts = datetime.strptime(a["timestamp"], "%Y-%m-%d %H:%M:%S")
            if now - ts <= timedelta(hours=24):
                hourly[str(ts.hour)] = hourly.get(str(ts.hour), 0) + 1
        except (ValueError, KeyError):
            pass

    recent = sorted(alerts, key=lambda x: x.get("timestamp", ""), reverse=True)[:10]
    hosts  = list({a.get("host", "localhost") for a in alerts})
    modulos_disponibles = sorted(by_module.keys())

    return {
        "total": total,
        "by_criticidad": by_crit,
        "by_modulo": by_module,
        "hourly": hourly,
        "recent": recent,
        "hosts_afectados": len(hosts),
        "hosts": hosts,
        "modulos_disponibles": modulos_disponibles,
    }

# ─── Rutas ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    alerts = load_alerts()
    filtradas = aplicar_filtros(alerts, request.args)
    return jsonify(compute_stats(filtradas))


@app.route("/api/alerts")
def api_alerts():
    alerts = load_alerts()
    filtradas = aplicar_filtros(alerts, request.args)
    ordenadas = sorted(filtradas, key=lambda x: x.get("timestamp", ""), reverse=True)
    return jsonify(ordenadas)


@app.route("/api/modulos")
def api_modulos():
    """Devuelve la lista de módulos disponibles para poblar el filtro."""
    alerts = load_alerts()
    modulos = sorted({a.get("modulo", "desconocido") for a in alerts})
    return jsonify(modulos)


@app.route("/api/export/csv")
def export_csv():
    """Exporta las alertas filtradas como CSV descargable."""
    alerts  = load_alerts()
    filtradas = aplicar_filtros(alerts, request.args)
    ordenadas = sorted(filtradas, key=lambda x: x.get("timestamp", ""), reverse=True)

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=["timestamp", "id_alerta", "modulo", "criticidad", "mensaje", "host"],
        extrasaction="ignore",
        lineterminator="\n",
    )
    writer.writeheader()
    for a in ordenadas:
        writer.writerow(a)

    filename = f"hids_alertas_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ─── Demo ─────────────────────────────────────────────────────────────────────

@app.route("/api/demo/generate")
def generate_demo():
    modulos = ["auth_monitor", "file_integrity", "file_monitor",
               "network_monitor", "process_monitor"]
    criticidades = ["CRITICA", "ALTA", "MEDIA", "BAJA"]
    pesos = [0.1, 0.2, 0.35, 0.35]
    mensajes = {
        "auth_monitor":    ["Múltiples intentos de login fallidos", "Acceso SSH desde IP externa"],
        "file_integrity":  ["Hash modificado en /etc/passwd", "Cambio en /etc/sudoers"],
        "file_monitor":    ["Nuevo ejecutable en /tmp/", "Eliminación de logs"],
        "network_monitor": ["Escaneo de puertos detectado", "Conexión a IP sospechosa"],
        "process_monitor": ["Proceso con privilegios root", "Shell inversa detectada"],
    }
    now = datetime.now()
    demo_alerts = []
    for i in range(80):
        modulo = random.choice(modulos)
        crit   = random.choices(criticidades, weights=pesos)[0]
        ts     = now - timedelta(minutes=random.randint(0, 1440))
        demo_alerts.append({
            "timestamp":  ts.strftime("%Y-%m-%d %H:%M:%S"),
            "id_alerta":  f"ALT-{1000 + i}",
            "modulo":     modulo,
            "criticidad": crit,
            "mensaje":    random.choice(mensajes[modulo]),
            "host":       random.choice(["web-server-01", "db-server-02", "app-node-05"]),
        })
    with open(ALERTS_FILE, "w", encoding="utf-8") as f:
        for alerta in demo_alerts:
            f.write(json.dumps(alerta, ensure_ascii=False) + "\n")
    return jsonify({"ok": True, "generadas": len(demo_alerts)})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
