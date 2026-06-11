from flask import Flask, render_template, jsonify
from datetime import datetime, timedelta
import json
import os
import re
import random

app = Flask(__name__)

# ─── Ruta a tu archivo de alertas ───────────────────────────────────────────
ALERTS_FILE = os.environ.get("ALERTS_FILE", "events.log")


# ─── Parser de formato mixto ─────────────────────────────────────────────────

def normalizar_criticidad(c):
    """Normaliza criticidades en inglés/español a los valores del dashboard."""
    mapa = {
        "CRITICAL": "CRITICA", "CRITICA": "CRITICA",
        "HIGH": "ALTA",        "ALTA": "ALTA",
        "MEDIUM": "MEDIA",     "MEDIA": "MEDIA", "WARNING": "MEDIA",
        "LOW": "BAJA",         "BAJA": "BAJA",   "INFO": "BAJA",
    }
    return mapa.get((c or "").upper(), "BAJA")


# Mapeo de tipo de alerta (texto plano) → módulo y criticidad
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
    """Parsea líneas de texto plano: [timestamp] [TIPO] mensaje"""
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
    """Carga alertas desde events.log — soporta texto plano y JSONL mezclados."""
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


def compute_stats(alerts):
    """Calcula todas las métricas que necesita el dashboard."""
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
    hosts = list({a.get("host", "localhost") for a in alerts})

    return {
        "total": total,
        "by_criticidad": by_crit,
        "by_modulo": by_module,
        "hourly": hourly,
        "recent": recent,
        "hosts_afectados": len(hosts),
        "hosts": hosts,
    }


# ─── Rutas ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


@app.route("/api/stats")
def api_stats():
    alerts = load_alerts()
    stats = compute_stats(alerts)
    return jsonify(stats)


@app.route("/api/alerts")
def api_alerts():
    alerts = load_alerts()
    recent = sorted(alerts, key=lambda x: x.get("timestamp", ""), reverse=True)[:50]
    return jsonify(recent)


# ─── Generador de datos de prueba ────────────────────────────────────────────

@app.route("/api/demo/generate")
def generate_demo():
    """Genera alertas de demo en events.log. Eliminar en producción."""
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
        crit = random.choices(criticidades, weights=pesos)[0]
        ts = now - timedelta(minutes=random.randint(0, 1440))
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
    app.run(host="0.0.0.0", port=5000, debug=True)
