# HIDS Dashboard

Dashboard web para tu sistema HIDS en Python. Se conecta a tu `alerts.json` existente y lo muestra en tiempo real con gráficos.

## Estructura esperada del JSON

El dashboard lee el mismo formato que ya genera tu HIDS:

```json
[
  {
    "timestamp": "2026-06-10 14:32:00",
    "id_alerta": "ALT-1001",
    "modulo": "auth_monitor",
    "criticidad": "CRITICA",
    "mensaje": "Múltiples intentos de login fallidos",
    "host": "web-server-01"
  }
]
```

> El campo `host` es opcional pero recomendado. Agrégalo en tu `log_manager.py` si aún no lo tienes.

---

## Instalación

```bash
cd hids_dashboard
pip install -r requirements.txt
```

---

## Configuración

Por defecto el dashboard busca `alerts.json` en la carpeta donde se ejecuta.  
Puedes cambiar la ruta con la variable de entorno `ALERTS_FILE`:

```bash
export ALERTS_FILE="/ruta/a/tu/alerts.json"
```

---

## Ejecución en desarrollo

```bash
python app.py
# Abre http://localhost:5000
```

---

## Ejecución en producción (con dominio)

### 1. Instalar Gunicorn y Nginx

```bash
pip install gunicorn
sudo apt install nginx -y
```

### 2. Levantar Gunicorn

```bash
gunicorn -w 4 -b 127.0.0.1:5000 app:app
```

O como servicio systemd (recomendado):

```ini
# /etc/systemd/system/hids-dashboard.service
[Unit]
Description=HIDS Dashboard
After=network.target

[Service]
User=tu_usuario
WorkingDirectory=/ruta/a/hids_dashboard
Environment="ALERTS_FILE=/ruta/a/alerts.json"
ExecStart=/usr/bin/gunicorn -w 4 -b 127.0.0.1:5000 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable hids-dashboard
sudo systemctl start hids-dashboard
```

### 3. Configurar Nginx como reverse proxy

```nginx
# /etc/nginx/sites-available/hids
server {
    listen 80;
    server_name tu-dominio.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/hids /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

### 4. HTTPS con Certbot (opcional pero recomendado)

```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d tu-dominio.com
```

---

## Integración con tu log_manager.py

En tu `log_manager.py`, asegúrate de guardar las alertas en el mismo archivo que lee el dashboard. Si usas append, cambia el modo de escritura:

```python
import json, os

ALERTS_FILE = os.environ.get("ALERTS_FILE", "alerts.json")

def guardar_alerta(evento: dict):
    """Agrega una alerta al JSON existente."""
    alertas = []
    if os.path.exists(ALERTS_FILE):
        with open(ALERTS_FILE, "r") as f:
            try:
                alertas = json.load(f)
            except json.JSONDecodeError:
                alertas = []
    alertas.append(evento)
    with open(ALERTS_FILE, "w") as f:
        json.dump(alertas, f, ensure_ascii=False, indent=2)
```

---

## Ruta de demo (solo para pruebas)

Visita `http://localhost:5000/api/demo/generate` para generar 80 alertas de ejemplo.  
**Elimina esta ruta en producción** (comenta el decorador `@app.route("/api/demo/generate")` en `app.py`).

---

## API disponible

| Ruta | Descripción |
|------|-------------|
| `GET /` | Dashboard visual |
| `GET /api/stats` | Métricas agregadas en JSON |
| `GET /api/alerts` | Últimas 50 alertas en JSON |
| `GET /api/demo/generate` | Genera alertas de prueba (solo dev) |
