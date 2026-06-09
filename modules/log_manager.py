import os
import json
from datetime import datetime

# Ruta estandarizada de auditoria
LOG_PATH = "logs/events.log"

def registrar_evento(id_alerta, modulo, criticidad, mensaje):
    """ Registra un evento de seguridad en formato JSON estructurado y mantiene la persistencia en modo Append sin alterar registros previos"""
    # Garantizar la existencia del directorio de logs de forma automática
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    
    # Construccion del objeto JSON estructurado para el parseo del Dashboard
    evento = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "id_alerta": id_alerta,
        "modulo": modulo,
        "criticidad": criticidad,
        "mensaje": mensaje
    }
    
    # Escritura inline para evitar corrupcion de archivo
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(evento) + "\n")
