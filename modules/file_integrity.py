import hashlib  # libreria encargada de las funciones hash y algoritmos de cifrado, huella diigital de una rchivo 
import os       # permite que python ejecute comandos y acciones, sirve para verficar archivos, crear directorios etc
import json     # al calcualr huellas, las guardamos en disco duro en este formato de texto
from datetime import datetime

#funcion centralizada de logs en JSON
from modules.log_manager import registrar_evento

# Archivos criticos definidos para el control de seguridad
CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow"
]

BASELINE_PATH = "data/baseline.json"
LOG_PATH = "logs/events.log"

def calcular_sha256(ruta_archivo):
    """Calcula el hash SHA-256 de un archivo de forma eficiente por bloques"""
    hash_sha256 = hashlib.sha256()
    try:
        with open(ruta_archivo, "rb") as f:
            for bloque in iter(lambda: f.read(4096), b""):
                hash_sha256.update(bloque)
        return hash_sha256.hexdigest()
    except FileNotFoundError:
        return None
    except PermissionError:
        # Se captura el error de privilegios para archivos restrictivos como /etc/shadow
        return "ERROR_PERMISOS"


def generar_baseline():
    """Calcula y almacena los hashes de referencia iniciales en un archivo JSON junto con la marca temporal"""
    # Nueva estructura que soporta metadatos de tiempo
    baseline_estructura = {
        "fecha_generacion": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hashes": {}
    }
    
    for archivo in CRITICAL_FILES:
        hash_actual = calcular_sha256(archivo)
        if hash_actual and hash_actual != "ERROR_PERMISOS":
            baseline_estructura["hashes"][archivo] = hash_actual
        elif hash_actual == "ERROR_PERMISOS":
            print(f"[!] Advertencia: Se requieren privilegios sudo para leer {archivo}")
    
    # Crear carpetas contenedoras si no existen por seguridad
    os.makedirs(os.path.dirname(BASELINE_PATH), exist_ok=True)
    with open(BASELINE_PATH, "w") as f:
        json.dump(baseline_estructura, f, indent=4)
    print(f"[*] Baseline guardada exitosamente en {BASELINE_PATH} el {baseline_estructura['fecha_generacion']}")


def verificar_integridad():
    """Compara los hashes en tiempo real contra la linea base estatica, contrastando marcas de tiempo."""
    if not os.path.exists(BASELINE_PATH):
        print("[-] No se encontro una linea base previa. Creando baseline inicial...")
        generar_baseline()
        return

    with open(BASELINE_PATH, "r") as f:
        datos_json = json.load(f)

    # Extraemos de forma segura la fecha vieja y los hashes
    fecha_baseline = datos_json.get("fecha_generacion", "Fecha desconocida")
    baseline = datos_json.get("hashes", {})
    
    fecha_actual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for archivo in CRITICAL_FILES:
        hash_actual = calcular_sha256(archivo)
        
        if hash_actual == "ERROR_PERMISOS":
            registrar_evento("ALERTA_INTEGRIDAD", "file_integrity", "CRITICAL", f"Acceso denegado en auditoria del archivo: {archivo}")
            continue

        # Evaluación analitica de integridad:
        # Caso 1: El archivo existia en el baseline pero fue borrado
        if archivo in baseline and hash_actual is None:
            registrar_evento("ALERTA_INTEGRIDAD", "file_integrity", "CRITICAL", f"El archivo critico ha sido ELIMINADO: {archivo}")
        
        # Caso 2: El hash actual no coincide con la firma registrada (Modificacion)
        elif archivo in baseline and hash_actual != baseline[archivo]:
            mensaje_log = f"MODIFICACIÓN DETECTADA en: {archivo} (Hash previo: {baseline[archivo][:10]}... -> Actual: {hash_actual[:10]}...)"
            registrar_evento("ALERTA_INTEGRIDAD", "file_integrity", "CRITICAL", mensaje_log)
            
            # Formato extendido profesional en pantalla para la catedra
            print(f"[ALERTA] MODIFICACIÓN DETECTADA en: {archivo}")
            print(f"  └─► Firma legítima guardada el : {fecha_baseline} ({baseline[archivo][:10]}...)")
            print(f"  └─► Firma hostil detectada el  : {fecha_actual} ({hash_actual[:10]}...)")

        # Caso 3: Archivo nuevo que no estaba contemplado en la firma inicial
        elif archivo not in baseline and hash_actual is not None:
            registrar_evento("ALERTA_INTEGRIDAD", "file_integrity", "CRITICAL", f"Nuevo archivo critico detectado fuera de la linea base: {archivo}")

if __name__ == "__main__":
    print("[+] Ejecutando verificacion de prueba de integridad...")
    verificar_integridad()
