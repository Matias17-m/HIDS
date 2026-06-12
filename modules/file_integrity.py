import hashlib  # libreria encargada de las funciones hash y algoritmos de cifrado, huella diigital de una rchivo 
import os       # permite que python ejecute comandos y acciones, sirve para verficar archivos, crear directorios etc
import json     # al calcualr huellas, las guardamos en disco duro en este formato de texto
import difflib  # compara textos línea por línea para análisis forense
from datetime import datetime

#funcion centralizada de logs en JSON
from modules.log_manager import registrar_evento

# Archivos criticos definidos para el control de seguridad
CRITICAL_FILES = [
    "/etc/passwd",
    "/etc/shadow"
]

BASELINE_PATH = "data/baseline.json"
BACKUP_DIR = "data/backups"  # carpeta segura para almacenar los textos de referencia limpios

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
        return "ERROR_PERMISOS"


def obtener_detalles_diff(ruta_archivo):
    """ Compara el archivo modificado contra su respaldo limpio y extrae la linea exacta alterada"""
    nombre_seguro = ruta_archivo.replace("/", "_")
    ruta_respaldo = os.path.join(BACKUP_DIR, f"{nombre_seguro}.bak")
    
    if not os.path.exists(ruta_respaldo):
        return "No hay respaldo previo disponible para comparar diferencias"

    try:
        # Leer el texto original guardado en el baseline
        with open(ruta_respaldo, "r", encoding="utf-8", errors="ignore") as f:
            lineas_viejas = f.readlines()
        
        # Leer el texto alterado actual
        with open(ruta_archivo, "r", encoding="utf-8", errors="ignore") as f:
            lineas_nuevas = f.readlines()
        
        # Computar la diferencia estructural limpia
        diferencias = list(difflib.unified_diff(lineas_viejas, lineas_nuevas, lineterm=""))
        
        cambios = []
        for linea in diferencias:
            if linea.startswith("+") and not linea.startswith("+++"):
                cambios.append(f"[AÑADIDO] {linea[1:].strip()}")
            elif linea.startswith("-") and not linea.startswith("---"):
                cambios.append(f"[ELIMINADO] {linea[1:].strip()}")
        
        return " | ".join(cambios) if cambios else "Cambios imperceptibles en formato de texto"
    except Exception as e:
        return f"Error en analisis forense: {str(e)}"


def generar_baseline():
    """Calcula y almacena los hashes de referencia iniciales en un archivo JSON y respalda el texto plano"""
    baseline_estructura = {
        "fecha_generacion": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hashes": {}
    }
    
    # Crear carpetas contenedoras por seguridad
    os.makedirs(os.path.dirname(BASELINE_PATH), exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    
    for archivo in CRITICAL_FILES:
        hash_actual = calcular_sha256(archivo)
        if hash_actual and hash_actual != "ERROR_PERMISOS":
            baseline_estructura["hashes"][archivo] = hash_actual
            
            # GUARDAR RESPALDO FORENSE: Copiamos el contenido de texto limpio
            try:
                nombre_seguro = archivo.replace("/", "_")
                with open(archivo, "r", encoding="utf-8", errors="ignore") as f_origen:
                    contenido = f_origen.read()
                with open(os.path.join(BACKUP_DIR, f"{nombre_seguro}.bak"), "w", encoding="utf-8") as f_destino:
                    f_destino.write(contenido)
            except Exception as e:
                print(f"[!] No se pudo respaldar el texto de {archivo}: {e}")
                
        elif hash_actual == "ERROR_PERMISOS":
            print(f"[!] Advertencia: Se requieren privilegios sudo para leer {archivo}")
    
    with open(BASELINE_PATH, "w") as f:
        json.dump(baseline_estructura, f, indent=4)
    print(f"[*] Baseline y backups guardados exitosamente el {baseline_estructura['fecha_generacion']}")


def verificar_integridad():
    """Compara los hashes en tiempo real y realiza analisis de diferencias si detecta anomalias"""
    if not os.path.exists(BASELINE_PATH):
        print("[-] No se encontro una linea base previa. Creando baseline inicial...")
        generar_baseline()
        return

    with open(BASELINE_PATH, "r") as f:
        datos_json = json.load(f)

    fecha_baseline = datos_json.get("fecha_generacion", "Fecha desconocida")
    baseline = datos_json.get("hashes", {})
    fecha_actual = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 📥 Lista para consolidar los hallazgos de todos los archivos
    anomalias_detectadas = []
    detalles_consola = []

    for archivo in CRITICAL_FILES:
        hash_actual = calcular_sha256(archivo)
        
        if hash_actual == "ERROR_PERMISOS":
            anomalias_detectadas.append(f"Acceso denegado en auditoria del archivo: {archivo}")
            detalles_consola.append(f"[CRITICAL] Acceso denegado en: {archivo}")
            continue

        # Caso 1: El archivo existia en el baseline pero fue borrado
        if archivo in baseline and hash_actual is None:
            anomalias_detectadas.append(f"El archivo critico ha sido ELIMINADO: {archivo}")
            detalles_consola.append(f"[CRITICAL] Archivo ELIMINADO: {archivo}")
        
        # Caso 2: El hash actual no coincide con la firma registrada (Modificacion)
        elif archivo in baseline and hash_actual != baseline[archivo]:
            detalles_cambio = obtener_detalles_diff(archivo)
            
            # Acumulamos el detalle resumido para el JSON/Correo
            anomalias_detectadas.append(
                f"MODIFICACIÓN en {archivo}. Cambios: {detalles_cambio} (Hash: {baseline[archivo][:8]}... -> {hash_actual[:8]}...)"
            )
            
            # Acumulamos la estructura visual para la terminal
            detalles_consola.append(
                f"[ALERTA] MODIFICACIÓN DETECTADA en: {archivo}\n"
                f"  └─► Firma legítima guardada el : {fecha_baseline} ({baseline[archivo][:10]}...)\n"
                f"  └─► Firma hostil detectada el  : {fecha_actual} ({hash_actual[:10]}...)\n"
                f"  └─► Detalle Forense            : {detalles_cambio}"
            )

        # Caso 3: Archivo nuevo que no estaba contemplado en la firma inicial
        elif archivo not in baseline and hash_actual is not None:
            anomalias_detectadas.append(f"Nuevo archivo critico detectado fuera de la linea base: {archivo}")
            detalles_consola.append(f"[CRITICAL] Archivo fuera de línea base: {archivo}")

    # 📤 Procesamiento Centralizado: Reportar todo junto al terminar el bucle
    if anomalias_detectadas:
        # 1. Imprimir todo el bloque unificado en la terminal
        print("\n" + "="*75)
        print("🚨 REPORTE DE ALTERACIÓN DE INTEGRIDAD DETECTADO 🚨")
        print("="*75)
        for detalle in detalles_consola:
            print(detalle)
            print("-" * 75)
            
        # 2. Unificar los mensajes para el evento único de Log, Dashboard y Correo
        mensaje_unificado = " | ".join(anomalias_detectadas)
        registrar_evento("ALERTA_INTEGRIDAD", "file_integrity", "CRITICAL", mensaje_unificado)


if __name__ == "__main__":
    print("[+] Ejecutando verificacion de prueba de integridad...")
    verificar_integridad()