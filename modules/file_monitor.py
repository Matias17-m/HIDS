import time
import os
from datetime import datetime
from watchdog.observers import Observer #a
from watchdog.events import FileSystemEventHandler

# IMPORTANTE: Importamos la función centralizada de logs en JSON
from modules.log_manager import registrar_evento

# Configuración basada exactamente en la guía de la cátedra
DIRECTORIOS_VIGILADOS = ['/home/matias/hids/data', '/tmp']
EXTENSIONES_SOSPECHOSAS = ['.sh', '.py', '.elf']

def procesar_y_registrar_alerta(tipo_evento, ruta_archivo):
    """Evalúa la criticidad del evento y lo envía al administrador de logs JSON."""
    nombre_archivo = os.path.basename(ruta_archivo)
    _, extension = os.path.splitext(nombre_archivo)
    
    # Valores por defecto para un evento estándar
    id_alerta = "ALERTA_MONITOR"
    criticidad = "INFO"
    mensaje = f"Evento {tipo_evento} detectado en el archivo: {ruta_archivo}"
    
    # Lógica de la guía: alertar con criticidad si aparecen ejecutables en directorios temporales
    if "/tmp" in ruta_archivo and extension in EXTENSIONES_SOSPECHOSAS:
        id_alerta = "ALERTA_CRITICA"
        criticidad = "CRITICAL"
        mensaje = f"Ejecutable sospechoso en directorio temporal: {ruta_archivo}"

    # Guardar usando el nuevo formato estructurado JSON
    registrar_evento(id_alerta, "file_monitor", criticidad, mensaje)
    print(f"[{criticidad}] {mensaje}")

class ManejadorEventos(FileSystemEventHandler):
    """Hereda de FileSystemEventHandler para interceptar llamadas de inotify."""
    
    def on_created(self, event):
        if not event.is_directory:
            procesar_y_registrar_alerta("CREACION", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            procesar_y_registrar_alerta("MODIFICACION", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            procesar_y_registrar_alerta("ELIMINACION", event.src_path)

def iniciar_monitoreo():
    """Inicializa el hilo observador en segundo plano (requerido para main.py)."""
    print(f"[+] Iniciando Monitor de Archivos. Vigilando directorios: {DIRECTORIOS_VIGILADOS}")
    
    handler = ManejadorEventos()
    observer = Observer()
    
    # Registrar cada directorio de la lista para vigilar de forma recursiva
    for directorio in DIRECTORIOS_VIGILADOS:
        if os.path.exists(directorio):
            observer.schedule(handler, directorio, recursive=True)
            
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[-] Deteniendo el monitor de archivos...")
        observer.stop()
    observer.join()

if __name__ == "__main__":
    iniciar_monitoreo()