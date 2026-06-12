import time
import os
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# IMPORTANTE: Importamos la funcion centralizada de logs en JSON
from modules.log_manager import registrar_evento

# ruta restringida/no autorizada 
DIRECTORIOS_VIGILADOS = ['/home/matias/hids/data', '/tmp', '/home/matias/hids/data/no_autorizado']
EXTENSIONES_SOSPECHOSAS = ['.sh', '.py', '.elf']

def procesar_y_registrar_alerta(tipo_evento, ruta_archivo, es_directorio=False):
    """Evalúa la criticidad del evento y lo envía al administrador de logs JSON."""
    
    # FILTRO EXCLUSIVO: Ignorar el ruido del Language Server de VS Code en /tmp
    if "python-languageserver" in ruta_archivo or ".vscode-server" in ruta_archivo:
        return 

    nombre_archivo = os.path.basename(ruta_archivo)
    _, extension = os.path.splitext(nombre_archivo)
    
    # Valores por defecto para un evento estandar
    id_alerta = "ALERTA_MONITOR"
    criticidad = "INFO"
    mensaje = f"Evento {tipo_evento} detectado en: {ruta_archivo}"
    
    # Detectar entrada o lectura a directorio/archivo no autorizado
    if "no_autorizado" in ruta_archivo:
        id_alerta = "ACCESO_NO_AUTORIZADO"
        criticidad = "CRITICAL"
        elemento = "directorio" if es_directorio else "archivo"
        mensaje = f"¡ALERTA DE INTRUSIÓN! Entrada o lectura no autorizada al {elemento}: {ruta_archivo}"

    # Logica de la guia: alertar con criticidad si aparecen ejecutables en directorios temporales
    elif "/tmp" in ruta_archivo and extension in EXTENSIONES_SOSPECHOSAS:
        id_alerta = "ALERTA_CRITICA"
        criticidad = "CRITICAL"
        mensaje = f"Ejecutable sospechoso en directorio temporal: {ruta_archivo}"

    # Guardar usando el formato estructurado JSON
    registrar_evento(id_alerta, "file_monitor", criticidad, mensaje)
    print(f"[{criticidad}] {mensaje}")


class ManejadorEventos(FileSystemEventHandler):
    """Hereda de FileSystemEventHandler para interceptar llamadas de inotify"""
    
    # Detecta cuando alguien abre o accede a un archivo/directorio
    def on_opened(self, event):
        procesar_y_registrar_alerta("ACCESO/ENTRADA", event.src_path, event.is_directory)
    
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
    """Inicializa el hilo observador en segundo plano (requerido para main.py)"""
    
    # Nos aseguramos de que la carpeta "trampa" exista para que watchdog no falle al iniciar
    carpeta_trampa = '/home/matias/hids/data/no_autorizado'
    if not os.path.exists(carpeta_trampa):
        os.makedirs(carpeta_trampa)

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