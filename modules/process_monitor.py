
#modulo inspector de que cada pocos segundos pide lista de programas en ejecucion, busca si hay herramientas de hackeoo si algun programa satura el cpu generando reportes automat+icos
import psutil
import time
import os
from modules.log_manager import registrar_evento

def monitorear_procesos():
    """
    Supervisa activamente el consumo de recursos de los procesos, detecta sniffers en ejecución e identifica usuarios conectados.
    """
    print("[+] Iniciando Monitor de Procesos e Integridad de Recursos...")
    
    # Herramientas de captura de paquetes explicitamente prohibidas por la catedra , LA LISTA NEGRA
    sniffers_prohibidos = ["tcpdump", "wireshark", "tshark"]
    
    while True:
        try:
            # 1. Auditoria de Usuarios Conectados
            usuarios_activos = psutil.users()
            for usuario in usuarios_activos:
                # Opcional: se puede mapear quien esta adentro del sistema si es necesario para mas adelante
                pass
            
            # 2. Analisis iterativo de procesos en ejecucion, de cada programa en ejecucion extrae 4 datos 
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    info = proc.info
                    nombre_proceso = info['name'].lower() if info['name'] else ""
                    cpu = info['cpu_percent']
                    ram = info['memory_percent']
                    pid = info['pid']
                    
                    # Control A: Deteccion de Sniffers Activos
                    if any(sniffer in nombre_proceso for sniffer in sniffers_prohibidos):
                        mensaje_snif = f"Herramienta de captura detectada: {info['name']} en ejecución activa (PID: {pid})."
                        registrar_evento("ALERTA_PROMISCUO", "process_monitor", "CRITICAL", mensaje_snif)
                        print(f"[CRITICAL] {mensaje_snif}")
                    
                    # Control B: Umbral de Carga de CPU excesivo (>80%)
                    if cpu > 80.0:
                        mensaje_cpu = f"Consumo crítico de CPU detectado en proceso: {info['name']} (PID: {pid}) -> {cpu}%"
                        registrar_evento("ALERTA_RECURSOS", "process_monitor", "WARNING", mensaje_cpu)
                        print(f"[WARNING] {mensaje_cpu}")
                        
                    # Control C: Umbral de Memoria RAM excesivo (>80%)
                    if ram > 80.0:
                        mensaje_ram = f"Agotamiento de memoria RAM por proceso: {info['name']} (PID: {pid}) -> {ram}%"
                        registrar_evento("ALERTA_RECURSOS", "process_monitor", "WARNING", mensaje_ram)
                        print(f"[WARNING] {mensaje_ram}")
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # gestoin de errores por procesos efimeros del sistema que mueren en el milisegundo de lectura
                    continue
            
            # Pausa tactica de 5 segundos para balancear la carga del procesador de la VM
            time.sleep(5)
            
        except Exception as e:
            print(f"[-] Error crítico en bucle de procesos: {e}")
            time.sleep(5)

if __name__ == "__main__":
    # Prueba de ejecucipn autonoma del módulo
    monitorear_procesos()