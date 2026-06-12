# modulo inspector de que cada pocos segundos pide lista de programas en ejecucion, busca si hay herramientas de hackeoo si algun programa satura el cpu generando reportes automat+icos
import psutil
import time
import os
from collections import Counter  # para contar multiples instancias eficientemente
from modules.log_manager import registrar_evento

def monitorear_procesos():
    """ Supervisa activamente el consumo de recursos de los procesos, detecta sniffers en ejecución,
    procesos con demasiadas instancias y procesos de larga duración en el sistema """
    
    print("[+] Iniciando Monitor de Procesos e Integridad de Recursos...")
    
    # Herramientas de captura de paquetes explicitamente prohibidas por la catedra
    sniffers_prohibidos = ["tcpdump", "wireshark", "tshark", "dumpcap"]
    
    # Registro temporal de PIDs ya reportados para evitar spam en el Dashboard
    pids_reportados = set()
    alertas_instancias_reportadas = set()
    alertas_duracion_reportadas = set()
    
    # Umbrales exigidos
    UMBRAL_INSTANCIAS_MAXIMAS = 10
    UMBRAL_LARGA_DURACION_SEGUNDOS = 86400  # 24 Horas de ejecucion continua
    
    # Procesos del sistema operativo que es normal que tengan muchas instancias o duren mucho
    PROCESOS_IGNORADOS = ["systemd", "sshd", "bash", "python3", "code", "kworker", "tmux"]

    while True:
        try:
            pids_activos_en_ronda = set()
            conteo_instancias = Counter()
            
            # Pedimos  'create_time' para auditar la duracion
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'create_time']):
                try:
                    info = proc.info
                    nombre_original = info['name'] if info['name'] else "Desconocido"
                    nombre_proceso = nombre_original.lower()
                    cpu = info['cpu_percent']
                    ram = info['memory_percent']
                    pid = info['pid']
                    tiempo_creacion = info['create_time']
                    
                    # Contabilizamos la instancia 
                    if nombre_proceso not in PROCESOS_IGNORADOS:
                        conteo_instancias[nombre_original] += 1
                    
                    # Control A: Deteccion de Sniffers Activos 
                    if any(sniffer in nombre_proceso for sniffer in sniffers_prohibidos):
                        pids_activos_en_ronda.add(pid)
                        if pid not in pids_reportados:
                            mensaje_snif = f"Herramienta de captura detectada: {nombre_original} en ejecución activa (PID: {pid})."
                            registrar_evento("ALERTA_PROMISCUO", "process_monitor", "CRITICAL", mensaje_snif)
                            print(f"[CRITICAL] {mensaje_snif}")
                            pids_reportados.add(pid)
                    
                    # Control B: Umbral de Carga de CPU excesivo (>80%) 
                    if cpu > 80.0:
                        pids_activos_en_ronda.add(pid)
                        if pid not in pids_reportados:
                            mensaje_cpu = f"Consumo crítico de CPU detectado en proceso: {nombre_original} (PID: {pid}) -> {cpu}%"
                            registrar_evento("ALERTA_RECURSOS", "process_monitor", "WARNING", mensaje_cpu)
                            print(f"[WARNING] {mensaje_cpu}")
                            pids_reportados.add(pid)
                        
                    # Control C: Umbral de Memoria RAM excesivo (>80%) 
                    if ram > 80.0:
                        pids_activos_en_ronda.add(pid)
                        if pid not in pids_reportados:
                            mensaje_ram = f"Agotamiento de memoria RAM por proceso: {nombre_original} (PID: {pid}) -> {ram}%"
                            registrar_evento("ALERTA_RECURSOS", "process_monitor", "WARNING", mensaje_ram)
                            print(f"[WARNING] {mensaje_ram}")
                            pids_reportados.add(pid)

                    # Control D: Procesos de Larga Duración 
                    if tiempo_creacion and (nombre_proceso not in PROCESOS_IGNORADOS):
                        segundos_activo = time.time() - tiempo_creacion
                        if segundos_activo > UMBRAL_LARGA_DURACION_SEGUNDOS:
                            firma_duracion = f"{nombre_original}_{pid}"
                            pids_activos_en_ronda.add(pid)
                            if firma_duracion not in alertas_duracion_reportadas:
                                horas_activo = int(segundos_activo // 3600)
                                mensaje_duracion = f"Proceso de larga duración detectado: '{nombre_original}' (PID: {pid}) lleva {horas_activo} horas ejecutándose."
                                registrar_evento("ALERTA_PROCESO_PERSISTENTE", "process_monitor", "WARNING", mensaje_duracion)
                                print(f"[WARNING] {mensaje_duracion}")
                                alertas_duracion_reportadas.add(firma_duracion)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            # Control E: Procesos con Muchas Instancias Abiertas 
            for nombre, cantidad in conteo_instancias.items():
                if cantidad > UMBRAL_INSTANCIAS_MAXIMAS:
                    if nombre not in alertas_instancias_reportadas:
                        mensaje_instancias = f"Abuso de instancias: Se detectaron {cantidad} ejecuciones simultáneas del proceso '{nombre}'."
                        registrar_evento("ALERTA_MULTIPLES_INSTANCIAS", "process_monitor", "WARNING", mensaje_instancias)
                        print(f"[WARNING] {mensaje_instancias}")
                        alertas_instancias_reportadas.add(nombre)
                else:
                    # Si el numero de procesos bajo del umbral, limpiamos la alerta para permitir futuros reportes
                    if nombre in alertas_instancias_reportadas:
                        alertas_instancias_reportadas.remove(nombre)

            # Limpieza forense de sets globales
            pids_reportados = pids_reportados.intersection(pids_activos_en_ronda)
            
            # Limpieza de firmas de duración viejas
            alertas_duracion_reportadas = {f for f in alertas_duracion_reportadas if int(f.split("_")[1]) in pids_activos_en_ronda}

            time.sleep(2)
            
        except Exception as e:
            print(f"[-] Error crítico en bucle de procesos: {e}")
            time.sleep(2)

if __name__ == "__main__":
    monitorear_procesos()