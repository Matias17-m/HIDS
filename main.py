import sys
from dotenv import load_dotenv
import os
import threading  # LIBRERÍA CRÍTICA: Permite la ejecución en paralelo
import time

# Configuracion de rutas para que Python detecte la carpeta de modulos
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

# Importamos las funciones core que ya programamos y probamos
from modules.log_manager import registrar_evento
from modules.file_integrity import verificar_integridad
from modules.file_monitor import iniciar_monitoreo
from modules.process_monitor import monitorear_procesos
from modules.network_monitor import iniciar_monitor_red
from modules.auth_monitor import monitorear_autenticacion


def verificar_privilegios():
    """Garantiza que el HIDS se ejecute con los permisos requeridos (sudo)."""
    if os.getuid() != 0:
        print("[!] Error critico: El HIDS requiere privilegios de administrador (sudo).")
        sys.exit(1)

def ejecutar_hids_unificado():
    verificar_privilegios()
    
    print("=" * 65)
    print("   SISTEMA DE DETECCION DE INTRUSOS (HIDS) - ORQUESTADOR CORE")
    print("=" * 65)
    
    # FASE 1: Analisis Estatico por Hashes al arrancar
    print("\n[FASE 1] Iniciando analisis estatico de integridad (Firmas SHA-256)...")
    try:
        verificar_integridad()
    except Exception as e:
        print(f"[-] Error critico en el modulo de integridad: {e}")
        
    print("-" * 65)
    
    # FASE 2: Transicion automática al Guardian en Tiempo Real con Hilos Concurrentes
    print("[FASE 2] Transicionando a monitoreo reactivo continuo...")
    print("[+] Inicializando hilos independientes para optimización del núcleo...")
    
    try:
        # Hilo A: Monitor de sistema de archivos (Watchdog)
        hilo_archivos = threading.Thread(target=iniciar_monitoreo, daemon=True)
        
        # Hilo B: Monitor de procesos, recursos y sniffers (Psutil), monitorear_procesos viene de process_monitor
        hilo_procesos = threading.Thread(target=monitorear_procesos, daemon=True)
        
        #Hilo C: Monitor de red (modo promiscuo y sockets escuchando)
        hilo_red = threading.Thread(target=iniciar_monitor_red, daemon=True)

        #Hilo D: Monitor de Autenticacion y accesos 
        hilo_auth = threading.Thread(target=monitorear_autenticacion)

        # Arrancamos los dos guardianes en paralelo
        hilo_archivos.start()
        hilo_procesos.start()
        hilo_red.start()
        hilo_auth.start()
        
        print("[+] HIDS operando en tiempo real con todos sus módulos concurrentes.")
        print("[+] Guardando registros JSON estructurados en logs/events.log")
        print("[+] Presione Ctrl+C para finalizar.\n")
        
        # Mantener el hilo principal vivo para que no se cierre el script
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n[-] Apagando todos los módulos del HIDS de manera segura...")
        print("[+] HIDS Detenido. ¡Buen descanso, Matías!")
    except Exception as e:
        print(f"[-] Error critico en la ejecucion de hilos dinámicos: {e}")

if __name__ == "__main__":
    # Control de Seguridad Obligatorio: Validar privilegios de Root/Sudo
    if os.getuid() != 0:
        print("[-] ERROR: El HIDS requiere privilegios de administrador (sudo) para operar")
        sys.exit(1)
        
    ejecutar_hids_unificado()