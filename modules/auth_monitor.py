import time
import os
from modules.log_manager import registrar_evento

def monitorear_autenticacion():
    """
    Monitorea en tiempo real el archivo /var/log/auth.log buscando intentos fallidos 
    de inicio de sesión para mitigar ataques de fuerza bruta.
    """
    ruta_log = "/var/log/auth.log"
    
    print("[+] Iniciando Monitor de Autenticación e Intentos de Acceso...")
    print(f"[*] Escaneando activamente el archivo de sistema: {ruta_log}")
    
    if not os.path.exists(ruta_log):
        print(f"[-] Error crítico: No se encuentra el archivo {ruta_log}.")
        return

    # Abrimos el archivo en modo lectura
    with open(ruta_log, "r") as archivo:
        # Nos movemos al final del archivo para procesar solo los eventos nuevos
        archivo.seek(0, os.SEEK_END)
        
        while True:
            linea = archivo.readline()
            if not linea:
                # Si no hay actividad, pausa táctica de 1 segundo para no saturar CPU
                time.sleep(1)
                continue
                
            # Pasamos la línea a minúsculas para machear sin problemas de tipeo
            linea_lower = linea.lower()
            
            # Patrón 1: Contraseña incorrecta general (SSH o local)
            if "failed password" in linea_lower or "authentication failure" in linea_lower:
                mensaje = f"Intento de acceso fallido detectado en el sistema: {linea.strip()}"
                registrar_evento("ALERTA_AUTENTICACION_FALLIDA", "auth_monitor", "WARNING", mensaje)
                print(f"\n[WARNING] {mensaje}")
                
            # Patrón 2: Intento directo contra el usuario ROOT
            elif "failed password for root" in linea_lower:
                mensaje = f"¡CRÍTICO! Intento de fuerza bruta dirigido al usuario ROOT: {linea.strip()}"
                registrar_evento("ALERTA_FUERZA_BRUTA_ROOT", "auth_monitor", "CRITICAL", mensaje)
                print(f"\n[CRITICAL] {mensaje}")
                
            # Patrón 3: Uso no autorizado o fallido de SUDO
            elif "user not in sudoers" in linea_lower or "incorrect password" in linea_lower:
                mensaje = f"Abuso de privilegios o contraseña incorrecta en comando SUDO: {linea.strip()}"
                registrar_evento("ALERTA_ABUSO_SUDO", "auth_monitor", "CRITICAL", mensaje)
                print(f"\n[CRITICAL] {mensaje}")

if __name__ == "__main__":
    # Forzamos el arranque directo sí o sí con un capturador de salida limpia
    try:
        monitorear_autenticacion()
    except KeyboardInterrupt:
        print("\n[-] Monitor de autenticación detenido localmente.")