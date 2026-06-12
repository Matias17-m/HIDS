import time
import os
import psutil  # psutil para auditar los usuarios conectados reales
from modules.log_manager import registrar_evento

# Memoria temporal para no repetir alertas de usuarios que ya sabemos que están conectados
usuarios_ya_reportados = set()

def verificar_usuarios_conectados():
    """Identifica los usuarios conectados actualmente en el sistema 
        y extrae su IP o terminal de origen (Cumple Puntos 2 y 12)"""
    global usuarios_ya_reportados
    usuarios_actuales = set()
    
    try:
        sesiones = psutil.users()
        for sesion in sesiones:
            usuario = sesion.name
            origen = sesion.host if sesion.host else "Terminal Local (tty)"
            terminal = sesion.terminal
            
            # creamos una firma unica para la sesion activa (Ej: "matias@192.168.1.50")
            firma_sesion = f"{usuario}@{origen}"
            usuarios_actuales.add(firma_sesion)
            
            # alerta la primera vez que ve al usuario entrar
            if firma_sesion not in usuarios_ya_reportados:
                # 1 Registro estAndar 
                mensaje = f"Sesión activa detectada: Usuario '{usuario}' conectado desde el origen [{origen}] vía terminal ({terminal})"
                registrar_evento("SESION_ACTIVA_ORIGEN", "auth_monitor", "INFO", mensaje)
                print(f"\n[INFO] {mensaje}")
                
                # CONTROL ANOMALÍAS 
                from datetime import datetime
                hora_actual = datetime.now().hour
                
                # Criterio A: Horario marginal/nocturno (Puesto a las 22hs para que te salte la alerta YA)
                
                es_horario_sospechoso = (hora_actual >= 23 or hora_actual <= 6)
                
                # Criterio B: IP fuera del rango domEstico estAndar o localhost
                es_ip_sospechosa = (origen != "Terminal Local (tty)" and 
                                    not origen.startswith("192.168.0.") and 
                                    not origen.startswith("127.0.0.1"))
                
                if es_horario_sospechoso or es_ip_sospechosa:
                    motivo = "Horario nocturno/no laboral" if es_horario_sospechoso else "IP de origen externa no autorizada"
                    mensaje_sospecha = f"¡ALERTA DE ANOMALÍA! Inicio de sesión sospechoso del usuario '{usuario}' desde [{origen}]. Motivo: {motivo}."
                    registrar_evento("ALERTA_LOGIN_SOSPECHOSO", "auth_monitor", "WARNING", mensaje_sospecha)
                    print(f"[WARNING] {mensaje_sospecha}")
                
                usuarios_ya_reportados.add(firma_sesion)
                
        # Limpieza: Si el usuario cerrO sesion, lo sacamos de la memoria
        for sesion_vieja in list(usuarios_ya_reportados):
            if sesion_vieja not in usuarios_actuales:
                usuarios_ya_reportados.remove(sesion_vieja)
                
    except Exception as e:
        print(f"[-] Error al verificar usuarios conectados: {e}")


def monitorear_autenticacion():
    """ Monitorea en tiempo real el archivo /var/log/auth.log buscando intentos fallidos 
        de inicio de sesión para mitigar ataques de fuerza bruta """
    ruta_log = "/var/log/auth.log"
    
    print("[+] Iniciando Monitor de Autenticación e Intentos de Acceso...")
    print(f"[*] Escaneando activamente el archivo de sistema: {ruta_log}")
    
    if not os.path.exists(ruta_log):
        print(f"[-] Error crítico: No se encuentra el archivo {ruta_log}.")
        return

    # Realizamos un primer chequeo de usuarios conectados al arrancar
    verificar_usuarios_conectados()
    
    # Contador auxiliar para no saturar el comando de usuarios en cada microsegundo del bucle
    contador_vueltas = 0

    with open(ruta_log, "r") as archivo:
        archivo.seek(0, os.SEEK_END)
        
        while True:
            contador_vueltas += 1
            # Cada 10 vueltas vacías (aproximadamente 10 segundos), refresca los usuarios en el sistema
            if contador_vueltas >= 10:
                verificar_usuarios_conectados()
                contador_vueltas = 0

            linea = archivo.readline()
            if not linea:
                time.sleep(1)
                continue
                
            linea_lower = linea.lower()
            
            # Patron 1: Contraseña incorrecta general (SSH o local)
            if "failed password" in linea_lower or "authentication failure" in linea_lower:
                mensaje = f"Intento de acceso fallido detectado en el sistema: {linea.strip()}"
                registrar_evento("ALERTA_AUTENTICACION_FALLIDA", "auth_monitor", "WARNING", mensaje)
                print(f"\n[WARNING] {mensaje}")
                
            # Patron 2: Intento directo contra el usuario ROOT
            elif "failed password for root" in linea_lower:
                mensaje = f"¡CRÍTICO! Intento de fuerza bruta dirigido al usuario ROOT: {linea.strip()}"
                registrar_evento("ALERTA_FUERZA_BRUTA_ROOT", "auth_monitor", "CRITICAL", mensaje)
                print(f"\n[CRITICAL] {mensaje}")
                
            # Patron 3: Uso no autorizado o fallido de SUDO
            elif "user not in sudoers" in linea_lower or "incorrect password" in linea_lower:
                mensaje = f"Abuso de privilegios o contraseña incorrecta en comando SUDO: {linea.strip()}"
                registrar_evento("ALERTA_ABUSO_SUDO", "auth_monitor", "CRITICAL", mensaje)
                print(f"\n[CRITICAL] {mensaje}")

if __name__ == "__main__":
    try:
        monitorear_autenticacion()
    except KeyboardInterrupt:
        print("\n[-] Monitor de autenticación detenido localmente.")