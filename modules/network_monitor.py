import psutil
import time
import os
from modules.log_manager import registrar_evento

interfaces_alertadas = set()
puertos_alertados = set()
# Memoria para reportar cambios significativos en la cantidad de equipos de la red
ultima_cantidad_equipos = -1

def escanear_equipos_red():
    """ Escanea la red local leyendo la tabla ARP del kernel de Linux 
        para identificar la cantidad de equipos conectados en la LAN """
    global ultima_cantidad_equipos
    ruta_arp = "/proc/net/arp"
    equipos_detectados = set()

    try:
        if os.path.exists(ruta_arp):
            with open(ruta_arp, "r") as f:
                # Omitimos la primera linea que es el encabezado del archivo
                lineas = f.readlines()[1:]
                for linea in lineas:
                    columnas = linea.split()
                    if len(columnas) >= 4:
                        ip = columnas[0]
                        mac = columnas[3]
                        # 00:00:00:00:00:00 significa una IP que no respondio o no es valida
                        if mac != "00:00:00:00:00:00":
                            equipos_detectados.add(ip)
            
            cantidad_actual = len(equipos_detectados)
            
            # Notificamos si la cantidad de equipos cambia o si es el primer escaneo
            if cantidad_actual != ultima_cantidad_equipos:
                mensaje = f"Auditoría de Red LAN: Se identificaron {cantidad_actual} equipos activos conectados en la subred."
                registrar_evento("CONTEO_EQUIPOS_RED", "network_monitor", "INFO", mensaje)
                print(f"[INFO] {mensaje} -> IPs: {list(equipos_detectados)}")
                ultima_cantidad_equipos = cantidad_actual
                
    except Exception as e:
        print(f"[-] Error al escanear equipos de la red local: {e}")


def verificar_modo_promiscuo():
    """ Revisa las interfaces de red del sistema para verificar si tienen la bandera 
        PROMISC activa (caracteristica de sniffers a nivel de kernel)  """
    global interfaces_alertadas
    interfaces_actuales_promiscuas = set()
    
    try:
        rutas_net = "/sys/class/net/" 
        if os.path.exists(rutas_net):
            for interfaz in os.listdir(rutas_net):
                ruta_flags = os.path.join(rutas_net, interfaz, "flags")
                if os.path.exists(ruta_flags):
                    with open(ruta_flags, "r") as f:
                        flags = int(f.read().strip(), 16) 
                        if flags & 0x100:  
                            interfaces_actuales_promiscuas.add(interfaz)
                            
                            # Alertar solo si es una interfaz nueva en modo promiscuo
                            if interfaz not in interfaces_alertadas:
                                mensaje = f"¡ALERTA DE SEGURIDAD! Interfaz de red en MODO PROMISCUO detectada: {interfaz}"
                                registrar_evento("ALERTA_RED_PROMISCUA", "network_monitor", "CRITICAL", mensaje)
                                print(f"\n[CRITICAL] {mensaje}")
                                interfaces_alertadas.add(interfaz)
        
        # Limpieza: si la interfaz vuelve a la normalidad, la sacamos de la memoria
        for intf_vieja in list(interfaces_alertadas):
            if intf_vieja not in interfaces_actuales_promiscuas:
                interfaces_alertadas.remove(intf_vieja)

    except Exception as e:
        print(f"[-] Error al auditar modo promiscuo: {e}")


def monitorear_puertos():
    """ Escanea las conexiones de red del sistema en busca de sockets en estado LISTEN
    para mapear puertos abiertos en tiempo real """
    puertos_autorizados = [22, 53, 68, 3306, 5000] 
    puertos_actuales = set()
    try:
        conexiones = psutil.net_connections(kind='tcp')
        for conn in conexiones: 
            if conn.status == 'LISTEN': 
                puerto = conn.laddr.port
                pid = conn.pid
                
                if puerto not in puertos_autorizados:
                    nombre_proceso = "Desconocido"
                    if pid:
                        try:
                            nombre_proceso = psutil.Process(pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    if "code-" in nombre_proceso or "MainThread" in nombre_proceso:
                        continue

                    puertos_actuales.add(puerto)
                            
                    if puerto not in puertos_alertados:
                        mensaje = f"Puerto sospechoso abierto en estado LISTEN: {puerto} (Proceso: {nombre_proceso}, PID: {pid})"
                        registrar_evento("ALERTA_PUERTO_NO_AUTORIZADO", "network_monitor", "WARNING", mensaje)
                        print(f"[WARNING] {mensaje}")
                        puertos_alertados.add(puerto)
                        
        for puerto_viejo in list(puertos_alertados):
            if puerto_viejo not in puertos_actuales:
                print(f"[*] El puerto {puerto_viejo} se ha cerrado. Removiendo de memoria de alertas.")
                puertos_alertados.remove(puerto_viejo)
                    
    except Exception as e:
        print(f"[-] Error al escanear conexiones de red: {e}")


def iniciar_monitor_red():
    """ Punto de entrada para el hilo de red. Corre en bucle continuo """
    print("[+] Iniciando Monitor de Red Completo (Modo Promiscuo, Puertos y Escáner LAN)...")
    while True:
        verificar_modo_promiscuo()
        monitorear_puertos()
        escanear_equipos_red()  # Ejecuta el escaner de red local
        time.sleep(4)


if __name__ == "__main__":
    iniciar_monitor_red()