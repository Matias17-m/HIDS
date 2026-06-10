import psutil
import time
import os
from modules.log_manager import registrar_evento

def verificar_modo_promiscuo():
    """ Revisa las interfaces de red del sistema para verificar si tienen la bandera 
        PROMISC activa (caracteristica de sniffers a nivel de kernel)  """
    try:
        # En Linux, las interfaces promiscuas se detectan leyendo el archivo de flags
        # en el sistema de archivos de procesos nativo (/sys/class/net/)
        rutas_net = "/sys/class/net/" # esta carpeta es como el inventario de hardware de la red
        if os.path.exists(rutas_net):
            for interfaz in os.listdir(rutas_net):
                ruta_flags = os.path.join(rutas_net, interfaz, "flags")
                if os.path.exists(ruta_flags):
                    with open(ruta_flags, "r") as f:
                        # el flag hexadecimal 0x100 indica modo promiscuo 
                        # hacemos una operacion de bits para verificar si esta activo
                        flags = int(f.read().strip(), 16) # 16 para pasar a decimal y que python pueda leerlo
                        if flags & 0x100:  # el SO activa el bit 0x100 (256 en decimal) unicamente cuando la placa entra en modo 
                                           # promiscuo (captura trafico ajeno)
                            mensaje = f"¡ALERTA DE SEGURIDAD! Interfaz de red en MODO PROMISCUO detectada: {interfaz}"
                            registrar_evento("ALERTA_RED_PROMISCUA", "network_monitor", "CRITICAL", mensaje)
                            print(f"\n[CRITICAL] {mensaje}")
    except Exception as e:
        print(f"[-] Error al auditar modo promiscuo: {e}")

def monitorear_puertos():
    """ Escanea las conexiones de red del sistema en busca de sockets en estado LISTEN
    para mapear puertos abiertos en tiempo real """
    # Lista de puertos estandar que permitimos (22 para SSH, 53 para DNS, 68 para DHCP, 3306 mariaDB)
    puertos_autorizados = [22, 53, 68, 3306] 
    
    try:
        # Obtenemos las conexiones de red del sistema de tipo TCP
        conexiones = psutil.net_connections(kind='tcp')
        for conn in conexiones: #revisamos lista de conexiones 
            if conn.status == 'LISTEN': #significa escuchando 
                puerto = conn.laddr.port
                pid = conn.pid
                
                # Si el puerto no esta en la lista de aprobados, disparamos la alerta
                if puerto not in puertos_autorizados:
                    nombre_proceso = "Desconocido"
                    if pid:
                        try:
                            nombre_proceso = psutil.Process(pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    # FILTRO : Si el puerto lo abrio el VS Code, lo ignoramos para no saturar la pantalla
                    if "code-" in nombre_proceso or "MainThread" in nombre_proceso:
                        continue
                            
                    mensaje = f"Puerto sospechoso abierto en estado LISTEN: {puerto} (Proceso: {nombre_proceso}, PID: {pid})"
                    registrar_evento("ALERTA_PUERTO_NO_AUTORIZADO", "network_monitor", "WARNING", mensaje)
                    print(f"[WARNING] {mensaje}")
                    
    except Exception as e:
        print(f"[-] Error al escanear conexiones de red: {e}")

def iniciar_monitor_red():
    """ Punto de entrada para el hilo de red. Corre en bucle continuo """
    print("[+] Iniciando Monitor de Red (Modo Promiscuo y Puertos)...")
    while True:
        verificar_modo_promiscuo()
        monitorear_puertos()
        # Pausa tactica de 4 segundos para balancear el rendimiento
        time.sleep(4)

if __name__ == "__main__":
    # Prueba autonoma para testear sin ir al main
    iniciar_monitor_red()