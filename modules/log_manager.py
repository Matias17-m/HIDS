import os
from dotenv import load_dotenv

# Forzamos la carga del archivo .env 
ruta_env = '/home/matias/hids/.env'
load_dotenv(dotenv_path=ruta_env)
import json
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Ruta estandarizada de auditoria
LOG_PATH = "logs/events.log"

def enviar_alerta_email(tipo_evento, modulo, prioridad, mensaje):
    """ Se conecta al servidor SMTP de Gmail usando TLS y envía una notificación formal al administrador 
    en caso de alertas critivcas """
    # ================= CONFIGURACION DE CREDENCIALES =================
    remitente = os.environ.get("REMITENTE")      # El correo con el que se creo el token
    destinatario = os.environ.get("DESTINATARIO")  # Tu mail personal donde llegaran
    password = os.environ.get("PASSWORD")               
    # =================================================================
    #
    # para testeo
    #print(f"[DEBUG] Remitente:    {remitente}")
    #print(f"[DEBUG] Destinatario: {destinatario}")
    #print(f"[DEBUG] Password:     {'OK' if password else 'NO ENCONTRADA ❌'}")

    if not all([remitente, destinatario, password]):
        print("[-] Faltan variables de entorno, abortando envío")
        return
    # encabezado del correo electrónico
    msg = MIMEMultipart()
    msg['From'] = remitente
    msg['To'] = destinatario
    msg['Subject'] = f"! [ALERTA CRITICA HIDS] - {tipo_evento} detectado en {modulo}"
    
    # formato formal del cuerpo del correo 
    cuerpo = f"""
    =================================================================
             ALERTA DE SEGURIDAD EMITIDA POR EL CORE HIDS
    =================================================================
    Fecha/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    Severidad:  {prioridad}
    Módulo:     {modulo}
    Evento:     {tipo_evento}
    
    Detalle Técnico del Incidente:
    {mensaje}
    
    -----------------------------------------------------------------
    Acción Recomendada: Se sugiere realizar revisión urgente de la terminal 
    del servidor y chequear la integridad de los servicios afectados.
    =================================================================
    """
    msg.attach(MIMEText(cuerpo, 'plain'))
    
    try:
        # Iniciamos la conexion con el servidor SMTP de Google (Puerto 587 para TLS)
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()  # Cifrado de la conexión por seguridad
        
        # Autenticacion segura con el token de aplicación
        server.login(remitente, password)
        
        # Envio definitivo del paquete MIME encapsulado
        server.sendmail(remitente, destinatario, msg.as_string())
        server.quit()
        
        print(f"[EMAIL] Notificación de emergencia enviada con éxito a: {destinatario}")
    except Exception as e:
        # Control de excepciones por si el servidor se queda sin internet o fallan las credenciales
        print(f"[-] Error crítico al despachar la notificación por correo: {e}")


def registrar_evento(id_alerta, modulo, criticidad, mensaje):
    """ Registra un evento de seguridad en formato JSON estructurado y mantiene la persistencia en modo Append sin alterar registros previos"""
    # Garantizar la existencia del directorio de logs de forma automática
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    
    # Construccion del objeto JSON estructurado para el parseo del Dashboard
    evento = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "id_alerta": id_alerta,
        "modulo": modulo,
        "criticidad": criticidad,
        "mensaje": mensaje
    }
    
    # Escritura inline para evitar corrupcion de archivo
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(evento) + "\n")

    if criticidad == "CRITICAL":
        enviar_alerta_email(id_alerta, modulo, criticidad, mensaje)
