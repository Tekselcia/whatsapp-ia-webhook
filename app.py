from flask import Flask, request, jsonify
import openai
import requests
import json
import logging
from datetime import datetime
import os
import sys
from datetime import datetime, timedelta
import pytz

# ===========================
# Configuración logging
# ===========================
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ===========================
# Configuración Flask
# ===========================
app = Flask(__name__)

# ===========================
# Variables de entorno
# ===========================
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
WHATSAPP_ACCESS_TOKEN = os.getenv('WHATSAPP_ACCESS_TOKEN')
WHATSAPP_PHONE_NUMBER_ID = os.getenv('WHATSAPP_PHONE_NUMBER_ID')
ODOO_URL = os.getenv('ODOO_URL')
ODOO_DB = os.getenv('ODOO_DB')
ODOO_USER = os.getenv('ODOO_USER')
ODOO_PASSWORD = os.getenv('ODOO_PASSWORD')
WEBHOOK_VERIFY_TOKEN = os.getenv('WEBHOOK_VERIFY_TOKEN', 'mi_token_secreto')

# Configurar OpenAI
openai.api_key = OPENAI_API_KEY

# ===========================
# Funciones Odoo
# ===========================
def authenticate_odoo():
    try:
        login_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'common',
                'method': 'login',
                'args': [ODOO_DB, ODOO_USER, ODOO_PASSWORD]
            }
        }
        response = requests.post(f"{ODOO_URL}/jsonrpc", json=login_data)
        uid = response.json().get('result')
        if uid:
            return {'uid': uid, 'password': ODOO_PASSWORD}
        else:
            raise Exception("Autenticación fallida")
    except Exception as e:
        logger.error(f"Error autenticando Odoo: {e}")
        raise e

def get_selection_values(session, model, field):
    """Obtiene keys válidas de un campo selection en Odoo"""
    try:
        data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [ODOO_DB, session['uid'], session['password'],
                         model, 'fields_get', [field]]
            }
        }
        resp = requests.post(f"{ODOO_URL}/jsonrpc", json=data)
        field_info = resp.json().get('result', {}).get(field, {})
        selection = field_info.get('selection', [])
        return [k for k, v in selection]
    except Exception as e:
        logger.error(f"Error obteniendo selection values: {e}")
        return []

def create_odoo_message(message_info, partner_id):
    try:
        session = authenticate_odoo()
        if not session or not session.get('uid'):
            logger.error("Sesión inválida para Odoo")
            return None

        # Mapear tipo de mensaje
        tipo_field = 'x_studio_tipo_de_mensaje'
        model = 'x_ia_tai'
        selection_keys = get_selection_values(session, model, tipo_field)
        valid_tipo = None
        if selection_keys:
            for k in selection_keys:
                if k.lower() in ['inbound','entrada']:
                    valid_tipo = k
                    break
            if not valid_tipo:
                valid_tipo = selection_keys[0]

        message_text = message_info.get('text') or 'Sin contenido'
        payload_data = {
            'x_name': message_text,
            'x_studio_partner_id': partner_id,
            'x_studio_partner_phone': message_info.get('phone'),
            'x_studio_mensaje_whatsapp': message_text,
            'x_studio_date': datetime.now().replace(microsecond=0).isoformat(),
            'x_studio_estado': 'received'
        }
        if valid_tipo:
            payload_data[tipo_field] = valid_tipo

        create_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [ODOO_DB, session['uid'], session['password'],
                         model, 'create', [payload_data]]
            }
        }
        resp = requests.post(f"{ODOO_URL}/jsonrpc", json=create_data)
        resp_json = resp.json()
        if 'error' in resp_json:
            logger.error(f"Odoo error creating message: {resp_json['error']}")
            return None
        result = resp_json.get('result')
        logger.info(f"Mensaje creado en Odoo con ID: {result}")
        return result
    except Exception as e:
        logger.error(f"Odoo error creating message: {e}")
        return None

def get_odoo_record(message_id):
    """Obtiene los datos de un registro específico desde Odoo."""
    try:
        session = authenticate_odoo()
        if not session or not session.get("uid"):
            logger.error("Sesión inválida para Odoo")
            return None

        model = "x_ia_tai"

        # Asegurar que message_id sea lista
        ids_to_fetch = [message_id] if isinstance(message_id, int) else message_id

        data = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "service": "object",
                "method": "execute",
                "args": [
                    ODOO_DB,
                    session["uid"],
                    session["password"],
                    model,
                    "read",
                    ids_to_fetch,
                    [
                        "x_studio_estado",
                        "x_studio_respuesta_ia",
                        "x_studio_procesado_por_ia",
                        "x_studio_hora_ultimo_humano",
                        "x_studio_ia_activa"
                    ],
                ],
            },
        }

        response = requests.post(f"{ODOO_URL}/jsonrpc", json=data)
        resp_json = response
        if "error" in resp_json:
            logger.error(f"Odoo error al obtener registro: {resp_json['error']}")
            return None

        records = resp_json.get("result", [])
        if not records:
            logger.warning(f"No se encontró registro con ID {message_id}")
            return None

        return records[0]  # Devolvemos el primer registro encontrado

    except Exception as e:
        logger.error(f"Error al obtener registro desde Odoo: {e}")
        return None

# =========================
# ACTUALIZAR ESTADO EN ODOO
# =========================
def update_message_status(message_id, new_status, mark_processed=True):
    """Actualiza el campo x_studio_estado del mensaje en Odoo de manera segura."""
    try:
        session = authenticate_odoo()
        if not session or not session.get("uid"):
            logger.error("Sesión inválida para Odoo")
            return False

        model = "x_ia_tai"

        # Aplanar y asegurar que message_id sea lista de enteros
        if isinstance(message_id, int):
            ids_to_update = [message_id]
        elif isinstance(message_id, list):
            ids_to_update = []
            for mid in message_id:
                if isinstance(mid, int):
                    ids_to_update.append(mid)
                elif isinstance(mid, list):
                    ids_to_update.extend([int(x) for x in mid if isinstance(x, int)])
            if not ids_to_update:
                logger.error("No se encontró ningún ID válido para actualizar")
                return False
        else:
            logger.error(f"Tipo de ID inválido: {type(message_id)}")
            return False

        # 🔹 Mapeo estado → etapa
        etapa_map = {
            "received": "Nuevo",
            "processing": "En proceso",
            "responded": "En proceso",
            "escalated": "En proceso",
            "closed": "Hecho"
        }
        etapa_nombre = etapa_map.get(new_status.lower(), "Nuevo")

        # 🔹 Buscar ID de la etapa en Odoo
        search_stage_data = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "service": "object",
                "method": "execute",
                "args": [
                    ODOO_DB,
                    session["uid"],
                    session["password"],
                    "x_ia_tai_stage",  # Modelo de etapas
                    "search",
                    [["name", "=", etapa_nombre]],
                    1
                ]
            }
        }
        stage_response = requests.post(f"{ODOO_URL}/jsonrpc", json=search_stage_data)
        stage_result = stage_response.json().get("result", [])
        stage_id = stage_result[0] if stage_result else False

        # 🔹 Datos a actualizar
        values = {
            "x_studio_estado": new_status,
            "x_studio_procesado_por_ia": mark_processed
        }
        if stage_id:
            values["stage_id"] = stage_id  # actualiza la etapa si existe
            
        
        data = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "service": "object",
                "method": "execute",
                "args": [
                    ODOO_DB,
                    session["uid"],
                    session["password"],
                    model,
                    "write",
                    ids_to_update,          # Lista de IDs
                    {
                        "x_studio_estado": new_status,        # Estado del mensaje
                        "x_studio_procesado_por_ia": True     # Marcar como procesado por IA
                    }  # Valores
                ]
            }
        }

        response = requests.post(f"{ODOO_URL}/jsonrpc", json=data)
        resp_json = response.json()
        if "error" in resp_json:
            logger.error(f"Odoo error al actualizar estado: {resp_json['error']}")
            return False

        logger.info(f"Estado actualizado a '{new_status}' (etapa: {etapa_nombre}) para IDs {ids_to_update}")
        # 🚨 ALERTA AUTOMÁTICA SI ES ESCALADO
        if new_status.lower() == "escalado":
            for mid in ids_to_update:
                logger.warning(f"Mensaje ID {mid} está ESCALADO: requiere atención inmediata")
                # Aquí puedes agregar integración con WhatsApp, email o cualquier otro sistema de alertas
                # ejemplo: send_whatsapp_alert(mid, "El mensaje ha sido escalado y requiere acción.")

        return True
    except Exception as e:
        logger.error(f"Error actualizando estado: {e}")
        return False


def update_odoo_response(message_id, response_text, mark_processed=False, new_stage=None):
    """Guarda la respuesta de la IA en el mensaje de Odoo."""
    try:
        session = authenticate_odoo()
        if not session or not session.get("uid"):
            logger.error("Sesión inválida para Odoo")
            return False

        model = "x_ia_tai"

        # Aplanar y asegurar que message_id sea lista de enteros
        if isinstance(message_id, int):
            ids_to_update = [message_id]
        elif isinstance(message_id, list):
            ids_to_update = []
            for mid in message_id:
                if isinstance(mid, int):
                    ids_to_update.append(mid)
                elif isinstance(mid, list):
                    ids_to_update.extend([int(x) for x in mid if isinstance(x, int)])
            if not ids_to_update:
                logger.error("No se encontró ningún ID válido para actualizar")
                return False
        else:
            logger.error(f"Tipo de ID inválido: {type(message_id)}")
            return False
            
        # Primero, obtener el estado actual para no sobrescribir escalated
        get_data = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "service": "object",
                "method": "execute",
                "args": [
                    ODOO_DB,
                    session["uid"],
                    session["password"],
                    model,
                    "read",
                    ids_to_update,
                    ["x_studio_estado"]  # Solo necesitamos el estado
                ]
            }
        }

        get_resp = requests.post(f"{ODOO_URL}/jsonrpc", json=get_data)
        get_json = get_resp.json()
        if "error" in get_json:
            logger.error(f"Odoo error al leer estado: {get_json['error']}")
            return False

        # Construir dict de actualización, solo cambiar estado si no está escalated
        updates = {"x_studio_respuesta_ia": response_text}
        for idx, record in enumerate(get_json.get("result", [])):
            if record.get("x_studio_estado") != "escalated":
                updates["x_studio_estado"] = "responded"  # o el estado que desees
        
                # 🔹 Mapear estado → etapa
                etapa_map = {
                    "received": "Nuevo",
                    "processing": "En proceso",
                    "responded": "En proceso",
                    "escalated": "En proceso",
                    "closed": "Hecho"
                }
                etapa_nombre = etapa_map.get("responded", "En proceso")

                # Buscar ID de etapa en Odoo
                search_stage_data = {
                    "jsonrpc": "2.0",
                    "method": "call",
                    "params": {
                        "service": "object",
                        "method": "execute",
                        "args": [
                            ODOO_DB, session["uid"], session["password"],
                            "x_ia_tai_stage", "search",
                            [["name", "=", etapa_nombre]], 1
                        ]
                    }
                }
                stage_result = requests.post(f"{ODOO_URL}/jsonrpc", json=search_stage_data).json().get("result", [])
                if stage_result:
                    updates["stage_id"] = stage_result[0]

        
        if mark_processed:
            updates["x_studio_procesado_por_ia"] = True
            
        # Llamada para actualizar 
        write_data = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "service": "object",
                "method": "execute",
                "args": [
                    ODOO_DB,
                    session["uid"],
                    session["password"],
                    model,
                    "write",
                    ids_to_update,  # Lista de IDs
                    updates                    # {"x_studio_respuesta_ia": response_text}  # Valores
                ]
            }
        }

        response = requests.post(f"{ODOO_URL}/jsonrpc", json=write_data)
        resp_json = response.json()
        if "error" in resp_json:
            logger.error(f"Odoo error al guardar respuesta IA: {resp_json['error']}")
            return False

        logger.info(f"Respuesta IA guardada y etapa actualizada para IDs {ids_to_update}")
        return True
    except Exception as e:
        logger.error(f"Error guardando respuesta IA: {e}")
        return False

def update_odoo_ia_status(message_id, active=True):
    """Activa o desactiva la IA para un mensaje."""
    try:
        session = authenticate_odoo()
        model = "x_ia_tai"ids_to_update = [message_id] if isinstance(message_id, int) else message_id
        if isinstance(ids_to_update, list) and any(isinstance(x, list) for x in ids_to_update):
            # Aplanar lista si hay sublistas
            flat_ids = []
            for x in ids_to_update:
                if isinstance(x, list):
                    flat_ids.extend([int(i) for i in x if isinstance(i, int)])
                else:
                    flat_ids.append(x)
            ids_to_update = flat_ids

        data = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "service": "object",
                "method": "execute",
                "args": [
                    ODOO_DB,
                    session["uid"],
                    session["password"],
                    "x_ia_tai",
                    "write",
                    ids_to_update,
                    {"x_studio_ia_activa": active},
                ],
            },
        }
        response = requests.post(f"{ODOO_URL}/jsonrpc", json=data).json()
        if "error" in response:
            logger.error(f"Error actualizando estado de IA: {response['error']}")
            return False
        logger.info(f"IA {'activada' if active else 'desactivada'} para mensaje {message_id}")
        return True
    except Exception as e:
        logger.error(f"Error update_odoo_ia_status: {e}")
        return False


def update_odoo_human_response(message_id, timestamp):
    """Guarda la hora de la última intervención humana."""
    try:
        session = authenticate_odoo()
        model = "x_ia_tai"
        data = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "service": "object",
                "method": "execute",
                "args": [
                    ODOO_DB,
                    session["uid"],
                    session["password"],
                    model,
                    "write",
                    [message_id],
                    {"x_studio_hora_ultimo_humano": timestamp.isoformat()},
                ],
            },
        }
        response = requests.post(f"{ODOO_URL}/jsonrpc", json=data)
        if "error" in response.json():
            logger.error(f"Error actualizando hora humano: {response.json()['error']}")
            return False
        logger.info(f"Última intervención humana actualizada en {timestamp}")
        return True
    except Exception as e:
        logger.error(f"Error update_odoo_human_response: {e}")
        return False


# ===========================
# Funciones WhatsApp
# ===========================
def send_whatsapp_message(phone, message_text):
    try:
        url = f"https://graph.facebook.com/v16.0/{WHATSAPP_PHONE_NUMBER_ID}/messages"
        payload = {
            "messaging_product": "whatsapp",
            "to": phone,
            "type": "text",
            "text": {"body": message_text}
        }
        headers = {"Authorization": f"Bearer {WHATSAPP_ACCESS_TOKEN}",
                   "Content-Type": "application/json"}
        response = requests.post(url, json=payload, headers=headers)
        logger.debug(f"WhatsApp API response: {response.status_code} {response.text}")
    except Exception as e:
        logger.error(f"Error enviando WhatsApp: {e}")

# ===========================
# Funciones IA
# ===========================
def generar_respuesta_openai(message_id, text, config, prompt_base):
    """
    Genera respuesta considerando:
    - Historial de la conversación (x_ia_tai)
    - Base de conocimiento (otro modelo en Odoo)
    """
    try:
        session = authenticate_odoo()
        model_historial = "x_ia_tai"
        model_base = "x_base_conocimiento"  # tu modelo de base de conocimiento

        # 1️⃣ Traer historial
        get_hist = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "service": "object",
                "method": "execute",
                "args": [
                    ODOO_DB, session["uid"], session["password"],
                    model_historial, "read", [message_id],
                    ["x_studio_mensajes_historial"]
                ]
            }
        }
        resp_hist = requests.post(f"{ODOO_URL}/jsonrpc", json=get_hist).json()
        historial_str = resp_hist.get("result", [{}])[0].get("x_studio_mensajes_historial", "[]")
        try:
            historial = json.loads(historial_str)
        except:
            historial = []

        # 2️⃣ Traer información de la base de conocimiento
        get_base = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "service": "object",
                "method": "execute",
                "args": [
                    ODOO_DB, session["uid"], session["password"],
                    model_base, "search_read",
                    [], ["name", "respuesta", "palabras_clave"]
                ]
            }
        }
        resp_base = requests.post(f"{ODOO_URL}/jsonrpc", json=get_base).json()
        kb_entries = resp_base.get("result", [])

        # Construir prompt de base de conocimiento
        kb_text = ""
        for entry in kb_entries:
            kb_text += f"Pregunta: {entry.get('name', '')}\nRespuesta: {entry.get('respuesta', '')}\n\n"

        # 3️⃣ Preparar mensajes para OpenAI
        messages = [{"role": "system", "content": prompt_base + "\n" + kb_text}]
        for h in historial:
            role = h.get("role", "user")
            content = h.get("content", "")
            messages.append({"role": role, "content": content})

        messages.append({"role": "user", "content": text})

        # 4️⃣ Llamada a OpenAI
        response = openai.ChatCompletion.create(
            model=config['model_name'],
            messages=messages,
            max_tokens=config.get('max_tokens', 500),
            temperature=config.get('temperature', 0.7)
        )
        respuesta = response.choices[0].message.content

        # 5️⃣ Guardar mensaje y respuesta en historial
        historial.append({"role": "user", "content": text})
        historial.append({"role": "assistant", "content": respuesta})
        update_odoo_response_historial(message_id, json.dumps(historial))

        return respuesta

    except Exception as e:
        logger.error(f"Error generando respuesta OpenAI con historial y base: {e}")
        return "Disculpa, estamos teniendo problemas técnicos."

def update_odoo_response_historial(message_id, historial):
    """Actualiza el historial de mensajes en Odoo."""
    try:
        session = authenticate_odoo()
        model = "x_ia_tai"
        data = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "service": "object",
                "method": "execute",
                "args": [
                    ODOO_DB, session["uid"], session["password"],
                    model, "write", [message_id],
                    {"x_studio_mensajes_historial": historial}
                ]
            }
        }
        resp = requests.post(f"{ODOO_URL}/jsonrpc", json=data).json()
        if "error" in resp:
            logger.error(f"Error guardando historial en Odoo: {resp['error']}")
            return False
        return True
    except Exception as e:
        logger.error(f"Error update_odoo_response_historial: {e}")
        return False


def get_stage_id(nombre_etapa):
    """
    Devuelve el ID de la etapa según su nombre.
    """
    try:
        session = authenticate_odoo()
        search_data = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "service": "object",
                "method": "execute",
                "args": [
                    ODOO_DB,
                    session["uid"],
                    session["password"],
                    "x_ia_tai_stage",  # o crm.stage según tu modelo
                    "search_read",
                    [["name", "=", nombre_etapa]],
                    ["id"]
                ]
            }
        }
        response = requests.post(f"{ODOO_URL}/jsonrpc", json=search_data).json()
        result = response.get("result", [])
        if result:
            return result[0]["id"]
    except Exception as e:
        logger.error(f"Error obteniendo ID de etapa {nombre_etapa}: {e}")
    return False


def get_ia_config():
    try:
        session = authenticate_odoo()
        search_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [
                    ODOO_DB, session['uid'], session['password'],
                    'x_configuracion_ia_tai', 'search_read',
                    [['x_studio_activo', '=', True]],
                    ['x_studio_nombre', 'x_studio_respuestas_automticas',
                     'x_studio_prompt_del_sistema', 'x_studio_palabras_escalamiento']
                ]
            }
        }
        response = requests.post(f"{ODOO_URL}/jsonrpc", json=search_data)
        configs = response.json().get('result', [])
        if not configs:
            logger.warning("[IA] No se encontró configuración activa en Odoo")
            return None

        config = configs[0]
        ia_config = {
            'api_key': config.get('x_studio_nombre', '').strip(),
            'model_name': 'gpt-3.5-turbo',
            'max_tokens': 200,
            'temperature': 0.7,
            'auto_response': config.get('x_studio_respuestas_automticas', False),
            'system_prompt': config.get('x_studio_prompt_del_sistema', 'Eres un asistente profesional. Responde cordialmente.'),
            'escalation_keywords': config.get('x_studio_palabras_escalamiento', '')
        }
        if not ia_config['api_key']:
            logger.error("[IA] La API key de OpenAI no está configurada en Odoo")
            return None
        return ia_config
    except Exception as e:
        logger.error(f"Error get_ia_config: {e}")
        return None

# ===========================
# Procesamiento mensajes
# ===========================
def is_valid_message(data):
    try:
        entry = data.get('entry', [])
        if not entry:
            return False
        changes = entry[0].get('changes', [])
        if not changes:
            return False
        value = changes[0].get('value', {})
        messages = value.get('messages', [])
        return len(messages) > 0
    except Exception as e:
        logger.error(f"Error validando mensaje: {e}")
        return False

def process_whatsapp_message(data):
    try:
        entry = data['entry'][0]
        changes = entry['changes'][0]
        value = changes['value']
        contacts = value.get('contacts', [])

        if 'messages' in value:
            for message in value['messages']:
                phone_number = message.get('from')
                contact_name = phone_number
                for contact in contacts:
                    if contact.get('wa_id') == phone_number:
                        contact_name = contact.get('profile', {}).get('name', phone_number)
                        break

                message_type = message.get('type', 'text')
                message_text = ''
                if message_type == 'text':
                    message_text = message.get('text', {}).get('body', '')
                elif message_type == 'button':
                    message_text = message.get('button', {}).get('text', '')
                elif message_type == 'interactive':
                    interactive = message.get('interactive', {})
                    if 'button_reply' in interactive:
                        message_text = interactive['button_reply'].get('title', '')
                    elif 'list_reply' in interactive:
                        message_text = interactive['list_reply'].get('title', '')

                message_info = {
                    'phone': phone_number,
                    'name': contact_name,
                    'text': message_text,
                    'type': message_type
                }

                # Crear partner
                partner_id = get_or_create_partner(message_info)

                # Crear mensaje en Odoo
                create_odoo_message(message_info, partner_id)

                # Generar respuesta IA
                ia_config = get_ia_config()
                if ia_config:
                    respuesta_ia = generar_respuesta_openai(message_text, ia_config, ia_config['system_prompt'])
                    send_whatsapp_message(phone_number, respuesta_ia)
    except Exception as e:
        logger.error(f"Error procesando mensaje: {e}")

def get_or_create_partner(message_info):
    try:
        session = authenticate_odoo()
        phone = message_info.get('phone')
        name = message_info.get('name', phone)

        search_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [ODOO_DB, session['uid'], session['password'],
                         'res.partner', 'search', [['phone', '=', phone]]]
            }
        }
        response = requests.post(f"{ODOO_URL}/jsonrpc", json=search_data)
        partner_ids = response.json().get('result', [])
        if partner_ids:
            return partner_ids[0]

        create_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [ODOO_DB, session['uid'], session['password'],
                         'res.partner', 'create', {'name': name, 'phone': phone, 'is_company': False}]
            }
        }
        resp = requests.post(f"{ODOO_URL}/jsonrpc", json=create_data)
        return resp.json().get('result')
    except Exception as e:
        logger.error(f"Error get_or_create_partner: {e}")
        return None

# ===========================
# Rutas Flask
# ===========================
@app.route("/", methods=["GET"])
def home():
    return jsonify({'status': 'WhatsApp IA Webhook funcionando', 'timestamp': datetime.now().isoformat()})

@app.route("/webhook", methods=["GET"])
def verify_webhook():
    """Verificación del token de Meta"""
    mode = request.args.get("hub.mode")
    token = request.args.get("hub.verify_token")
    challenge = request.args.get("hub.challenge")

    if mode and token:
        if mode == "subscribe" and token == WEBHOOK_VERIFY_TOKEN:
            logger.info("Webhook verificado correctamente.")
            return challenge, 200
        else:    
            logger.warning("Verificación fallida.")
            return "Forbidden", 403
    return "Bad Request", 400

@app.route("/webhook", methods=["POST"])
def webhook():
    """Recibe mensajes desde WhatsApp y los guarda en Odoo, maneja escalamiento."""
    try:
        data = request.get_json()
        logger.info(f"Mensaje recibido: {json.dumps(data)}")

        if data.get("object") != "whatsapp_business_account":
            return "No es WhatsApp", 400

        for entry in data.get("entry", []):
            for change in entry.get("changes", []):
                value = change.get("value", {})
                messages = value.get("messages", [])
                contacts = value.get("contacts", [])
                if not messages:
                    continue

                for message in messages:
                    from_number = message.get("from")
                    msg_type = message.get("type", "text")
                    if msg_type == "text":
                        msg_text = message.get("text", {}).get("body", "").strip()
                    elif msg_type == "button":
                        msg_text = message.get("button", {}).get("text", "")
                    elif msg_type == "interactive":
                        interactive = message.get("interactive", {})
                        if "button_reply" in interactive:
                            msg_text = interactive["button_reply"].get("title", "")
                        elif "list_reply" in interactive:
                            msg_text = interactive["list_reply"].get("title", "")
                    else:
                        msg_text = ""
                    
                    msg_text_lower = msg_text.lower()

                    message_info = {
                        "text": msg_text,
                        "phone": from_number
                    }

                    # Crear partner en Odoo
                    partner_id = get_or_create_partner(message_info)

                    # Crear mensaje en Odoo
                    odoo_id = create_odoo_message(message_info, partner_id)
                    if not odoo_id:
                        continue

                    # Obtener configuración IA
                    ia_config = get_ia_config()
                    if not ia_config:
                        logger.warning("No hay configuración IA activa")
                        continue

                    
                    # Validar escalamiento
         #           if odoo_id:
          #              ia_config = get_ia_config()
           #             palabras_escalamiento = []
            #        if ia_config:
             #           palabras_escalamiento = ia_config.get("escalation_keywords", "").lower().split(",")

              #      palabras_escalamiento = [p.strip() for p in palabras_escalamiento if p.strip()]
                                  
               #     if not palabras_escalamiento:
                #        palabras_escalamiento = ["asesor", "humano", "agente", "soporte", "persona", "ayuda"]

                    # Obtener registro de Odoo
                    odoo_record = get_odoo_record(odoo_id)
                    if not odoo_record:
                        continue

                    ia_activa = odoo_record.get("x_studio_ia_activa", True)
                    ultima_hora_humano = odoo_record.get("x_studio_hora_ultimo_humano")
                    now_utc = datetime.utcnow().replace(tzinfo=pytz.UTC)

                    # Verificar si es un mensaje de un humano (por ejemplo, enviado desde Odoo manualmente)
                    if message.get("from_type") == "human":
                        update_odoo_human_response(odoo_id, now_utc)
                        update_odoo_ia_status(odoo_id, active=False)
                        logger.info(f"IA desactivada por intervención humana en mensaje {odoo_id}")
                        continue

                    # Si hubo intervención humana hace menos de 4 horas, IA sigue desactivada
                    if ultima_hora_humano:
                        try:
                            last_human_dt = datetime.fromisoformat(ultima_hora_humano)
                            if (now_utc - last_human_dt) < timedelta(hours=4):
                                ia_activa = False
                                update_odoo_ia_status(odoo_id, active=False)
                                logger.info("IA sigue desactivada (<4h desde intervención humana)")
                            else:
                                ia_activa = True
                                update_odoo_ia_status(odoo_id, active=True)
                                logger.info("IA reactivada (>4h desde intervención humana)")
                        except Exception as e:
                            logger.error(f"Error interpretando hora de humano: {e}")
                    else:
                        ia_activa = True
                        update_odoo_ia_status(odoo_id, active=True)

                     # Escalamiento
                    palabras_escalamiento = ia_config.get("escalation_keywords", "").lower().split(",")
                    palabras_escalamiento = [p.strip() for p in palabras_escalamiento if p.strip()]
                    if not palabras_escalamiento:
                        palabras_escalamiento = ["asesor","humano","agente","soporte","persona","ayuda"]
                    
                    # 🚨 Escalamiento
                    if any(p in msg_text_lower for p in palabras_escalamiento):
                        logger.info("🚨 Escalamiento detectado. Actualizando estado en Odoo...")
                        update_message_status(odoo_id, "escalated", mark_processed=True)
                        continue

                    # Si la IA está activa, genera respuesta
                    if ia_activa:
                        respuesta_ia = generar_respuesta_openai(msg_text, ia_config, ia_config['system_prompt'])
                        send_whatsapp_message(from_number, respuesta_ia)
                        update_odoo_response(odoo_id, respuesta_ia, mark_processed=True)
                        update_message_status(odoo_id, "responded", mark_processed=True)
                                    
        return "EVENT_RECEIVED", 200
    except Exception as e:
        logger.error(f"Error procesando webhook: {e}")
        return "ERROR", 500


# ===========================
# Ejecutar Flask
# ===========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)


































