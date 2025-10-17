from flask import Flask, request, jsonify
import openai
import requests
import json
import logging
from datetime import datetime
import os
import sys

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

# =========================
# ACTUALIZAR ESTADO EN ODOO
# =========================
def update_message_status(message_id, new_status):
    """Actualiza el campo x_studio_estado del mensaje en Odoo de manera segura."""
    try:
        session = authenticate_odoo()
        if not session or not session.get("uid"):
            logger.error("Sesión inválida para Odoo")
            return False

        model = "x_ia_tai"

        # Asegurar que message_id sea lista de enteros
        if isinstance(message_id, int):
            ids_to_update = [message_id]
        elif isinstance(message_id, list):
            # Si la lista tiene elementos, usar solo los enteros
            ids_to_update = [m for m in message_id if isinstance(m, int)]
            if not ids_to_update:
                logger.error("No se encontró ningún ID válido para actualizar")
                return False
        else:
            logger.error(f"Tipo de ID inválido: {type(message_id)}")
            return False

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
                    [ids_to_update, {"x_studio_estado": new_status}]
                ]
            }
        }

        response = requests.post(f"{ODOO_URL}/jsonrpc", json=data)
        resp_json = response.json()
        if "error" in resp_json:
            logger.error(f"Odoo error al actualizar estado: {resp_json['error']}")
            return False

        logger.info(f"Estado actualizado a '{new_status}' para IDs {ids_to_update}")
        return True
    except Exception as e:
        logger.error(f"Error actualizando estado: {e}")
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
def generar_respuesta_openai(text, config, prompt):
    try:
        openai.api_key = config['api_key']
        response = openai.ChatCompletion.create(
            model=config['model_name'],
            messages=[
                {"role": "system", "content": prompt},
                {"role": "user", "content": text}
            ],
            max_tokens=config['max_tokens'],
            temperature=config['temperature']
        )
        return response.choices[0].message['content']
    except Exception as e:
        logger.error(f"Error generando respuesta OpenAI: {e}")
        return "Disculpa, estamos teniendo problemas técnicos."

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
                    msg_text = message.get("text", {}).get("body", "").strip()
                    msg_text_lower = msg_text.lower()

                    message_info = {
                        "text": msg_text,
                        "phone": from_number
                    }

                    # Crear partner en Odoo
                    partner_id = get_or_create_partner(message_info)

                    # Crear mensaje en Odoo
                    odoo_id = create_odoo_message(message_info, partner_id)

                    # Validar escalamiento
                    if odoo_id:
                        ia_config = get_ia_config()
                        palabras_escalamiento = []
                        if ia_config:
                            palabras_escalamiento = ia_config.get("escalation_keywords", "").lower().split(",")

                        # Convertir a lista de palabras y limpiar espacios
                        palabras_escalamiento = [p.strip() for p in palabras_escalamiento if p.strip()]
                        # Si no hay palabras configuradas, usar predeterminadas
                        if not palabras_escalamiento:
                            palabras_escalamiento = ["asesor", "humano", "agente", "soporte", "persona", "ayuda"]

                        if any(p in msg_text_lower for p in palabras_escalamiento):
                            logger.info("🚨 Escalamiento detectado. Actualizando estado en Odoo...")
                            update_message_status(odoo_id, "escalado")

                        # Generar respuesta IA y enviar
                        if ia_config:
                            respuesta_ia = generar_respuesta_openai(msg_text, ia_config, ia_config['system_prompt'])
                            send_whatsapp_message(from_number, respuesta_ia)

        return "EVENT_RECEIVED", 200
    except Exception as e:
        logger.error(f"Error procesando webhook: {e}")
        return "ERROR", 500


# ===========================
# Ejecutar Flask
# ===========================
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)












