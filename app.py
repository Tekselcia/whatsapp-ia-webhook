from flask import Flask, request, jsonify
import openai
import requests
import json
import logging
from datetime import datetime
import os

# ===========================
# Configuración logging
# ===========================
logging.basicConfig(level=logging.INFO)
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
ODOO_URL = os.getenv('ODOO_URL')  # https://tu-empresa.odoo.com
ODOO_DB = os.getenv('ODOO_DB')    # tu-base-datos
ODOO_USER = os.getenv('ODOO_USER')
ODOO_PASSWORD = os.getenv('ODOO_PASSWORD')
WEBHOOK_VERIFY_TOKEN = os.getenv('WEBHOOK_VERIFY_TOKEN', 'mi_token_secreto')

# Configurar OpenAI
openai.api_key = OPENAI_API_KEY

# ===========================
# Rutas básicas
# ===========================
@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'status': 'WhatsApp IA Webhook funcionando',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/webhook', methods=['GET'])
def verify_webhook():
    """Verificación del webhook de Meta"""
    try:
        mode = request.args.get('hub.mode')
        token = request.args.get('hub.verify_token')
        challenge = request.args.get('hub.challenge')
        
        logger.info(f"Verificación webhook: mode={mode}, token={token}")
        
        if mode == 'subscribe' and token == WEBHOOK_VERIFY_TOKEN:
            logger.info("Webhook verificado correctamente")
            return challenge
        else:
            logger.error("Verificación fallida")
            return 'Forbidden', 403
            
    except Exception as e:
        logger.error(f"Error en verificación: {e}")
        return 'Error', 500

@app.route('/webhook', methods=['POST'])
def whatsapp_webhook():
    """Procesar mensajes de WhatsApp"""
    try:
        data = request.get_json()
        logger.info(f"Webhook recibido: {json.dumps(data, indent=2)}")
        
        if not is_valid_message(data):
            return jsonify({'status': 'ignored'})
        
        process_whatsapp_message(data)
        
        return jsonify({'status': 'success'})
        
    except Exception as e:
        logger.error(f"Error procesando webhook: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ===========================
# Funciones de validación
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

# ===========================
# Procesamiento de mensajes
# ===========================
def process_whatsapp_message(data):
    try:
        entry = data['entry'][0]
        changes = entry['changes'][0]
        value = changes['value']
        
        if 'messages' in value:
            for message in value['messages']:
                message_info = extract_message_info(message, value)
                if message_info:
                    handle_message(message_info)
                    
    except Exception as e:
        logger.error(f"Error procesando mensaje: {e}")

def extract_message_info(message, value):
    try:
        phone_number = message.get('from')
        message_id = message.get('id')
        timestamp = message.get('timestamp')
        
        message_text = ''
        message_type = message.get('type', 'unknown')
        
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
        
        contact_name = phone_number
        if 'contacts' in value:
            contacts = value['contacts']
            for contact in contacts:
                if contact.get('wa_id') == phone_number:
                    profile = contact.get('profile', {})
                    contact_name = profile.get('name', phone_number)
                    break
        
        return {
            'phone': phone_number,
            'name': contact_name,
            'text': message_text,
            'type': message_type,
            'message_id': message_id,
            'timestamp': timestamp
        }
        
    except Exception as e:
        logger.error(f"Error extrayendo información: {e}")
        return None

# ===========================
# Manejo completo del mensaje
# ===========================
def handle_message(message_info):
    try:
        logger.info(f"[STEP 0] Procesando mensaje de {message_info['name']}: {message_info['text']}")

        # 1. Buscar o crear contacto
        partner_id = get_or_create_partner(message_info)
        logger.debug(f"[STEP 1] Partner ID obtenido/creado: {partner_id}")

        # 2. Crear mensaje en Odoo
        message_id = create_odoo_message(message_info, partner_id)
        if not message_id:
            logger.error("[STEP 2] No se pudo crear mensaje en Odoo")
            return
        logger.debug(f"[STEP 2] ID de mensaje creado en Odoo: {message_id}")

        # 3. Escalamiento
        if needs_escalation(message_info['text']):
            logger.debug("[STEP 3] Mensaje requiere escalamiento")
            escalate_message(message_id, message_info)
            return
        else:
            logger.debug("[STEP 3] Mensaje no requiere escalamiento")

        # 4. Config IA
        ia_config = get_ia_config()
        if not ia_config or not ia_config.get('auto_response'):
            logger.info("[STEP 4] Respuestas automáticas desactivadas o configuración no encontrada")
            return
        logger.debug(f"[STEP 4] Configuración IA: {ia_config}")

        # 5. Obtener conocimiento
        knowledge_context = get_relevant_knowledge(message_info['text'])
        logger.debug(f"[STEP 5] Contexto relevante: {knowledge_context}")

        # 6. Generar respuesta IA
        ia_response = generate_ia_response(
            message_info['text'],
            ia_config,
            knowledge_context,
            message_info['name']
        )
        if ia_response:
            logger.debug(f"[STEP 6] Respuesta IA: {ia_response}")

            # 7. Actualizar mensaje en Odoo
            update_message_with_response(message_id, ia_response)
            logger.debug("[STEP 7] Mensaje actualizado con respuesta IA")

            # 8. Crear log IA
            create_ia_log(message_info, ia_response, partner_id)
            logger.debug("[STEP 8] Log IA creado")

            # 9. Enviar WhatsApp
            send_whatsapp_message(message_info['phone'], ia_response)
            logger.info(f"[STEP 9] Respuesta enviada a {message_info['name']}")

        else:
            logger.debug("[STEP 6] No se generó respuesta IA")

    except Exception as e:
        logger.error(f"[ERROR] Error manejando mensaje: {e}")
        create_error_log(message_info, str(e))

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

def get_or_create_partner(message_info):
    try:
        session = authenticate_odoo()
        if not session or not session.get('uid'):
            return None
        phone = message_info.get('phone')
        name = message_info.get('name', phone)

        # Buscar existente
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

        # Crear partner
        partner_data = {'name': name, 'phone': phone, 'is_company': False, 'customer_rank': 1, 'supplier_rank': 0}

        create_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [ODOO_DB, session['uid'], session['password'],
                         'res.partner', 'create', partner_data]
            }
        }
        response = requests.post(f"{ODOO_URL}/jsonrpc", json=create_data)
        result = response.json().get('result')
        return result
    except Exception as e:
        logger.error(f"Error get_or_create_partner: {e}")
        return None

def create_odoo_message(message_info, partner_id):
    try:
        session = authenticate_odoo()
        create_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [
                    ODOO_DB, session['uid'], session['password'],
                    'x_ia_tai', 'create',
                    {
                        'x_studio_partner_id': partner_id,
                        'x_studio_partner_phone': message_info['phone'],
                        'x_studio_tipo_de_mensaje': 'inbound',
                        'x_studio_mensaje_whatsapp': message_info['text'],
                        'x_studio_date': datetime.now().replace(microsecond=0).isoformat(),
                        'x_studio_estado': 'received'
                    }
                ]
            }
        }

        # Validar payload
        validation_errors = validate_odoo_payload_generic('x_ia_tai', create_data)
        if validation_errors:
            logger.error(f"[ERROR] Payload inválido Odoo: {validation_errors}")
            return None

        response = requests.post(f"{ODOO_URL}/jsonrpc", json=create_data)
        result = response.json().get('result')
        return result
    except Exception as e:
        logger.error(f"Error create_odoo_message: {e}")
        return None

def validate_odoo_payload_generic(model_name, payload):
    errors = []
    try:
        data = payload.get('params', {}).get('args', [])[4]
        if not data:
            errors.append("Payload vacío")
            return errors

        required_fields_by_model = {
            'x_ia_tai': [
                'x_studio_partner_id',
                'x_studio_partner_phone',
                'x_studio_tipo_de_mensaje',
                'x_studio_mensaje_whatsapp',
                'x_studio_date',
                'x_studio_estado'
            ]
        }
        required_fields = required_fields_by_model.get(model_name, [])
        for field in required_fields:
            if field not in data or data[field] in [None, '']:
                errors.append(f"Campo obligatorio faltante o vacío: {field}")

        for key, value in data.items():
            if 'date' in key.lower() and value:
                try:
                    datetime.fromisoformat(value)
                except Exception:
                    errors.append(f"Campo {key} no tiene formato ISO 8601 válido: {value}")
    except Exception as e:
        errors.append(f"Error validando payload: {e}")
    return errors

# ===========================
# IA, escalamiento, logs
# ===========================
def get_ia_config():
    try:
        session = authenticate_odoo()
        search_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [ODOO_DB, session['uid'], session['password'],
                         'x_configuracion_ia_tai', 'search_read',
                         [['x_studio_activo', '=', True]],
                         ['x_studio_nombre', 'x_studio_respuestas_automticas', 'x_studio_prompt_del_sistema', 'x_studio_palabras_escalamiento']]
            }
        }
        response = requests.post(f"{ODOO_URL}/jsonrpc", json=search_data)
        configs = response.json().get('result', [])
        if configs:
            config = configs[0]
            return {
                'api_key': config.get('x_studio_nombre'),
                'model_name': 'gpt-3.5-turbo',
                'max_tokens': 200,
                'temperature': 0.7,
                'auto_response': config.get('x_studio_respuestas_automticas', False),
                'system_prompt': config.get('x_studio_prompt_del_sistema', ''),
                'escalation_keywords': config.get('x_studio_palabras_escalamiento', '')
            }
        return None
    except Exception as e:
        logger.error(f"Error get_ia_config: {e}")
        return None

def get_relevant_knowledge(message_text):
    try:
        session = authenticate_odoo()
        search_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [ODOO_DB, session['uid'], session['password'],
                         'x_base_conocimiento', 'search_read',
                         [['x_active', '=', True]],
                         ['x_titulo', 'x_palabras_clave', 'x_pregunta', 'x_respuesta', 'x_veces_usada']]
            }
        }
        response = requests.post(f"{ODOO_URL}/jsonrpc", json=search_data)
        knowledge_items = response.json().get('result', [])
        relevant = []
        msg_lower = message_text.lower()
        for item in knowledge_items:
            keywords = item.get('x_palabras_clave', '')
            if keywords:
                if any(k.strip().lower() in msg_lower for k in keywords.split(',')):
                    relevant.append({'id': item['id'], 'pregunta': item.get('x_pregunta', ''),
                                     'respuesta': item.get('x_respuesta', ''), 'titulo': item.get('x_titulo', '')})
        return relevant[:3]
    except Exception as e:
        logger.error(f"Error get_relevant_knowledge: {e}")
        return []

def needs_escalation(message_text):
    try:
        ia_config = get_ia_config()
        if not ia_config:
            return False
        keywords = ia_config.get('escalation_keywords', '')
        if not keywords:
            return False
        return any(k.strip().lower() in message_text.lower() for k in keywords.split(','))
    except Exception as e:
        logger.error(f"Error needs_escalation: {e}")
        return False

def generate_ia_response(message_text, ia_config, knowledge_context, customer_name):
    try:
        openai.api_key = ia_config.get('api_key')
        knowledge_text = ""
        if knowledge_context:
            knowledge_text = "\n\nINFORMACIÓN RELEVANTE:\n" + \
                             "\n".join(f"- {item['titulo']}: {item['respuesta']}" for item in knowledge_context)
        system_prompt = ia_config.get('system_prompt') or \
            "Eres un asistente profesional. Responde cordialmente y ofrece ayuda adicional."
        full_prompt = f"{system_prompt}\n\nCLIENTE: {customer_name}\nMENSAJE: {message_text}\nResponde:"
        response = openai.ChatCompletion.create(
            model=ia_config.get('model_name', 'gpt-3.5-turbo'),
            messages=[{"role": "user", "content": full_prompt}],
            max_tokens=ia_config.get('max_tokens', 200),
            temperature=ia_config.get('temperature', 0.7)
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.error(f"Error generate_ia_response: {e}")
        return "Disculpa, estamos teniendo problemas técnicos. Un agente te contactará."

def update_message_with_response(message_id, ia_response):
    try:
        session = authenticate_odoo()
        update_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [ODOO_DB, session['uid'], session['password'],
                         'x_ia_tai', 'write', [message_id],
                         {'x_studio_procesado_por_ia': True,
                          'x_studio_respuesta_ia': ia_response,
                          'x_studio_estado': 'responded'}]
            }
        }
        requests.post(f"{ODOO_URL}/jsonrpc", json=update_data)
    except Exception as e:
        logger.error(f"Error update_message_with_response: {e}")

def create_ia_log(message_info, ia_response, partner_id):
    try:
        session = authenticate_odoo()
        create_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [ODOO_DB, session['uid'], session['password'],
                         'x_logs_ia', 'create',
                         {'x_cliente': partner_id,
                          'x_telefono': message_info['phone'],
                          'x_mensaje_original': message_info['text'],
                          'x_respuesta_ia': ia_response,
                          'x_estado': 'sent',
                          'x_tiempo_procesamiento': 2.5}]
            }
        }
        requests.post(f"{ODOO_URL}/jsonrpc", json=create_data)
    except Exception as e:
        logger.error(f"Error create_ia_log: {e}")

def create_error_log(message_info, error_message):
    try:
        session = authenticate_odoo()
        create_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [ODOO_DB, session['uid'], session['password'],
                         'x_logs_ia', 'create',
                         {'x_cliente': message_info.get('phone'),
                          'x_telefono': message_info.get('phone'),
                          'x_mensaje_original': message_info.get('text'),
                          'x_respuesta_ia': error_message,
                          'x_estado': 'error',
                          'x_tiempo_procesamiento': 0}]
            }
        }
        requests.post(f"{ODOO_URL}/jsonrpc", json=create_data)
    except Exception as e:
        logger.error(f"Error creando log de error: {e}")

def escalate_message(message_id, message_info):
    try:
        session = authenticate_odoo()
        update_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [ODOO_DB, session['uid'], session['password'],
                         'x_ia_tai', 'write', [message_id],
                         {'x_studio_estado': 'escalated'}]
            }
        }
        requests.post(f"{ODOO_URL}/jsonrpc", json=update_data)
        logger.info(f"Mensaje {message_id} escalado correctamente")
    except Exception as e:
        logger.error(f"Error escalando mensaje: {e}")

# ===========================
# WhatsApp API
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
# Run Flask
# ===========================
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)



