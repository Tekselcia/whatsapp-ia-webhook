from flask import Flask, request, jsonify
import openai
import requests
import json
import logging
from datetime import datetime
import os
from flask import Flask, request, jsonify


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

@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.json
    # Procesa tu mensaje
    return jsonify({"status": "ok"})
    

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
@app.post("/webhook")
async def handle_message(request: Request):
    try:
        data = await request.json()
        logger.info(f"[STEP 1] Webhook recibido: {data}")

        message = data.get('message', {})
        sender = message.get('from')
        text = message.get('text', {}).get('body', '').strip()

        if not text:
            logger.warning("[STEP 2] Mensaje vacío o sin texto")
            return {"status": "sin texto"}

        logger.info(f"[STEP 3] Mensaje recibido de {sender}: {text}")

        # 🔹 Obtener configuración de IA desde Odoo
        ia_config = get_ia_config()
        if not ia_config:
            logger.error("[STEP 4] No se encontró configuración de IA")
            return {"status": "sin configuración"}

        # 🔹 Analizar si es palabra de escalamiento
        escalation_keywords = ia_config.get('escalation_keywords', '').lower().split(',')
        is_escalation = any(word.strip() in text.lower() for word in escalation_keywords)

        session = authenticate_odoo()
        if not session:
            logger.error("[STEP 5] Falló la autenticación con Odoo")
            return {"status": "error autenticación"}

        if is_escalation:
            logger.info("[STEP 6] Palabra de escalamiento detectada 🚨")

            # ✅ Crear ticket en Odoo
            ticket_data = {
                'jsonrpc': '2.0',
                'method': 'call',
                'params': {
                    'service': 'object',
                    'method': 'execute',
                    'args': [
                        ODOO_DB,
                        session['uid'],
                        session['password'],
                        'helpdesk.ticket',  # Modelo del ticket
                        'create',
                        [{
                            'x_studio_nombre': f"Escalamiento desde WhatsApp - {sender}",
                            'x_studio_descripcion': text,
                            'x_studio_estado': 'nuevo',
                            'x_studio_origen': 'whatsapp',
                            'x_studio_cliente': sender
                        }]
                    ]
                }
            }

            resp_ticket = requests.post(f"{ODOO_URL}/jsonrpc", json=ticket_data)
            logger.info(f"[STEP 7] Ticket creado en Odoo: {resp_ticket.text}")

            # ✅ Enviar confirmación al cliente
            send_whatsapp_message(sender, "📩 Hemos escalado tu mensaje con nuestro equipo. En breve un asesor te contactará. ¡Gracias por tu paciencia!")
            
            return {"status": "ticket creado"}

        # 🔹 Generar respuesta con IA
        prompt = ia_config.get('system_prompt', '')
        respuesta_ia = generar_respuesta_openai(text, ia_config, prompt)

        logger.info(f"[IA] Respuesta generada: {respuesta_ia}")

        # 🔹 Registrar mensaje en Odoo
        message_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [
                    ODOO_DB,
                    session['uid'],
                    session['password'],
                    'x_mensajes_ia_tai',
                    'create',
                    [{
                        'x_studio_numero': sender,
                        'x_studio_mensaje': text,
                        'x_studio_respuesta': respuesta_ia,
                        'x_studio_estado': 'responded'
                    }]
                ]
            }
        }

        response_odoo = requests.post(f"{ODOO_URL}/jsonrpc", json=message_data)
        logger.info(f"[STEP 8] Log IA creado: {response_odoo.text}")

        # 🔹 Enviar respuesta al cliente por WhatsApp
        send_whatsapp_message(sender, respuesta_ia)
        logger.info(f"[STEP 9] Respuesta enviada a {sender}")

        # 🔹 Actualizar estado del mensaje a “responded”
        try:
            message_id = response_odoo.json().get('result')
            if message_id:
                update_data = {
                    'jsonrpc': '2.0',
                    'method': 'call',
                    'params': {
                        'service': 'object',
                        'method': 'execute',
                        'args': [
                            ODOO_DB,
                            session['uid'],
                            session['password'],
                            'x_mensajes_ia_tai',
                            'write',
                            [[message_id], {'x_studio_estado': 'responded'}]
                        ]
                    }
                }
                update_resp = requests.post(f"{ODOO_URL}/jsonrpc", json=update_data)
                logger.info(f"[STEP 10] Estado del mensaje actualizado: {update_resp.text}")
        except Exception as e:
            logger.error(f"[ERROR] No se pudo actualizar el estado: {e}")

        return {"status": "ok"}

    except Exception as e:
        logger.error(f"[ERROR handle_message]: {e}")
        return {"status": "error", "detail": str(e)}




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
        if not session or not session.get('uid'):
            logger.error("[STEP 2] Sesión inválida para Odoo")
            return None

        # Mapear tipo de mensaje real de WhatsApp a Odoo
        tipo_mensaje_map = {
            'text': 'inbound',
            'button': 'inbound',
            'interactive': 'inbound',
            'salida': 'outbound'
        }
        # Obtener tipo de mensaje según WhatsApp
        tipo_mensaje = tipo_mensaje_map.get(message_info.get('type', 'text'), 'inbound')

        # Asegurarse de que x_name tenga un valor
        message_text = message_info.get('text') or 'Sin contenido'

        payload_data = {
            'x_name': message_text,  # Coma corregida
            'x_studio_partner_id': partner_id,
            'x_studio_partner_phone': message_info.get('phone'),
            'x_studio_tipo_de_mensaje': tipo_mensaje,
            'x_studio_mensaje_whatsapp': message_text,
            'x_studio_date': datetime.now().replace(microsecond=0).isoformat(),
            'x_studio_estado': 'received'
        }

        # Validar payload antes de enviar
        validation_errors = validate_odoo_payload_fields('x_ia_tai', payload_data)
        if validation_errors:
            logger.error(f"[ERROR] Payload inválido Odoo: {validation_errors}")
            return None

        create_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [
                    ODOO_DB, session['uid'], session['password'],
                    'x_ia_tai',
                    'create',
                    [payload_data]  # Debe ser lista
                ]
            }
        }

        response = requests.post(f"{ODOO_URL}/jsonrpc", json=create_data)
        try:
            resp_json = response.json()
        except Exception as e:
            logger.error(f"[STEP 2] No se pudo parsear JSON de Odoo: {e}")
            return None

        if 'error' in resp_json:
            logger.error(f"[STEP 2] Odoo respondió con error: {json.dumps(resp_json['error'], indent=2)}")
            return None

        result = resp_json.get('result')
        if not result:
            logger.error("[STEP 2] No se creó el mensaje en Odoo. 'result' es None o vacío.")
        else:
            logger.info(f"[STEP 2] Mensaje creado en Odoo con ID: {result}")

        return result

    except Exception as e:
        logger.error(f"[STEP 2] Excepción creando mensaje en Odoo: {e}")
        return None

def validate_odoo_payload_fields(model_name, data):
    """
    Valida un payload de Odoo usando directamente el diccionario de campos.
    - Verifica campos obligatorios (no None ni vacío)
    - Valida campos de fecha en formato ISO 8601
    """
    errors = []

    try:
        if not isinstance(data, dict):
            errors.append("Payload inválido: data no es un diccionario")
            return errors

        # Campos obligatorios por modelo
        required_fields_by_model = {
            'x_ia_tai': [
                'x_name',  # ✅ ahora es obligatorio
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

        # Validar fechas ISO
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
                'args': [
                    ODOO_DB, session['uid'], session['password'],
                    'x_configuracion_ia_tai', 'search_read',
                    [['x_studio_activo', '=', True]],
                    [
                        'x_studio_nombre',                   # Asegúrate aquí que contiene la API key
                        'x_studio_respuestas_automticas',  # Corrige typo si tu campo es diferente
                        'x_studio_prompt_del_sistema',
                        'x_studio_palabras_escalamiento'
                    ]
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

        logger.info(f"[IA] Configuración IA obtenida: {ia_config}")
        return ia_config

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
                         [['x_studio_activo', '=', True]],
                         ['x_name', 'x_studio_palabras_clave', 'x_studio_pregunta', 'x_studio_respuesta', 'x_studio_veces_usada']]
            }
        }
        response = requests.post(f"{ODOO_URL}/jsonrpc", json=search_data)
        knowledge_items = response.json().get('result', [])
        relevant = []
        msg_lower = message_text.lower()
        for item in knowledge_items:
            keywords = item.get('x_studio_palabras_clave', '')
            if keywords:
                if any(k.strip().lower() in msg_lower for k in keywords.split(',')):
                    relevant.append({'id': item['id'], 'pregunta': item.get('x_studio_pregunta', ''),
                                     'respuesta': item.get('x_studio_respuesta', ''), 'titulo': item.get('x_name', '')})
        return relevant[:3]
    except Exception as e:
        logger.error(f"Error get_relevant_knowledge: {e}")
        return []

def generate_ia_response(message_text, ia_config, knowledge_context, customer_name):
    try:
        if not ia_config or not ia_config.get('api_key'):
            logger.error("[IA] No hay configuración de IA válida o falta API key")
            return None

        openai.api_key = ia_config['api_key']

        # Construir contexto de conocimiento relevante
        knowledge_text = ""
        if knowledge_context:
            knowledge_text = "\n\nINFORMACIÓN RELEVANTE:\n" + \
                             "\n".join(f"- {item['titulo']}: {item['respuesta']}" for item in knowledge_context)

        system_prompt = ia_config.get('system_prompt', 'Eres un asistente profesional. Responde cordialmente.')
        full_prompt = f"{system_prompt}\n\nCLIENTE: {customer_name}\nMENSAJE: {message_text}{knowledge_text}\nResponde:"

        logger.info(f"[IA] Prompt enviado a OpenAI:\n{full_prompt}")

        response = openai.ChatCompletion.create(
            model=ia_config.get('model_name', 'gpt-3.5-turbo'),
            messages=[{"role": "user", "content": full_prompt}],
            max_tokens=ia_config.get('max_tokens', 200),
            temperature=ia_config.get('temperature', 0.7)
        )

        ia_result = response.choices[0].message.content.strip()
        logger.info(f"[IA] Respuesta generada: {ia_result}")
        return ia_result

    except Exception as e:
        logger.error(f"[IA] Error generando respuesta: {e}")
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
                          'x_studio_respuesta_ia': ia_response,
                          'x_studio_estado': 'sent',
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
                          'x_studio_telefono': message_info.get('phone'),
                          'x_studio_mensaje_original': message_info.get('text'),
                          'x_studio_respuesta_ia': error_message,
                          'x_studio_estado': 'error',
                          'x_studio_tiempo_procesamiento': 0}]
            }
        }
        requests.post(f"{ODOO_URL}/jsonrpc", json=create_data)
    except Exception as e:
        logger.error(f"Error creando log de error: {e}")

# ===========================
# Función para determinar si un mensaje requiere escalamiento
# ===========================
def needs_escalation(message_text):
    try:
        ia_config = get_ia_config()
        if not ia_config:
            return False
        keywords = ia_config.get('escalation_keywords', '')
        if not keywords:
            return False
        # Verificar si alguna palabra clave aparece en el mensaje (case insensitive)
        return any(k.strip().lower() in message_text.lower() for k in keywords.split(','))
    except Exception as e:
        logger.error(f"Error needs_escalation: {e}")
        return False

# ===========================
# Función para escalamiento
# ===========================
def escalate_message(message_id, message_info):
    try:
        session = authenticate_odoo()
        if not session or not session.get('uid'):
            logger.error("No se pudo autenticar Odoo para escalamiento")
            return

        # Asegurarse de que sea lista de enteros
        ids_to_update = message_id if isinstance(message_id, list) else [message_id]

        # 1️⃣ Actualizar estado del mensaje en Odoo
        update_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [
                    ODOO_DB, session['uid'], session['password'],
                    'x_ia_tai', 'write',
                    ids_to_update,
                    {'x_studio_estado': 'escalated'}
                ]
            }
        }
        response = requests.post(f"{ODOO_URL}/jsonrpc", json=update_data)
        resp_json = response.json()
        if resp_json.get('error'):
            logger.error(f"Error Odoo escalando mensaje: {resp_json['error']}")
        else:
            logger.info(f"Mensaje {message_id} escalado correctamente en Odoo")

        # 2️⃣ Crear ticket de reclamo o incidencia en Odoo (x_tickets_ia)
        ticket_data = {
            'x_cliente': message_info.get('phone'),
            'x_telefono': message_info.get('phone'),
            'x_mensaje_original': message_info.get('text'),
            'x_estado': 'open',
            'x_tipo': 'Reclamo'  # Puedes adaptarlo según tu modelo
        }
        create_ticket = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [
                    ODOO_DB, session['uid'], session['password'],
                    'x_tickets_ia', 'create',
                    [ticket_data]
                ]
            }
        }
        ticket_resp = requests.post(f"{ODOO_URL}/jsonrpc", json=create_ticket).json()
        if ticket_resp.get('error'):
            logger.error(f"No se pudo crear ticket en Odoo: {ticket_resp['error']}")
        else:
            logger.info(f"Ticket de reclamo creado en Odoo: {ticket_resp.get('result')}")

        # 3️⃣ Notificar al cliente por WhatsApp
        send_whatsapp_message(message_info['phone'], 
                              "Tu mensaje ha sido escalado y un agente te contactará pronto. ¡Gracias por tu paciencia!")

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

















