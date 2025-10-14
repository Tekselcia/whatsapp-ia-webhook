from flask import Flask, request, jsonify
import openai
import requests
import json
import logging
from datetime import datetime
import os

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuración - Variables de entorno
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
WHATSAPP_ACCESS_TOKEN = os.getenv('WHATSAPP_ACCESS_TOKEN')
WHATSAPP_PHONE_NUMBER_ID = os.getenv('WHATSAPP_PHONE_NUMBER_ID')
ODOO_URL = os.getenv('ODOO_URL')  # https://tu-empresa.odoo.com
ODOO_DB = os.getenv('ODOO_DB')   # tu-base-datos
ODOO_USER = os.getenv('ODOO_USER')
ODOO_PASSWORD = os.getenv('ODOO_PASSWORD')
WEBHOOK_VERIFY_TOKEN = os.getenv('WEBHOOK_VERIFY_TOKEN', 'mi_token_secreto')

# Configurar OpenAI
openai.api_key = OPENAI_API_KEY

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
        # Meta envía estos parámetros para verificar el webhook
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
        
        # Verificar estructura del mensaje
        if not is_valid_message(data):
            return jsonify({'status': 'ignored'})
        
        # Procesar mensaje
        process_whatsapp_message(data)
        
        return jsonify({'status': 'success'})
        
    except Exception as e:
        logger.error(f"Error procesando webhook: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def is_valid_message(data):
    """Verificar que el mensaje sea válido"""
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
    """Procesar mensaje de WhatsApp"""
    try:
        entry = data['entry'][0]
        changes = entry['changes'][0]
        value = changes['value']
        
        # Extraer información del mensaje
        if 'messages' in value:
            for message in value['messages']:
                message_info = extract_message_info(message, value)
                if message_info:
                    handle_message(message_info)
                    
    except Exception as e:
        logger.error(f"Error procesando mensaje: {e}")

def extract_message_info(message, value):
    """Extraer información del mensaje"""
    try:
        # Información básica
        phone_number = message.get('from')
        message_id = message.get('id')
        timestamp = message.get('timestamp')
        
        # Contenido del mensaje
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
        
        # Información del contacto
        contact_name = phone_number  # Por defecto
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

def handle_message(message_info):
    """Manejar mensaje completo con logs de depuración detallados"""
    try:
        logger.info(f"[STEP 0] Procesando mensaje de {message_info['name']}: {message_info['text']}")

        # 1. Buscar o crear contacto en Odoo
        partner_id = get_or_create_partner(message_info)
        logger.debug(f"[STEP 1] Partner ID obtenido/creado: {partner_id}")

        # 2. Crear mensaje en Odoo
        message_id = create_odoo_message(message_info, partner_id)
        logger.debug(f"[STEP 2] ID de mensaje creado en Odoo: {message_id}")
        if not message_id:
            logger.error("[STEP 2] No se pudo crear mensaje en Odoo")
            return

        # 3. Verificar si necesita escalamiento
        if needs_escalation(message_info['text']):
            logger.debug("[STEP 3] Mensaje requiere escalamiento")
            escalate_message(message_id, message_info)
            return
        else:
            logger.debug("[STEP 3] Mensaje no requiere escalamiento")

        # 4. Obtener configuración IA de Odoo
        ia_config = get_ia_config()
        if not ia_config:
            logger.info("[STEP 4] Configuración IA no encontrada")
            return
        if not ia_config.get('auto_response'):
            logger.info("[STEP 4] Respuestas automáticas desactivadas")
            return
        logger.debug(f"[STEP 4] Configuración IA cargada: {ia_config}")

        # 5. Obtener conocimiento relevante
        knowledge_context = get_relevant_knowledge(message_info['text'])
        logger.debug(f"[STEP 5] Contexto de conocimiento relevante: {knowledge_context}")

        # 6. Generar respuesta con IA
        ia_response = generate_ia_response(
            message_info['text'],
            ia_config,
            knowledge_context,
            message_info['name']
        )
        if ia_response:
            logger.debug(f"[STEP 6] Respuesta IA generada: {ia_response}")

            # 7. Actualizar mensaje en Odoo
            update_message_with_response(message_id, ia_response)
            logger.debug("[STEP 7] Mensaje actualizado en Odoo con respuesta IA")

            # 8. Crear log en Odoo
            create_ia_log(message_info, ia_response, partner_id)
            logger.debug("[STEP 8] Log de IA creado en Odoo")

            # 9. Enviar respuesta por WhatsApp
            send_whatsapp_message(message_info['phone'], ia_response)
            logger.info(f"[STEP 9] Respuesta enviada a {message_info['name']}")
        else:
            logger.debug("[STEP 6] No se generó respuesta IA")

    except Exception as e:
        logger.error(f"[ERROR] Error manejando mensaje: {e}")
        create_error_log(message_info, str(e))

def get_or_create_partner(message_info):
    """Buscar o crear contacto en Odoo con validación de campos obligatorios"""
    try:
        session = authenticate_odoo()
        if not session or not session.get('uid'):
            logger.error("[DEBUG] Sesión inválida para Odoo")
            return None

        phone = message_info.get('phone')
        name = message_info.get('name', phone)

        # 1. Buscar contacto existente por teléfono
        search_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [
                    ODOO_DB, session['uid'], session['password'],
                    'res.partner', 'search',
                    [['phone', '=', phone]]
                ]
            }
        }
        search_response = requests.post(f"{ODOO_URL}/jsonrpc", json=search_data)
        partner_ids = search_response.json().get('result', [])
        if partner_ids:
            logger.debug(f"[DEBUG] Contacto existente encontrado: {partner_ids[0]}")
            return partner_ids[0]

        # 2. Obtener campos obligatorios del modelo res.partner
        fields_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [
                    ODOO_DB, session['uid'], session['password'],
                    'res.partner', 'fields_get',
                    [],  # todos los campos
                    {'attributes': ['required']}
                ]
            }
        }
        fields_response = requests.post(f"{ODOO_URL}/jsonrpc", json=fields_data)
        fields_result = fields_response.json().get('result', {})
        required_fields = [f for f, v in fields_result.items() if v.get('required')]
        logger.debug(f"[DEBUG] Campos obligatorios de res.partner: {required_fields}")

        # 3. Preparar datos de contacto
        partner_data = {
            'name': name,
            'phone': phone,
            'is_company': False,
            'customer_rank': 1,
            'supplier_rank': 0
        }

        # 4. Validar campos obligatorios
        missing_fields = [f for f in required_fields if f not in partner_data or not partner_data[f]]
        if missing_fields:
            logger.error(f"[DEBUG] Campos obligatorios faltantes al crear contacto: {missing_fields}")
            return None

        create_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [
                    ODOO_DB, session['uid'], session['password'],
                    'res.partner', 'create',
                    partner_data
                ]
            }
        }
        logger.debug(f"[DEBUG] Payload para crear contacto: {json.dumps(create_data, indent=2)}")

        response = requests.post(f"{ODOO_URL}/jsonrpc", json=create_data)
        logger.debug(f"[DEBUG] Response status: {response.status_code}")
        logger.debug(f"[DEBUG] Response content: {response.text}")

        try:
            result = response.json().get('result')
            if result:
                logger.debug(f"[DEBUG] Contacto creado exitosamente: {result}")
            else:
                logger.error("[DEBUG] No se pudo crear el contacto en Odoo. Result es None o vacío.")
            return result
        except Exception as e:
            logger.error(f"[DEBUG] Error parseando JSON de Odoo: {e}")
            return None

    except Exception as e:
        logger.error(f"[ERROR] Excepción buscando/creando contacto: {e}")
        return None


def authenticate_odoo():
    """Autenticarse en Odoo"""
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

from datetime import datetime

REQUIRED_FIELDS = [
    'x_studio_partner_id',
    'x_studio_partner_phone',
    'x_studio_tipo_de_mensaje',
    'x_studio_mensaje_whatsapp',
    'x_studio_date',
    'x_studio_estado'
]

from datetime import datetime

def validate_odoo_payload_generic(model_name, payload):
    """
    Valida un payload de Odoo para cualquier modelo.
    - Verifica campos obligatorios (no None ni vacío)
    - Valida campos de fecha en formato ISO 8601
    """
    errors = []

    try:
        # Extraer el diccionario que se enviará a Odoo
        data = payload.get('params', {}).get('args', [])[4]

        if not data:
            errors.append("Payload vacío")
            return errors

        # Lista de campos obligatorios por modelo (puedes ampliarla según tus modelos)
        required_fields_by_model = {
            'x_ia_tai': [
                'x_studio_partner_id',
                'x_studio_partner_phone',
                'x_studio_tipo_de_mensaje',
                'x_studio_mensaje_whatsapp',
                'x_studio_date',
                'x_studio_estado'
            ],
            'x_logs_ia': [
                'x_cliente',
                'x_telefono',
                'x_mensaje_original',
                'x_respuesta_ia',
                'x_estado'
            ]
            # Agrega más modelos y sus campos obligatorios aquí
        }

        required_fields = required_fields_by_model.get(model_name, [])

        for field in required_fields:
            if field not in data or data[field] in [None, '']:
                errors.append(f"Campo obligatorio faltante o vacío: {field}")

        # Validar fechas en formato ISO 8601
        for key, value in data.items():
            if 'date' in key.lower() and value:
                try:
                    datetime.fromisoformat(value)
                except Exception:
                    errors.append(f"Campo {key} no tiene formato ISO 8601 válido: {value}")

    except Exception as e:
        errors.append(f"Error validando payload: {e}")

    return errors

def create_odoo_message(message_info, partner_id):
    """Crear mensaje en Odoo con validación y logs detallados"""
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
                    'x_ia_tai',
                    'create',
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

        # Validar payload antes de enviar
        validation_errors = validate_odoo_payload(create_data)
        if validation_errors:
            logger.error(f"[ERROR] Payload inválido para Odoo: {validation_errors}")
            return None

        # Log del payload
        logger.info(f"[DEBUG] Payload para Odoo: {json.dumps(create_data, indent=2)}")

        response = requests.post(f"{ODOO_URL}/jsonrpc", json=create_data)
        logger.info(f"[DEBUG] Respuesta de Odoo: status={response.status_code}, body={response.text}")

        try:
            resp_json = response.json()
        except Exception as e:
            logger.error(f"[ERROR] No se pudo parsear JSON de Odoo: {e}")
            return None

        if 'error' in resp_json:
            logger.error(f"[ERROR] Odoo respondió con error: {json.dumps(resp_json['error'], indent=2)}")
            return None

        result = resp_json.get('result')
        if not result:
            logger.error("[ERROR] No se creó el mensaje en Odoo. 'result' es None o vacío.")
        else:
            logger.info(f"[DEBUG] Mensaje creado en Odoo con ID: {result}")

        return result

    except Exception as e:
        logger.error(f"[ERROR] Excepción creando mensaje en Odoo: {e}")
        return None

def get_ia_config():
    """Obtener configuración IA activa de Odoo"""
    try:
        session = authenticate_odoo()
        
        # Buscar configuración activa
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
                    ['x_studio_nombre', 'x_studio_respuestas_automticas', 'x_studio_prompt_del_sistema', 'x_studio_palabras_escalamiento']
                ]
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
        logger.error(f"Error obteniendo configuración IA: {e}")
        return None

def get_relevant_knowledge(message_text):
    """Obtener conocimiento relevante de la base de datos"""
    try:
        session = authenticate_odoo()
        
        # Obtener toda la base de conocimiento activa
        search_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [
                    ODOO_DB, session['uid'], session['password'],
                    'x_base_conocimiento', 'search_read',
                    [['x_active', '=', True]],
                    ['x_titulo', 'x_palabras_clave', 'x_pregunta', 'x_respuesta', 'x_veces_usada']
                ]
            }
        }
        
        response = requests.post(f"{ODOO_URL}/jsonrpc", json=search_data)
        knowledge_items = response.json().get('result', [])
        
        # Buscar conocimiento relevante
        relevant_knowledge = []
        message_lower = message_text.lower()
        
        for item in knowledge_items:
            keywords = item.get('x_palabras_clave', '')
            if keywords:
                keyword_list = [k.strip().lower() for k in keywords.split(',')]
                if any(keyword in message_lower for keyword in keyword_list):
                    relevant_knowledge.append({
                        'id': item['id'],
                        'pregunta': item.get('x_pregunta', ''),
                        'respuesta': item.get('x_respuesta', ''),
                        'titulo': item.get('x_titulo', '')
                    })
                    
                    # Actualizar contador de uso
                    update_knowledge_usage(item['id'], item.get('x_veces_usada', 0) + 1)
        
        # Limitar a 3 elementos más relevantes
        return relevant_knowledge[:3]
        
    except Exception as e:
        logger.error(f"Error obteniendo conocimiento: {e}")
        return []

def update_knowledge_usage(knowledge_id, new_count):
    """Actualizar contador de uso del conocimiento"""
    try:
        session = authenticate_odoo()
        
        update_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [
                    ODOO_DB, session['uid'], session['password'],
                    'x_base_conocimiento', 'write',
                    [knowledge_id],
                    {'x_veces_usada': new_count}
                ]
            }
        }
        
        requests.post(f"{ODOO_URL}/jsonrpc", json=update_data)
        
    except Exception as e:
        logger.error(f"Error actualizando uso: {e}")

def needs_escalation(message_text):
    """Verificar si el mensaje necesita escalamiento"""
    try:
        # Obtener palabras clave de escalamiento
        ia_config = get_ia_config()
        if not ia_config:
            return False
        
        escalation_keywords = ia_config.get('escalation_keywords', '')
        if not escalation_keywords:
            return False
        
        keyword_list = [k.strip().lower() for k in escalation_keywords.split(',')]
        message_lower = message_text.lower()
        
        return any(keyword in message_lower for keyword in keyword_list)
        
    except Exception as e:
        logger.error(f"Error verificando escalamiento: {e}")
        return False

def generate_ia_response(message_text, ia_config, knowledge_context, customer_name):
    """Generar respuesta con IA"""
    try:
        # Configurar OpenAI con la clave de Odoo
        openai.api_key = ia_config.get('api_key')
        
        # Construir contexto de conocimiento
        knowledge_text = ""
        if knowledge_context:
            knowledge_text = "\n\nINFORMACIÓN RELEVANTE:\n"
            for item in knowledge_context:
                knowledge_text += f"- {item['titulo']}: {item['respuesta']}\n"
        
        # Construir prompt completo
        system_prompt = ia_config.get('system_prompt', '')
        if not system_prompt:
            system_prompt = """Eres un asistente de atención al cliente profesional y amable.
            
Instrucciones:
- Responde de manera cordial y profesional
- Si no tienes información específica, ofrece transferir con un agente humano
- Mantén las respuestas concisas (máximo 2 párrafos)
- Usa la información proporcionada para responder
- Siempre ofrece ayuda adicional"""
        
        full_prompt = f"""{system_prompt}
        
{knowledge_text}

CLIENTE: {customer_name}
MENSAJE: {message_text}

Responde de manera profesional y útil:"""
        
        # Llamar a OpenAI
        response = openai.ChatCompletion.create(
            model=ia_config.get('model_name', 'gpt-3.5-turbo'),
            messages=[
                {"role": "user", "content": full_prompt}
            ],
            max_tokens=ia_config.get('max_tokens', 200),
            temperature=ia_config.get('temperature', 0.7)
        )
        
        return response.choices[0].message.content.strip()
        
    except Exception as e:
        logger.error(f"Error generando respuesta IA: {e}")
        return "Disculpa, estoy teniendo problemas técnicos. Un agente te contactará pronto."

def update_message_with_response(message_id, ia_response):
    """Actualizar mensaje con respuesta IA"""
    try:
        session = authenticate_odoo()
        
        update_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [
                    ODOO_DB, session['uid'], session['password'],
                    'x_ia_tai', 'write',
                    [message_id],
                    {
                        'x_studio_procesado_por_ia': True,
                        'x_studio_respuesta_ia': ia_response,
                        'x_studio_estado': 'responded'
                    }
                ]
            }
        }
        
        requests.post(f"{ODOO_URL}/jsonrpc", json=update_data)
        
    except Exception as e:
        logger.error(f"Error actualizando mensaje: {e}")

def create_ia_log(message_info, ia_response, partner_id):
    """Crear log de IA en Odoo"""
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
                    'x_logs_ia', 'create',
                    {
                        'x_cliente': partner_id,
                        'x_telefono': message_info['phone'],
                        'x_mensaje_original': message_info['text'],
                        'x_respuesta_ia': ia_response,
                        'x_estado': 'sent',
                        'x_tiempo_procesamiento': 2.5  # Puedes calcular el tiempo real
                    }
                ]
            }
        }
        
        requests.post(f"{ODOO_URL}/jsonrpc", json=create_data)
        
    except Exception as e:
        logger.error(f"Error creando log: {e}")

def create_error_log(message_info, error_message):
    """Crear log de error"""
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
                    'x_logs_ia', 'create',
                    {
                        'x_telefono': message_info.get('phone', ''),
                        'x_mensaje_original': message_info.get('text', ''),
                        'x_estado': 'error',
                        'x_mensaje_error': error_message
                    }
                ]
            }
        }
        
        requests.post(f"{ODOO_URL}/jsonrpc", json=create_data)
        
    except Exception as e:
        logger.error(f"Error creando log de error: {e}")

def escalate_message(message_id, message_info):
    """Escalar mensaje a atención humana"""
    try:
        session = authenticate_odoo()
        
        # Actualizar mensaje
        update_data = {
            'jsonrpc': '2.0',
            'method': 'call',
            'params': {
                'service': 'object',
                'method': 'execute',
                'args': [
                    ODOO_DB, session['uid'], session['password'],
                    'x_ia_tai', 'write',
                    [message_id],
                    {
                        'x_requiere_humano': True,
                        'x_studio_estado': 'escalated'
                    }
                ]
            }
        }
        
        requests.post(f"{ODOO_URL}/jsonrpc", json=update_data)
        
        # Enviar mensaje automático de escalamiento
        escalation_message = """Gracias por contactarnos. Tu consulta ha sido transferida a uno de nuestros agentes especializados que te responderá a la brevedad.

Para consultas urgentes, puedes llamarnos directamente."""
        
        send_whatsapp_message(message_info['phone'], escalation_message)
        
        logger.info(f"Mensaje escalado: {message_info['text']}")
        
    except Exception as e:
        logger.error(f"Error escalando mensaje: {e}")

def send_whatsapp_message(phone_number, message):
    """Enviar mensaje por WhatsApp Business API"""
    try:
        url = f"https://graph.facebook.com/v18.0/{WHATSAPP_PHONE_NUMBER_ID}/messages"
        
        headers = {
            'Authorization': f'Bearer {WHATSAPP_ACCESS_TOKEN}',
            'Content-Type': 'application/json'
        }
        
        data = {
            'messaging_product': 'whatsapp',
            'to': phone_number,
            'text': {
                'body': message
            }
        }
        
        response = requests.post(url, headers=headers, json=data)
        
        if response.status_code == 200:
            logger.info(f"Mensaje enviado exitosamente a {phone_number}")
        else:
            logger.error(f"Error enviando mensaje: {response.status_code} - {response.text}")
            
    except Exception as e:
        logger.error(f"Error enviando WhatsApp: {e}")

# Endpoint de prueba para verificar que todo funciona
@app.route('/test', methods=['GET'])
def test_endpoint():
    """Endpoint de prueba"""
    try:
        # Probar conexión a Odoo
        session = authenticate_odoo()
        
        # Probar OpenAI (si hay configuración)
        ia_config = get_ia_config()
        
        return jsonify({
            'status': 'success',
            'odoo_connected': bool(session),
            'ia_config_found': bool(ia_config),
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))

    app.run(host='0.0.0.0', port=port, debug=False)















