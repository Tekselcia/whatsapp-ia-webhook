# app.py
from flask import Flask, request, jsonify
import openai
import requests
import json
import logging
from datetime import datetime
import os
import sys

# ---------------------------
# Logging
# ---------------------------
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

# ---------------------------
# Flask app
# ---------------------------
app = Flask(__name__)

# ---------------------------
# Environment / config
# ---------------------------
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
WHATSAPP_ACCESS_TOKEN = os.getenv('WHATSAPP_ACCESS_TOKEN')
WHATSAPP_PHONE_NUMBER_ID = os.getenv('WHATSAPP_PHONE_NUMBER_ID')
ODOO_URL = os.getenv('ODOO_URL')  # e.g. https://miodoo.com
ODOO_DB = os.getenv('ODOO_DB')
ODOO_USER = os.getenv('ODOO_USER')
ODOO_PASSWORD = os.getenv('ODOO_PASSWORD')
WEBHOOK_VERIFY_TOKEN = os.getenv('WEBHOOK_VERIFY_TOKEN', 'mi_token_secreto')

if OPENAI_API_KEY:
    openai.api_key = OPENAI_API_KEY

# ---------------------------
# Helpers: Odoo RPC wrappers
# ---------------------------
def odoo_jsonrpc(payload):
    """Envía payload JSON-RPC a ODOO_URL/jsonrpc y retorna dict."""
    try:
        url = f"{ODOO_URL.rstrip('/')}/jsonrpc"
        resp = requests.post(url, json=payload, timeout=30)
        try:
            return resp.json()
        except Exception as e:
            logger.error(f"Odoo: no se pudo parsear JSON. status={resp.status_code} body={resp.text}")
            return {'error': {'message': 'invalid_json', 'detail': str(e)}}
    except Exception as e:
        logger.exception("Error comunicándose con Odoo")
        return {'error': {'message': 'request_failed', 'detail': str(e)}}

def authenticate_odoo():
    """Autentica y retorna dict {'uid': uid, 'password': ODOO_PASSWORD} o None."""
    try:
        payload = {
            "jsonrpc": "2.0",
            "method": "call",
            "params": {
                "service": "common",
                "method": "authenticate",
                "args": [ODOO_DB, ODOO_USER, ODOO_PASSWORD, {}]
            }
        }
        resp = odoo_jsonrpc(payload)
        uid = resp.get('result')
        if uid:
            return {'uid': uid, 'password': ODOO_PASSWORD}
        logger.error(f"[ODoo] Autenticación fallida: {resp}")
        return None
    except Exception as e:
        logger.exception("authenticate_odoo error")
        return None

def execute_kw(session, model, method, args=None, kwargs=None):
    """Conveniencia para execute_kw."""
    if args is None:
        args = []
    if kwargs is None:
        kwargs = {}
    payload = {
        "jsonrpc": "2.0",
        "method": "call",
        "params": {
            "service": "object",
            "method": "execute_kw",
            "args": [ODOO_DB, session['uid'], session['password'], model, method, args, kwargs]
        }
    }
    return odoo_jsonrpc(payload)

def get_selection_values(session, model, field_name):
    """Devuelve lista de keys válidas para un campo selection (['inbound','outbound',...])"""
    try:
        resp = execute_kw(session, model, 'fields_get', [[field_name], {'attributes': ['selection']}])
        result = resp.get('result', {})
        field_data = result.get(field_name, {})
        selection = field_data.get('selection', [])
        # selection puede venir como list of tuples [(key,label),...]
        keys = [s[0] for s in selection if isinstance(s, (list, tuple)) and len(s) >= 1]
        return keys
    except Exception as e:
        logger.exception("get_selection_values")
        return []

# ---------------------------
# WhatsApp helpers
# ---------------------------
def send_whatsapp_message(phone, message_text):
    """Envía texto por la API de WhatsApp Cloud (Graph API)."""
    if not WHATSAPP_ACCESS_TOKEN or not WHATSAPP_PHONE_NUMBER_ID:
        logger.error("WhatsApp config faltante. No se envía mensaje.")
        return None
    try:
        url = f"https://graph.facebook.com/v17.0/{WHATSAPP_PHONE_NUMBER_ID}/messages"
        headers = {
            "Authorization": f"Bearer {WHATSAPP_ACCESS_TOKEN}",
            "Content-Type": "application/json"
        }
        payload = {
            "messaging_product": "whatsapp",
            "to": phone,
            "type": "text",
            "text": {"body": message_text}
        }
        r = requests.post(url, headers=headers, json=payload, timeout=20)
        if r.status_code not in (200, 201):
            logger.error(f"WhatsApp API error {r.status_code}: {r.text}")
        else:
            logger.info(f"WhatsApp enviado a {phone}")
        return r
    except Exception as e:
        logger.exception("Error enviando WhatsApp")
        return None

# ---------------------------
# Validación recibos (Webhook)
# ---------------------------
@app.route('/webhook', methods=['GET'])
def verify_webhook():
    try:
        mode = request.args.get('hub.mode')
        token = request.args.get('hub.verify_token')
        challenge = request.args.get('hub.challenge')
        logger.info(f"Webhook verify request: mode={mode}")
        if mode == 'subscribe' and token == WEBHOOK_VERIFY_TOKEN:
            return challenge, 200
        return "Forbidden", 403
    except Exception as e:
        logger.exception("verify_webhook")
        return "Error", 500

def is_valid_whatsapp_payload(data):
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
    except Exception:
        logger.exception("is_valid_whatsapp_payload")
        return False

# ---------------------------
# Extracción y procesamiento
# ---------------------------
def extract_message_info(message, value):
    try:
        phone_number = message.get('from')
        message_id = message.get('id')
        timestamp = message.get('timestamp')
        msg_type = message.get('type', 'text')
        text = ''
        if msg_type == 'text':
            text = message.get('text', {}).get('body', '')
        elif msg_type == 'button':
            text = message.get('button', {}).get('text', '')
        elif msg_type == 'interactive':
            it = message.get('interactive', {})
            if 'button_reply' in it:
                text = it['button_reply'].get('title', '')
            elif 'list_reply' in it:
                text = it['list_reply'].get('title', '')
        # contact name if provided by webhook
        contact_name = phone_number
        contacts = value.get('contacts') or []
        for c in contacts:
            if c.get('wa_id') == phone_number:
                contact_name = c.get('profile', {}).get('name', contact_name)
                break
        return {
            'phone': phone_number,
            'name': contact_name,
            'text': text,
            'type': msg_type,
            'message_id': message_id,
            'timestamp': timestamp
        }
    except Exception:
        logger.exception("extract_message_info")
        return None

# ---------------------------
# Odoo helpers: partner & message
# ---------------------------
def get_or_create_partner_by_phone(session, phone, name=None):
    try:
        # search by phone
        r = execute_kw(session, 'res.partner', 'search', [[['phone','=', phone]]])
        partner_ids = r.get('result') if isinstance(r, dict) else None
        # Note: execute_kw returns dict with 'result' key from odoo_jsonrpc wrapper
        if partner_ids and isinstance(partner_ids, list) and len(partner_ids) > 0:
            return partner_ids[0]
        # create
        vals = {'name': name or phone, 'phone': phone, 'is_company': False}
        r2 = execute_kw(session, 'res.partner', 'create', [vals])
        return r2.get('result') if isinstance(r2, dict) else None
    except Exception:
        logger.exception("get_or_create_partner_by_phone")
        return None

def create_message_record(session, partner_id, message_info):
    """
    Crea un registro en el modelo x_ia_tai (u otro) usando execute_kw.
    - Validamos que x_name exista si es requerido.
    - Validamos selection field allowed values.
    """
    try:
        model = 'x_ia_tai'
        # preparar texto/titulo
        message_text = (message_info.get('text') or '').strip() or 'Sin contenido'

        # obtener selección válida para x_studio_tipo_de_mensaje si existe
        tipo_field = 'x_studio_tipo_de_mensaje'
        valid_tipo = None
        selection_keys = get_selection_values(session, model, tipo_field)
        # mapeo deseado: inbound/outbound/etc - buscamos una key que contenga 'in' o 'entrada'
        if selection_keys:
            # prefer 'inbound' if present, else first key
            if 'inbound' in selection_keys:
                valid_tipo = 'inbound'
            else:
                # buscar coincidencia por texto
                for k in selection_keys:
                    if 'in' in k or 'entrada' in k or 'inbound' in k:
                        valid_tipo = k
                        break
                if not valid_tipo:
                    valid_tipo = selection_keys[0]

        vals = {
            'x_name': message_text,
            'x_studio_partner_id': partner_id,
            'x_studio_partner_phone': message_info.get('phone'),
            'x_studio_mensaje_whatsapp': message_text,
            'x_studio_date': datetime.now().replace(microsecond=0).isoformat(),
            'x_studio_estado': 'received'
        }
        if valid_tipo:
            vals['x_studio_tipo_de_mensaje'] = valid_tipo

        # Validate required fields server-side will respond with error if missing.
        r = execute_kw(session, model, 'create', [vals])
        if r.get('error'):
            logger.error(f"Odoo error creating message: {r}")
            return None
        result = r.get('result')
        logger.info(f"Mensaje creado en Odoo ID: {result}")
        return result
    except Exception:
        logger.exception("create_message_record")
        return None

def update_message_state(session, message_id, state='responded'):
    try:
        model = 'x_ia_tai'
        if isinstance(message_id, list):
            ids = message_id
        else:
            ids = [message_id]
        r = execute_kw(session, model, 'write', [ids, {'x_studio_estado': state}])
        if r.get('error'):
            logger.error(f"Odoo error updating message state: {r}")
    except Exception:
        logger.exception("update_message_state")

# ---------------------------
# IA functions
# ---------------------------
def get_ia_config():
    """
    Carga configuración IA desde Odoo.
    Espera que el registro tenga:
      - x_studio_nombre (guardar aquí la API key o dejar vacío y usar env)
      - x_studio_respuestas_automticas (bool)
      - x_studio_prompt_del_sistema (system prompt)
      - x_studio_palabras_escalamiento (csv)
    """
    try:
        session = authenticate_odoo()
        if not session:
            return None
        r = execute_kw(session, 'x_configuracion_ia_tai', 'search_read', [[['x_studio_activo','=', True]], ['x_studio_nombre','x_studio_respuestas_automticas','x_studio_prompt_del_sistema','x_studio_palabras_escalamiento']])
        configs = r.get('result') or []
        if not configs:
            logger.warning("No IA config active found in Odoo")
            return None
        cfg = configs[0]
        api_key = (cfg.get('x_studio_nombre') or '').strip() or OPENAI_API_KEY
        return {
            'api_key': api_key,
            'model_name': 'gpt-3.5-turbo',
            'max_tokens': 300,
            'temperature': 0.7,
            'auto_response': bool(cfg.get('x_studio_respuestas_automticas')),
            'system_prompt': cfg.get('x_studio_prompt_del_sistema') or '',
            'escalation_keywords': cfg.get('x_studio_palabras_escalamiento') or ''
        }
    except Exception:
        logger.exception("get_ia_config")
        return None

def get_relevant_knowledge(message_text):
    try:
        session = authenticate_odoo()
        if not session:
            return []
        r = execute_kw(session, 'x_base_conocimiento', 'search_read', [[['x_active','=', True]], ['x_name','x_studio_palabras_clave','x_studio_pregunta','x_studio_respuesta','x_studio_veces_usada']])
        items = r.get('result') or []
        relevant = []
        lower = (message_text or '').lower()
        for it in items:
            keys = (it.get('x_studio_palabras_clave') or '')
            if keys:
                for k in keys.split(','):
                    if k.strip().lower() and k.strip().lower() in lower:
                        relevant.append({
                            'id': it.get('id'),
                            'titulo': it.get('x_name'),
                            'pregunta': it.get('x_studio_pregunta'),
                            'respuesta': it.get('x_studio_respuesta')
                        })
                        # no actualizar contador aquí para evitar muchos requests
                        break
        return relevant[:3]
    except Exception:
        logger.exception("get_relevant_knowledge")
        return []

def generate_ia_response(message_text, ia_config, knowledge_context, customer_name):
    """Genera la respuesta usando OpenAI (usa api_key de ia_config si está)."""
    try:
        if not ia_config or not ia_config.get('api_key'):
            logger.error("No IA config or API key")
            return None
        openai.api_key = ia_config.get('api_key')
        system_prompt = ia_config.get('system_prompt') or (
            "Eres un asistente de atención al cliente cordial y profesional. Responde conciso."
        )
        knowledge_block = ""
        if knowledge_context:
            knowledge_block = "\n\nINFORMACIÓN RELEVANTE:\n" + "\n".join(f"- {k['titulo']}: {k['respuesta']}" for k in knowledge_context)

        full_prompt = f"{system_prompt}\n\nCLIENTE: {customer_name}\nMENSAJE: {message_text}{knowledge_block}\n\nResponde de forma útil y concisa:"
        logger.info("[IA] Prompt enviado a OpenAI:\n" + full_prompt)
        resp = openai.ChatCompletion.create(
            model=ia_config.get('model_name', 'gpt-3.5-turbo'),
            messages=[{"role":"system","content": system_prompt}, {"role":"user","content": full_prompt}],
            max_tokens=ia_config.get('max_tokens', 300),
            temperature=ia_config.get('temperature', 0.7)
        )
        content = resp.choices[0].message.content.strip()
        logger.info("[IA] Respuesta generada")
        return content
    except Exception:
        logger.exception("generate_ia_response")
        return "Disculpa, en este momento no puedo responder. Un agente humano te contactará."

# ---------------------------
# Escalamiento
# ---------------------------
def create_helpdesk_ticket(session, partner_id, message_info):
    """Crea un ticket en helpdesk.ticket. Usa partner_id si existe."""
    try:
        vals = {
            'name': f"Escalamiento WhatsApp - {message_info.get('phone') or ''}",
            'description': message_info.get('text') or '',
        }
        # si existe partner_id, pasarlo
        if partner_id:
            vals['partner_id'] = partner_id
        # algunos deployments usan team_id, asigna a 1 por defecto si existe
        # puedes comentar la línea siguiente si no aplica en tu Odoo
        # vals['team_id'] = 1
        r = execute_kw(session, 'helpdesk.ticket', 'create', [vals])
        if r.get('error'):
            logger.error(f"No se pudo crear ticket: {r}")
            return None
        ticket_id = r.get('result')
        logger.info(f"Ticket creado en Odoo ID: {ticket_id}")
        return ticket_id
    except Exception:
        logger.exception("create_helpdesk_ticket")
        return None

# ---------------------------
# Main message handler (único) - POST /webhook
# ---------------------------
@app.route('/webhook', methods=['POST'])
def webhook_handler():
    """Endpoint principal para webhook de WhatsApp (Webhook Cloud)."""
    try:
        data = request.get_json(force=True)
        logger.info(f"Webhook recibido: {json.dumps(data)[:1000]}")  # resumen por seguridad

        if not is_valid_whatsapp_payload(data):
            logger.info("Payload ignorado (no es mensaje válido)")
            return jsonify({'status':'ignored'})

        entry = data['entry'][0]
        changes = entry['changes'][0]
        value = changes.get('value', {})
        messages = value.get('messages', [])

        session = authenticate_odoo()
        if not session:
            logger.error("No se pudo autenticar en Odoo")
            return jsonify({'status':'error', 'detail': 'odoo auth failed'}), 500

        for message in messages:
            info = extract_message_info(message, value)
            if not info:
                continue

            logger.info(f"[STEP 0] Procesando mensaje de {info['name']}: {info['text'][:200]}")
            # obtener partner
            partner_id = get_or_create_partner_by_phone(session, info['phone'], info['name'])
            logger.info(f"[STEP 1] Partner ID: {partner_id}")

            # crear registro del mensaje en Odoo (x_ia_tai)
            message_id = create_message_record(session, partner_id, info)
            if not message_id:
                logger.error("[STEP 2] No se pudo crear mensaje en Odoo")
                # crear log de error opcional
                create_error_log(info, "No se pudo crear mensaje en Odoo")
                continue

            # verificar escalamiento según palabras claves de configuración
            ia_config = get_ia_config()
            if not ia_config:
                logger.warning("IA config no encontrada, no se generará respuesta automática")
                # si no hay IA config no seguimos con IA pero dejamos mensaje en Odoo
                continue

            esc_keywords = (ia_config.get('escalation_keywords') or '')
            needs_escal = False
            if esc_keywords:
                for k in esc_keywords.split(','):
                    if k.strip() and k.strip().lower() in (info.get('text') or '').lower():
                        needs_escal = True
                        break

            if needs_escal:
                logger.info("[STEP 3] Mensaje requiere escalamiento")
                # marcar mensaje como escalated en Odoo
                update_message_state(session, message_id, 'escalated')
                # crear ticket helpdesk
                ticket_id = create_helpdesk_ticket(session, partner_id, info)
                if ticket_id:
                    send_whatsapp_message(info['phone'], "📩 Hemos escalado tu mensaje a nuestro equipo. En breve te contactarán.")
                else:
                    send_whatsapp_message(info['phone'], "Hemos recibido tu mensaje. Un agente lo revisará pronto.")
                # log y continuar
                continue

            # obtener conocimiento relevante
            knowledge = get_relevant_knowledge(info.get('text') or '')

            # generar respuesta IA
            ia_resp = generate_ia_response(info.get('text') or '', ia_config, knowledge, info.get('name') or '')
            if ia_resp:
                # actualizar el registro del mensaje con respuesta IA y marcar procesado
                update_message_with_response(session= session, message_id=message_id, ia_response=ia_resp)
                # crear log IA
                try:
                    # create log simplified
                    execute_kw(session, 'x_logs_ia', 'create', [{
                        'x_cliente': partner_id,
                        'x_telefono': info.get('phone'),
                        'x_mensaje_original': info.get('text'),
                        'x_respuesta_ia': ia_resp,
                        'x_estado': 'sent',
                        'x_tiempo_procesamiento': 0.0
                    }])
                except Exception:
                    logger.exception("No se pudo crear log IA")

                # enviar por WhatsApp
                send_whatsapp_message(info.get('phone'), ia_resp)
                logger.info(f"Respuesta enviada a {info.get('phone')}")

        return jsonify({'status':'processed'}), 200

    except Exception as e:
        logger.exception("webhook_handler error")
        return jsonify({'status':'error','detail': str(e)}), 500

# ---------------------------
# Actualización de mensaje (helper)
# ---------------------------
def update_message_with_response(session, message_id, ia_response):
    try:
        model = 'x_ia_tai'
        ids = message_id if isinstance(message_id, list) else [message_id]
        execute_kw(session, model, 'write', [ids, {
            'x_studio_procesado_por_ia': True,
            'x_studio_respuesta_ia': ia_response,
            'x_studio_estado': 'responded'
        }])
        logger.info("[STEP 7] Mensaje actualizado con respuesta IA")
    except Exception:
        logger.exception("update_message_with_response")

# ---------------------------
# Error log creator
# ---------------------------
def create_error_log(message_info, error_message):
    try:
        session = authenticate_odoo()
        if not session:
            logger.error("No autenticación para crear error log")
            return
        execute_kw(session, 'x_logs_ia', 'create', [{
            'x_cliente': message_info.get('phone'),
            'x_telefono': message_info.get('phone'),
            'x_mensaje_original': message_info.get('text'),
            'x_mensaje_error': error_message,
            'x_estado': 'error'
        }])
    except Exception:
        logger.exception("create_error_log")

# ---------------------------
# Run Flask
# ---------------------------
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)






