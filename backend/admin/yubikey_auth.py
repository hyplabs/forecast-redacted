import logging
import os
import re
import json
import secrets
from urllib.parse import urlparse
from datetime import timedelta

from flask import Blueprint, jsonify, render_template, request, session, redirect, url_for
from flask_login import login_user, LoginManager, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import webauthn

RELYING_PARTY_ID = urlparse(os.environ['ADMIN_URL']).netloc.split(':')[0]
RELYING_PARTY_NAME = 'Forecast'
ICON_URL = 'https://forecast.example.com/android-chrome-96x96.png'
ORIGIN = os.environ['ADMIN_URL']
DISABLE_ADMIN_WEBAUTHN = os.environ.get('DISABLE_ADMIN_WEBAUTHN') == 'YES_REALLY_IM_SURE'


logger = logging.getLogger("yubikey_auth")
logger.setLevel(logging.INFO)


class AdminUser(UserMixin):
    def __init__(self, id, username, password_hash, credential_id, public_key):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.credential_id = credential_id
        self.public_key = public_key

    def get_id(self):
        return self.username


logger.info(f"Adding admin users: {os.environ['ADMIN_USERS']}")
ADMIN_USERS = {
    u['username']: AdminUser(u['id'], u['username'], u['password_hash'], u['credential_id'], u['public_key'])
    for u in json.loads(os.environ['ADMIN_USERS'])
}
bp = Blueprint('auth', __name__, url_prefix='/auth')
login_manager = LoginManager()
login_manager.session_protection = "strong"  # require IP and User-Agent to match the IP and User-Agent given at login


@login_manager.user_loader
def load_user(username):
    return ADMIN_USERS.get(username)


@bp.route('/')
def index():
    return render_template('login.html')


@bp.route('/is_disable_admin_webauthn_active')
def is_disable_admin_webauthn_active():
    return jsonify(DISABLE_ADMIN_WEBAUTHN)


@bp.route('/login_start', methods=['POST'])
def login_start():
    username, password = request.json.get('username'), request.json.get('password')
    if username not in ADMIN_USERS:
        logger.info(f"Login start failed: no user with username {username}")
        return jsonify(status='failure', error='User with given username not found')
    user = ADMIN_USERS[username]
    if not isinstance(password, str) or not check_password_hash(user.password_hash, password):
        logger.info(f"Login start failed: incorrect password")
        return jsonify(status='failure', error='Incorrect password')
    logger.info(f"Login started for user {username} with password hash {user.password_hash}: password correct")

    if DISABLE_ADMIN_WEBAUTHN:
        logger.info(f"Login completed for user {username} (DISABLE_ADMIN_WEBAUTHN is enabled)")
        login_user(user, remember=False)
        return jsonify(status='success', options={})

    challenge = secrets.token_urlsafe(32)
    session['challenge'] = challenge
    webauthn_user = webauthn.WebAuthnUser(user_id=user.id, username=user.username, display_name=user.username, icon_url=ICON_URL, credential_id=user.credential_id, public_key=user.public_key, sign_count=0, rp_id=RELYING_PARTY_ID)
    webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(webauthn_user, challenge)
    logger.info(f"Login challenge issued for user {username} with challenge {challenge}")
    return jsonify(status='success', options=webauthn_assertion_options.assertion_dict)


@bp.route('/login', methods=['POST'])
def login():
    challenge = session.get('challenge')
    credential_id = request.json.get('id')
    user_handle = request.json.get('userHandle')
    client_data = request.json.get('clientData')
    auth_data = request.json.get('authData')
    signature = request.json.get('signature')
    assertion_client_extensions = request.json.get('assertionClientExtensions')

    user = next((u for u in ADMIN_USERS.values() if u.credential_id == credential_id), None)
    if user is None:
        logger.info(f"Login start failed: no user with credential ID {credential_id}")
        return jsonify(status='failure', error='User with given credential_id not found')
    logger.info(f"Login submitted for user {user.username} with challenge {challenge}")

    webauthn_user = webauthn.WebAuthnUser(user_id=user.id, username=user.username, display_name=user.username, icon_url=ICON_URL, credential_id=user.credential_id, public_key=user.public_key, sign_count=0, rp_id=RELYING_PARTY_ID)
    webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
        webauthn_user=webauthn_user,
        assertion_response={'id': user.credential_id, 'userHandle': user_handle, 'clientData': client_data, 'authData': auth_data, 'signature': signature, 'assertionClientExtensions': assertion_client_extensions},
        challenge=challenge,
        origin=ORIGIN,
    )
    try:
        webauthn_assertion_response.verify()
    except Exception as e:
        logger.info(f"Login failed: {e}")
        return jsonify(status='failure', error=str(e))

    logger.info(f"Login completed for user {user.username}")
    login_user(user, remember=False)
    return jsonify(status='success')


@bp.route('/register_start', methods=['POST'])
def register_start():
    username, password = request.json.get('username'), request.json.get('password')
    if not isinstance(username, str) or not re.match(r"^[a-zA-Z0-9]{1,32}$", username):
        logger.info(f"Register start failed: invalid username {username}")
        return jsonify(status='failure', error='Invalid username, must be an alphanumeric string')
    if not isinstance(password, str) or len(password) < 8:
        logger.info(f"Register start failed: invalid password")
        return jsonify(status='failure', error='Invalid password, must be at least 8 characters')
    logger.info(f"Register started for user {username}")

    challenge = secrets.token_urlsafe(32)
    user_id = secrets.token_urlsafe(20)

    session['challenge'] = challenge
    session['user_id'] = user_id
    session['username'] = username
    session['password_hash'] = generate_password_hash(password)

    make_credential_options = webauthn.WebAuthnMakeCredentialOptions(
        challenge=challenge,
        rp_name=RELYING_PARTY_NAME,
        rp_id=RELYING_PARTY_ID,
        user_id=user_id,
        username=username,
        display_name=username,
        icon_url=ICON_URL,
    )
    logger.info(f"Register challenge issued for user {username} with challenge {challenge}")
    return jsonify(status='success', options=make_credential_options.registration_dict)


@bp.route('/register', methods=['POST'])
def register():
    challenge = session['challenge']
    user_id = session['user_id']
    username = session['username']
    password_hash = session['password_hash']
    logger.info(f"Register submitted for user {username} with challenge {challenge}")

    client_data, att_obj, registration_client_extensions = request.json.get('clientData'), request.json.get('attObj'), request.json.get('registrationClientExtensions')
    webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
        rp_id=RELYING_PARTY_ID,
        origin=ORIGIN,
        registration_response={'clientData': client_data, 'attObj': att_obj, 'registrationClientExtensions': registration_client_extensions},
        challenge=challenge,
        trusted_attestation_cert_required=True,
    )
    try:
        webauthn_credential = webauthn_registration_response.verify()
    except Exception as e:
        logger.info(f"Register failed: {e}")
        return jsonify(status='failure', error=str(e))

    logger.info(f"Register completed for user {username}")
    user = {
        'id': user_id,
        'username': username,
        'password_hash': password_hash,
        'credential_id': webauthn_credential.credential_id.decode('utf8'),
        'public_key': webauthn_credential.public_key.decode('utf8'),
    }
    return jsonify(status='success', user=user)


def auth_init_app(app):
    app.register_blueprint(bp)
    login_manager.init_app(app)

    @app.before_request
    def require_auth():
        # expire session after 1 hour of inactivity
        session.permanent = True
        app.permanent_session_lifetime = timedelta(hours=1)
        session.modified = True

        if request.endpoint == 'healthcheck':
            return None
        if request.endpoint in ['auth.is_disable_admin_webauthn_active', 'auth.index', 'auth.login_start', 'auth.login', 'auth.register_start', 'auth.register']:
            logger.info(f"Allowing access to whitelisted endpoint {request.endpoint} for {request.path} (IP {request.remote_addr})")
            return None
        if current_user.is_authenticated:
            logger.info(f"Allowing access to {request.path} for logged in user {current_user.username} (IP {request.remote_addr})")
            return None
        logger.info(f"Blocking access to {request.path} for logged out user (IP {request.remote_addr})")
        return redirect(url_for('auth.index', next=request.path))


def auth_get_current_username():
    return current_user.username
