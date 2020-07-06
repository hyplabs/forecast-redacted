from typing import Iterable, Set, List, Dict
import os
import logging
from datetime import datetime, timedelta, timezone, date
from dateutil import parser
from functools import wraps
from collections import defaultdict
import time
import re
import html
from flask import jsonify, request, current_app
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import (
    login_user, logout_user, login_required,
    fresh_login_required, current_user,
    LoginManager
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, join_room, leave_room
from twilio.rest import Client
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from enum import Enum
import phonenumbers

from models import (
    app, db, PhoneNumber, User,
    BetType, BetResult, Bet, TransactionType, TransactionStatus,
    Transaction, Exchange, Round, RoundStatus, Ticket, 
    Announcement, BalanceChangeRecord, RoundResult, RoundLotTypeStatus,
    UserRole, BalanceChangeType, UserPromotion
)
import caching
from util import generate_otp_hash, check_otp_hash, generate_otp, generate_verification_code, generate_uuid, generate_secondary_password


# NOTE: we must always lock rows in this order: User, Exchange, Round, Transaction/Bet, because this is the order that the price updater does it in


logging.basicConfig(level=logging.WARN)
logger = logging.getLogger("server")
logger.setLevel(logging.INFO)

TWILIO_ACCOUNT_SID = os.environ['TWILIO_ACCOUNT_SID']
TWILIO_AUTH_TOKEN = os.environ['TWILIO_AUTH_TOKEN']
TWILIO_FROM_PHONE_NUMBER = os.environ['TWILIO_FROM_PHONE_NUMBER']
SENDGRID_FROM_EMAIL = os.environ['SENDGRID_FROM_EMAIL']
SENDGRID_API_KEY = os.environ['SENDGRID_API_KEY']
FRONTEND_URL = os.environ['FRONTEND_URL']
REDIS_URL = os.environ['REDIS_URL']

PHONE_NUMBER_COUNTRY = "KR"
KRW_PER_LOT = 100000     # Won per lot
BET_CUT_PERCENT = 0.1    # each bet has an additional fee of 10% of bet amount
ROUND_UPDATE_PERIOD = 2  # seconds between Socket.IO round updates
MIN_PASSWORD_LENGTH = 6
BALANCE_CHANGE_RECORDS_HISTORY_LENGTH = 20  # show the last 20 balance change records
MINIMUM_BET_AMOUNT = 5000  # 5k KRW
MAXIMUM_AMOUNT_BET_PER_ROUND_PER_USER = 5000000  # each user can bet maximum 5 mil per round
DAILY_WITHDRAWAL_LIMIT = 10000000
FREE_WITHDRAWALS_PER_30_DAYS = 10
WITHDRAWAL_FEE = 1000
COMPANY_CUT = 0.78
SMS_VERIFICATION_MESSAGE = 'ZZZZ Forecast SMS ZZZ {}ZZZ. 5Z ZZ ZZZZZZ.'
EMAIL_VERIFICATION_SUBJECT = 'ForecastZ ZZ ZZ ZZZZZ. ZZZZ ZZZZZZ.'
EMAIL_VERIFICATION_CONTENT = '''
<p>ForecastZ ZZZZZZ ZZZZZ. ZZZZZZZ. {} Z ZZZZ ZZZZ ZZZZZZZ.</p>
'''
SECONDARY_PASSWORD_MESSAGE = 'ZZZZ Forecast 2Z ZZZZZ {}ZZZ. 2Z ZZZZZ ZZ ZZZ Z ZZZZZ.'
FORGOT_PASSWORD_SUBJECT = 'Forecast ZZZZZ ZZ ZZZZZZ.'
FORGOT_PASSWORD_CONTENT = '''
<p>{} ZZ Forecast  ZZZZZ ZZ ZZZZZZ. ZZ ZZZ 5ZZ ZZZZZ.</p>
'''
FORGOT_USERNAME_SUBJECT = 'Forecast ZZZ'
FORGOT_USERNAME_CONTENT = '''
<p>ZZZZ Forecast ZZZZ {} ZZZ.</p>
'''

twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
sendgrid_client = SendGridAPIClient(SENDGRID_API_KEY)

# Flask-Limiter config
limiter = Limiter(
    app,
    key_func=lambda: current_user.username if not current_user.is_anonymous else get_remote_address,
    default_limits=['3000 per day', '3000 per hour'],
    storage_uri=REDIS_URL,
    storage_options={'skip_full_coverage_check': True} if os.environ.get('REDIS_URL', '').startswith('redis+cluster://') else {},
)


# Flask-Login config
app.config['SECRET_KEY'] = os.environ['FLASK_SECRET_KEY']
login_manager = LoginManager()
login_manager.session_protection = "strong"  # require IP and User-Agent to match the IP and User-Agent given at login
login_manager.init_app(app)


# Flask-SocketIO config
socketio = SocketIO(app, cors_allowed_origins=FRONTEND_URL)
CONNECTED_SOCKETIO_CLIENTS = 0


@socketio.on('connect')
def on_connect():
    global CONNECTED_SOCKETIO_CLIENTS
    CONNECTED_SOCKETIO_CLIENTS += 1
    if current_user is not None and current_user.is_authenticated:
        join_room(f'user_{current_user.id}')
        logger.info(f'User {current_user.username} joined room user_{current_user.id}')


@socketio.on('disconnect')
def on_disconnect():
    global CONNECTED_SOCKETIO_CLIENTS
    CONNECTED_SOCKETIO_CLIENTS -= 1
    if current_user is not None and current_user.is_authenticated:
        leave_room(f'user_{current_user.id}')
        logger.info(f'User {current_user.username} left room user_{current_user.id}')


@login_manager.user_loader
def load_user(key):
    if key.count('|') != 1:
        return None
    user_id, user_uuid = key.split('|')
    user_id = int(user_id)

    # check cache for user entry
    user_or_none = caching.get_user(user_id)
    if user_or_none is not None:
        return user_or_none if user_uuid == user_or_none.uuid else None

    # not in cache, check database
    user_or_none = User.query.filter_by(id=user_id, uuid=user_uuid).first()
    if user_or_none is not None:
        caching.set_user(user_or_none)  # user is valid, because the browser passed a valid authenticated ID and UUID
    return user_or_none


@login_manager.unauthorized_handler
def unauthorized():
    return jsonify(status='failure', error='Unauthorized - please log in using /api/login first')


def partner_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user is None or not current_user.is_authenticated or not current_user.is_partner:
            return current_app.login_manager.unauthorized()
        return f(*args, **kwargs)
    return decorated_function


def hq_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user is None or not current_user.is_authenticated or not current_user.role == UserRole.HQ:
            return current_app.login_manager.unauthorized()
        return f(*args, **kwargs)
    return decorated_function


class QueryType(Enum):
    IDNAME = "idname"  # match on user.username or user.name
    FBNAME = "fbname"  # match on franchise or branch partner_name
    PHONE = "phone"    # match on user.phone.phone


def get_query_filtered_user_ids(type, query):
    if (type == QueryType.IDNAME.value and query is not None):
        user_ids = db.session.query(User.id).filter((User.name == query) | (User.username == query)).subquery()
    elif (type == QueryType.FBNAME.value and query is not None):
        ReferringUser = db.aliased(User)
        ReferringUser2 = db.aliased(User)
        ReferringUser3 = db.aliased(User)
        user_ids = (
            db.session.query(User.id)
            .outerjoin(ReferringUser, User.referring_user_id == ReferringUser.id)
            .outerjoin(ReferringUser2, ReferringUser.referring_user_id == ReferringUser2.id)
            .outerjoin(ReferringUser3, ReferringUser2.referring_user_id == ReferringUser3.id)
            .filter((User.partner_name == query) | (ReferringUser.partner_name == query) | (ReferringUser2.partner_name == query) | (ReferringUser3.partner_name == query))
            .subquery()
        )
    elif type == QueryType.PHONE.value and query is not None:
        phone_ids = db.session.query(PhoneNumber.id).filter(PhoneNumber.phone == query).subquery()
        user_ids = db.session.query(User.id).filter(User.phone_id.in_(phone_ids)).subquery()
    else:
        user_ids = None
    return user_ids


def get_descendant_user_ids(users: Iterable[User]) -> Set[int]:
    result = set()
    current_level_ids = [u.id for u in users]
    while current_level_ids:
        current_level_ids = [id for id, in db.session.query(User.id).filter(User.referring_user_id.in_(current_level_ids)).all()]
        result.update(current_level_ids)
    return result


def get_user_and_descendant_user_ids(user: User) -> Set[int]:
    return get_descendant_user_ids([user]) | {user.id}


def get_partners_in_subtree(user: User) -> List[User]:
    if user.role == UserRole.HQ:
        sole_distributors = User.query.filter(User.referring_user_id == user.id).all()
        branches = User.query.filter(User.referring_user_id.in_([u.id for u in sole_distributors])).all()
        franchisees = User.query.filter(User.referring_user_id.in_([u.id for u in branches])).all()
        return franchisees + branches + sole_distributors + [user]
    if user.role == UserRole.SOLE_DISTRIBUTOR:
        branches = User.query.filter(User.referring_user_id == user.id).all()
        franchisees = User.query.filter(User.referring_user_id.in_([u.id for u in branches])).all()
        return franchisees + branches + [user]
    if user.role == UserRole.PARTNER:
        franchisees = User.query.filter(User.referring_user_id == user.id).all()
        return franchisees + [user]
    if user.role == UserRole.FRANCHISEE:
        return [user]
    assert False, user


last_broadcast_time = time.time()


@app.route('/api/healthcheck')
@limiter.exempt
def healthcheck():
    assert time.time() - last_broadcast_time < 30, "Background loop hasn't updated in 30 seconds!"
    return jsonify(status='success')


@app.route('/api/ping')  # used for rate limiting testing
@limiter.limit("75 per hour", key_func=lambda: current_user.username if not current_user.is_anonymous else get_remote_address)
def ping():
    return jsonify(status='success')


@app.route('/api/send_sms_verification', methods=['POST'])
@limiter.limit("5 per minute", key_func=lambda: re.sub(r"\D", '', request.json.get('phone', '')))
def send_sms_verification():
    try:
        phone_data = phonenumbers.parse(request.json.get('phone'), PHONE_NUMBER_COUNTRY)
    except Exception:
        return jsonify(status='failure', error="Invalid phone number")
    phone = phonenumbers.format_number(phone_data, phonenumbers.PhoneNumberFormat.E164)

    phone_number = PhoneNumber.query.filter_by(phone=phone).first()
    if phone_number is None:
        phone_number = PhoneNumber(phone=phone, verified=False)

    # send out SMS confirmation
    otp = generate_otp()
    message = twilio_client.messages.create(
        body=SMS_VERIFICATION_MESSAGE.format(otp),
        from_=TWILIO_FROM_PHONE_NUMBER,
        to=phone,
    )
    logger.info(f'Sent verification SMS for {phone} with status {message.status}')
    if message.status == 'undelivered' or message.status == 'failed':
        logger.error(f'Failed to send verification SMS for {phone}: {message.status}')
        return jsonify(status='failure', error="SMS send failed")

    phone_number.confirm_otp_hash = generate_otp_hash(otp)
    phone_number.confirm_otp_hash_expiry = datetime.utcnow() + timedelta(minutes=5)
    db.session.add(phone_number)
    db.session.commit()
    return jsonify(status='success')


@app.route('/api/verify_phone', methods=['POST'])
@limiter.limit("20 per minute", key_func=lambda: re.sub(r"\D", '', request.json.get('phone', '')))
def verify_phone():
    try:
        phone_data = phonenumbers.parse(request.json.get('phone'), PHONE_NUMBER_COUNTRY)
    except Exception:
        return jsonify(status='failure', error="Invalid phone number")
    phone = phonenumbers.format_number(phone_data, phonenumbers.PhoneNumberFormat.E164)
    otp = request.json.get('otp')
    phone_number = PhoneNumber.query.filter_by(phone=phone).first()
    if phone_number is None:
        logger.error(f'Could not verify phone number {phone}, has not been encountered')
        return jsonify(status='success')
    if phone_number.verified:
        return jsonify(status='success')
    if phone_number.confirm_otp_hash is None or datetime.utcnow() > phone_number.confirm_otp_hash_expiry:
        logger.error(f'Phone number {phone} does not have an active verification code')
        return jsonify(status='failure', error='No active verification code')
    if not check_otp_hash(phone_number.confirm_otp_hash, otp):
        return jsonify(status='failure', error='Incorrect verification code')
    phone_number.verified = True
    phone_number.confirm_otp_hash = None
    phone_number.confirm_otp_hash_expiry = None
    db.session.add(phone_number)
    db.session.commit()
    return jsonify(status='success')


@app.route('/api/register/check', methods=['POST'])
def check_username_available():
    username = request.json.get('username')
    if User.query.filter_by(username=username).first() is not None:
        return jsonify(status='failure', error='User with provided username already exists')
    return jsonify(status='success')


@app.route('/api/register/check-referral-code', methods=['POST'])
def check_partner_referral_code_exists():
    referral_code = request.json.get('referral_code')
    if db.session.query(User.id).filter_by(partner_referral_code=referral_code).scalar() is not None:
        return jsonify(status='success')
    return jsonify(status='failure', error='ZZZ ZZZZZZZ.')


@app.route('/api/register/get_referral_codes', methods=['POST'])
def get_referral_codes():
    referral_query = db.session.query(
        User.partner_name,
        User.partner_referral_code
    ).filter(
        User.is_suspended == False,
        User.partner_referral_code != None
    ).all()
    referral_codes = [
        {
            "name": name,
            "referral_code": referral_code
        } for name, referral_code in referral_query
    ]
    return jsonify(status="success", referral_codes=referral_codes)


def send_email_verification(email, verification_code):
    # send out email confirmation
    response = sendgrid_client.send(Mail(
        from_email=SENDGRID_FROM_EMAIL,
        to_emails=email,
        subject=EMAIL_VERIFICATION_SUBJECT,
        html_content=EMAIL_VERIFICATION_CONTENT.format(f"{FRONTEND_URL}/verify_email/{verification_code}")
    ))
    logger.info(f'Sent verification email with code {verification_code} to {email} with status {response.status_code}')
    if response.status_code != 202:
        logger.error(f'Failed to send verification email to {email}: {response.status_code} {response.body}')
        return False
    return True


def send_forgot_password_email(email, reset_code):
    # send out email confirmation
    response = sendgrid_client.send(Mail(
        from_email=SENDGRID_FROM_EMAIL,
        to_emails=email,
        subject=FORGOT_PASSWORD_SUBJECT,
        html_content=FORGOT_PASSWORD_CONTENT.format(f"{FRONTEND_URL}/reset_password/{reset_code}")
    ))
    logger.info(f'Sending forgot password email to {email} with status {response.status_code}')
    if response.status_code != 202:
        logger.error(f'Failed to send forgot password email to {email}: {response.status_code} {response.body}')
        return False
    return True


def send_forgot_username_email(email, username):
    # send out email confirmation
    response = sendgrid_client.send(Mail(
        from_email=SENDGRID_FROM_EMAIL,
        to_emails=email,
        subject=FORGOT_USERNAME_SUBJECT,
        html_content=FORGOT_USERNAME_CONTENT.format(username)
    ))
    logger.info(f'Sending forgot username email to {email} with status {response.status_code}')
    if response.status_code != 202:
        logger.error(f'Failed to send forgot username email to {email}: {response.status_code} {response.body}')
        return False
    return True


@app.route('/api/register', methods=['POST'])
def register():
    email, username, name, dob, password = request.json.get('email'), request.json.get('username'), request.json.get('name'), request.json.get('dob'), request.json.get('password')
    bank_name, bank_account_number, bank_account_holder, referral_code = request.json.get('bank_name'), request.json.get('bank_account_number'), request.json.get('bank_account_holder'), request.json.get('referral_code')
    agree_receive_email, agree_receive_text = request.json.get('agree_receive_email'), request.json.get('agree_receive_text')
    try:
        phone_data = phonenumbers.parse(request.json.get('phone'), PHONE_NUMBER_COUNTRY)
    except Exception:
        return jsonify(status='failure', error="Invalid phone number")
    phone = phonenumbers.format_number(phone_data, phonenumbers.PhoneNumberFormat.E164)

    # validate inputs
    if not isinstance(email, str) or '@' not in email:
        return jsonify(status='failure', error=f'ZZZZ ZZ ZZZZZZ: {repr(email)}')
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        return jsonify(status='failure', error=f'ZZZZZ ZZZ ZZZ ZZZZ ZZZZ.')
    if not isinstance(username, str) or not re.match(r"^\w+$", username):
        return jsonify(status='failure', error=f'ZZZZ ZZ ZZZZZZ: {repr(username)}')
    if not isinstance(bank_name, str) or not bank_name:
        return jsonify(status='failure', error=f'ZZZZ ZZ ZZ ZZZZZ: {repr(bank_name)}')
    if not isinstance(bank_account_number, str) or not bank_account_number:
        return jsonify(status='failure', error=f'ZZZ ZZ ZZZZZZZ: {repr(bank_account_number)}')
    if not isinstance(referral_code, str) or not referral_code:
        return jsonify(status='failure', error=f'ZZZZ ZZ ZZ ZZZ: {repr(referral_code)}')

    phone_number = PhoneNumber.query.filter_by(phone=phone).first()
    if phone_number is None or not phone_number.verified:
        return jsonify(status='failure', error=f'ZZZZ ZZ ZZZZ ZZZZZ: {phone}')

    # get referring user
    referral_promotion = None
    referring_user = User.query.filter_by(partner_referral_code=referral_code).filter(User.role == UserRole.FRANCHISEE).first()
    if not referring_user or referring_user.is_suspended:
        return jsonify(status='failure', error=f'ZZZZ ZZ ZZZZZ.')
    if referring_user is not None and referring_user.owned_promotion is not None:
        referral_promotion = referring_user.owned_promotion

    # check if user already exists
    if User.query.filter_by(email=email).first() is not None:
        return jsonify(status='failure', error='ZZ ZZZ ZZZZZZ.')
    if User.query.filter_by(username=username).first() is not None:
        return jsonify(status='failure', error='ZZ ZZZ ZZZZZZ.')
    if User.query.filter_by(phone_id=phone_number.id).first() is not None:
        return jsonify(status='failure', error='ZZ ZZZ ZZZZZZ.')

    # send out secondary password
    secondary_password = generate_secondary_password()
    message = twilio_client.messages.create(
        body=SECONDARY_PASSWORD_MESSAGE.format(secondary_password),
        from_=TWILIO_FROM_PHONE_NUMBER,
        to=phone,
    )
    logger.info(f'Sent secondary password for {phone} with status {message.status}')
    if message.status == 'undelivered' or message.status == 'failed':
        logger.error(f'Failed to send secondary password for {phone}: {message.status}')
        return jsonify(status='failure', error="2Z ZZZZ ZZ ZZ.")

    # send out email confirmation
    verification_code = generate_verification_code()
    if not send_email_verification(email, verification_code):
        return jsonify(status='failure', error='ZZ ZZZ ZZ ZZ.')

    user = User(
        uuid=generate_uuid(),
        email=email,
        email_confirmed=False,
        username=username,
        name=name,
        dob=dob,
        password_hash=generate_password_hash(password),
        secondary_password_hash=generate_password_hash(secondary_password),
        is_suspended=False,
        phone_id=phone_number.id,
        bank_name=bank_name,
        bank_account_number=bank_account_number,
        bank_account_holder=bank_account_holder,
        balance=0,
        pending_commissions=0,
        payable_commissions=0,
        verification_code=verification_code,
        agree_receive_email=agree_receive_email,
        agree_receive_text=agree_receive_text,
        role=referring_user.get_subordinate_role(),
        referring_user_id=referring_user.id
    )
    db.session.add(user)
    db.session.flush()
    user.assert_hierarchy()

    if referral_promotion is not None:
        user_promotion = UserPromotion(
            user_id=user.id,
            promotion_id=referral_promotion.id
        )
        db.session.add(user_promotion)

    db.session.commit()
    caching.set_user(user)  # caching takes place after commit, since we want the cache entry to be created only if the DB transaction succeeds
    login_user(user, remember=True)
    return jsonify(status='success', user=user.to_json())


@app.route('/api/verify_email/<verification_code>')
def verify_email(verification_code):
    user = User.query.filter_by(verification_code=verification_code).first()
    if user is None:
        logger.error(f'A user with verification code {verification_code} does not exist')
        return jsonify(status='failure', error='Invalid verification code')
    user.email_confirmed = True
    user.verification_code = None
    db.session.add(user)
    db.session.commit()
    caching.set_user(user)  # caching takes place after commit, because we don't want to have the cache entry unless the transaction succeeded
    logger.info(f'Email verification successful for {user}')
    return jsonify(status='success')


@app.route('/api/resend_verification_email', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def resend_verification_email():
    user = User.query.get(current_user.id)
    if user.email_confirmed:
        return jsonify(status='failure', message='Email is already verified')
    verification_code = generate_verification_code()
    send_email_verification(user.email, verification_code)
    user.verification_code = verification_code
    db.session.add(user)
    db.session.commit()
    caching.set_user(user)  # caching takes place after commit, because we don't want to have the cache entry unless the transaction succeeded
    return jsonify(status='success')


@app.route('/api/login', methods=['POST'])
def login():
    username, password, secondary_password = request.json.get('username'), request.json.get('password'), request.json.get('secondary_password'),
    user = User.query.filter_by(username=username, is_suspended=False).first()
    if user is None or password is None or secondary_password is None:
        return jsonify(status='success', user=None)
    if not (check_password_hash(user.password_hash, password) and check_password_hash(user.secondary_password_hash, secondary_password)):
        return jsonify(status='success', user=None)
    login_user(user, remember=True)
    return jsonify(status='success', user=user.to_json())


@app.route('/api/login/forgot', methods=['POST'])
@limiter.limit("2 per hour", key_func=lambda: request.json.get('email', ''))
def forgot_password():
    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()
    if user is None:
        logger.error(f'A user with email {email} does not exist')
        return jsonify(status='success')  # frontend should display generic message "if a user exists, otp sent"

    if not user.email_confirmed:
        return jsonify(status='failure', error='ZZZZ ZZZZ ZZZZZ.')

    reset_code = generate_verification_code()
    if not send_forgot_password_email(email, reset_code):
        return jsonify(status='failure', error='ZZZZ ZZZZ ZZZ ZZ ZZ.')

    user.reset_code = reset_code
    user.reset_code_expiry = datetime.utcnow() + timedelta(minutes=5)
    db.session.add(user)
    db.session.commit()
    caching.set_user(user)  # caching takes place after commit, because we don't want to have the cache entry unless the transaction succeeded
    return jsonify(status='success')


@app.route('/api/login/forgot_username', methods=['POST'])
@limiter.limit("2 per hour", key_func=lambda: request.json.get('email', ''))
def forgot_username():
    email = request.json.get('email')
    user = User.query.filter_by(email=email).first()
    if user is None:
        logger.error(f'A user with email {email} does not exist')
        return jsonify(status='success')  # frontend should display generic message "if a user exists, otp sent"

    if not user.email_confirmed:
        return jsonify(status='failure', error='ZZZZ ZZZZ ZZZZZ.')

    if not send_forgot_username_email(email, user.username):
        return jsonify(status='failure', error='ZZ ZZZ ZZZ ZZ ZZ.')
    return jsonify(status='success')


@app.route('/api/reset_password', methods=['POST'])
def reset_password():
    reset_code, new_password = request.json.get('reset_code'), request.json.get('new_password')
    user = User.query.filter_by(reset_code=reset_code).first()
    if reset_code is None or user is None:
        logger.error('A user with reset code {} does not exists'.format(reset_code))
        return jsonify(status='failure', error='ZZZZ ZZ ZZ ZZZ ZZ ZZ.')
    if datetime.utcnow() > user.reset_code_expiry:
        logger.error('Reset code {} has expired'.format(reset_code))
        return jsonify(status='failure', error='ZZ ZZZ ZZ ZZ.')
    user.uuid = generate_uuid()  # reset user UUID, which causes user to need to login again since Flask-Login won't recognize this new UUID anymore
    user.password_hash = generate_password_hash(new_password)
    user.reset_code = None
    user.reset_code_expiry = None
    caching.delete_user(user.id)  # caching takes place before commit, since we don't want this transaction to succeed until the cache entry is deleted
    db.session.add(user)
    db.session.commit()
    logger.info(f'Reset password for user {user.id}.')
    return jsonify(status='success')


@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    user = User.query.get(current_user.id)
    user.uuid = generate_uuid()  # reset user UUID, which causes user to need to login again since Flask-Login won't recognize this new UUID anymore
    caching.delete_user(user.id)  # caching takes place before commit, since we don't want this transaction to succeed until the cache entry is deleted
    db.session.add(user)
    db.session.commit()
    logout_user()
    return jsonify(status='success')


@app.route('/api/me')
@login_required
def serve_current_user():
    user = User.query.get(current_user.id)
    return jsonify(status='success', user=user.to_json())


@app.route('/api/me', methods=['PATCH'])
@fresh_login_required  # require fresh login since this endpoint could change sensitive info like password
@limiter.limit("5 per minute")
def edit_profile():
    email = request.json.get('email')
    new_password = request.json.get('new_password')
    new_secondary_password = request.json.get('new_secondary_password')
    user = User.query.get(current_user.id)
    if new_password:
        if not user.email_confirmed:
            return jsonify(status='failure', error='ZZZZ ZZZZ ZZZZZ.')
        user.password_hash = generate_password_hash(new_password)
    if new_secondary_password: 
        if not user.email_confirmed:
            return jsonify(status='failure', error='ZZZZ ZZZZ ZZZZZ.')
        user.secondary_password_hash = generate_password_hash(new_secondary_password)
    if email != user.email:
        if not isinstance(email, str) or '@' not in email:
            return jsonify(status='failure', error=f'Invalid email: {repr(email)}')
        verification_code = generate_verification_code()
        send_email_verification(email, verification_code)
        user.email = email
        user.email_confirmed = False
        user.verification_code = verification_code
    db.session.add(user)
    db.session.commit()
    caching.set_user(user)  # caching takes place after commit, because we don't want to have the cache entry unless the transaction succeeded
    logger.info(f'Edited profile for user {user.id}.')
    return jsonify(status='success', user=user.to_json())


@app.route('/api/me/transactions')
@login_required
def list_my_transactions():
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.created_at.desc()).all()
    return jsonify(status='success', transactions=[transaction.to_json() for transaction in transactions])


@app.route('/api/me/transactions/deposits', methods=['POST'])
@login_required
def create_new_deposit():
    if not current_user.email_confirmed:
        return jsonify(status='failure', error='ZZZZ ZZZZ ZZZZZ.')
    amount = request.json.get('amount')
    transaction = Transaction(
        user_id=current_user.id,
        transaction_type=TransactionType.DEPOSIT,
        amount=amount,
        status=TransactionStatus.PENDING,
        notes='',
    )
    db.session.add(transaction)
    db.session.commit()
    logger.info(f'Added new {TransactionType.DEPOSIT} for {current_user.id} for amount: {amount}.')
    return jsonify(status='success', transaction=transaction.to_json())


@app.route('/api/me/transactions/withdrawals', methods=['POST'])
@login_required
def create_new_withdrawal():
    amount, otp = request.json.get('amount'), request.json.get('otp')
    if type(amount) not in (float, int) or amount <= 0:
        return jsonify(status='failure', error='ZZ ZZZ ZZZZ ZZZZ.')

    user = User.query.get(current_user.id)
    if not user.email_confirmed:
        return jsonify(status='failure', error='ZZZZ ZZZZ ZZZZZ.')

    withdrawals_today = db.session.query(db.func.sum(Transaction.amount)).filter(
        db.func.date(Transaction.created_at) == date.today(),
        Transaction.transaction_type == TransactionType.WITHDRAWAL,
        (Transaction.status == TransactionStatus.PENDING) | (Transaction.status == TransactionStatus.COMPLETE),
        Transaction.user_id == user.id
    ).scalar() or 0
    num_withdrawals_last_30_days = Transaction.query.filter(
        db.func.date(Transaction.created_at) <= date.today(),
        db.func.date(Transaction.created_at) >= date.today() - timedelta(days=30),
        Transaction.transaction_type == TransactionType.WITHDRAWAL,
        db.or_(Transaction.status == TransactionStatus.PENDING, Transaction.status == TransactionStatus.COMPLETE),
        Transaction.user_id == user.id
    ).count()
    outstanding_withdrawals = db.session.query(db.func.sum(Transaction.amount)).filter_by(transaction_type=TransactionType.WITHDRAWAL, status=TransactionStatus.PENDING, user_id=user.id).scalar() or 0
    if outstanding_withdrawals + amount > user.balance:
        return jsonify(status='failure', error='ZZZ ZZZZ ZZ ZZZZZ.')
    if withdrawals_today + amount > DAILY_WITHDRAWAL_LIMIT:
        return jsonify(status='failure', error='ZZ ZZZZ ZZ.')

    fee = WITHDRAWAL_FEE if num_withdrawals_last_30_days >= FREE_WITHDRAWALS_PER_30_DAYS else 0
    if amount + fee > user.balance:
        return jsonify(status='failure', error='ZZZ ZZZ ZZZZ.')

    if user.phone.confirm_otp_hash is None or datetime.utcnow() > user.phone.confirm_otp_hash_expiry:
        logger.error(f'Phone number {user.phone} does not have an active verification code')
        return jsonify(status='failure', error='ZZZZ ZZ ZZZ ZZZZ.')
    if not check_otp_hash(user.phone.confirm_otp_hash, otp):
        return jsonify(status='failure', error='ZZZZ ZZ ZZ ZZZZZ.')

    user.phone.confirm_otp_hash = None
    user.phone.confirm_otp_hash_expiry = None
    transaction = Transaction(
        user_id=user.id,
        transaction_type=TransactionType.WITHDRAWAL,
        amount=amount,
        status=TransactionStatus.PENDING,
        notes='',
        fee=fee,
    )
    db.session.add(transaction)
    db.session.flush()

    # look through all active promotions that aren't redeemed - if there are any, disallow this withdrawal
    for user_promotion in UserPromotion.query.filter_by(user_id=user.id, promotion_redeemed=False, promotion_activated=True):
        if not user_promotion.check_if_redeemable(transaction):
            logger.warning(f"User promotion {user_promotion} not currently redeemable, disallowing withdrawal")
            return jsonify(status='failure', error='ZZZZ ZZZ ZZZZ ZZZZ.')
        else:
            logger.info(f"Redeeming user promotion {user_promotion} for user {user.username}")
            user_promotion.promotion_redeemed = True
            db.session.add(user_promotion)

    db.session.commit()
    logger.info(f'Added new {TransactionType.WITHDRAWAL} for {user.id} for amount: {amount}.')

    return jsonify(status='success', transaction=transaction.to_json())


@app.route('/api/me/transactions/info')
@login_required
def get_transactions_info():
    withdrawals_today = Transaction.query.filter(
        db.func.date(Transaction.created_at) == date.today(),
        Transaction.transaction_type == TransactionType.WITHDRAWAL,
        db.or_(Transaction.status == TransactionStatus.PENDING, Transaction.status == TransactionStatus.COMPLETE),
        Transaction.user_id == current_user.id
    ).all()    
    num_withdrawals_last_30_days = Transaction.query.filter(
        db.func.date(Transaction.created_at) <= date.today(),
        db.func.date(Transaction.created_at) >= date.today() - timedelta(days=30),
        Transaction.transaction_type == TransactionType.WITHDRAWAL,
        db.or_(Transaction.status == TransactionStatus.PENDING, Transaction.status == TransactionStatus.COMPLETE),
        Transaction.user_id == current_user.id
    ).count()
    all_deposits = Transaction.query.filter_by(
        user_id=current_user.id,
        transaction_type=TransactionType.DEPOSIT,
        status=TransactionStatus.COMPLETE,
    ).all()
    total_deposited = 0
    for t in all_deposits:
        total_deposited += t.amount
    return jsonify(
        status='success',
        daily_withdrawal_limit_left=max(0, DAILY_WITHDRAWAL_LIMIT - sum(withdrawal.amount for withdrawal in withdrawals_today)),
        free_withdrawals_left=max(0, FREE_WITHDRAWALS_PER_30_DAYS - num_withdrawals_last_30_days),
        total_deposited=total_deposited
    )


@app.route('/api/me/bet', methods=['POST'])
@login_required
@limiter.limit("8 per minute")
def create_bet():
    # return jsonify(status='failure', error='ZZZ ZZ ZZZZZZ ZZZZ.')  # TODO
    exchange_id, bet_type, amount = request.json.get('exchange_id'), request.json.get('bet_type'), request.json.get('amount')
    if not isinstance(exchange_id, int):
        return jsonify(status='failure', error='ZZ Z ZZZZZZ.')
    if bet_type not in BetType.__members__:
        return jsonify(status='failure', error='ZZZZ ZZ ZZZ ZZZ ZZZZ ZZZZ.')
    if amount < MINIMUM_BET_AMOUNT:
        return jsonify(status='failure', error=f'{MINIMUM_BET_AMOUNT}Z ZZZZZ ZZZ Z ZZZZ.')

    # retrieve and lock user row, to avoid read-after-read conflicts
    user = db.session.query(User).with_for_update().populate_existing().get(current_user.id)
    if not user.email_confirmed:
        return jsonify(status='failure', error='ZZZZ ZZZZ ZZZZZ.')

    # get the current exchange from Redis (we don't care if it's inconsistent, since if it is then the bet just gets created somewhere harmless, like a nonexistent exchange)
    exchange_json = caching.get_exchange(exchange_id)
    if exchange_json is None:
        exchange = Exchange.query.filter_by(id=exchange_id).first()
        exchange_json = exchange.to_json() if exchange is not None else None
    if not exchange_json:
        return jsonify(status='failure', error='ZZZ ZZZ ZZZZZZZ')
    if amount > exchange_json['max_bet_amount']:
        return jsonify(status='failure', error=f'Z ZZZZ {exchange_json["max_bet_amount"]/10000}ZZZ ZZZZ ZZZ Z ZZZZ.')

    # get the current round from the DB, and some realtime-updated round metadata from Redis
    # this ensures we can avoid "FOR UPDATE" locking the round's row, which absolutely kills performance
    # if the Redis cached data is not in sync, we simply disable betting
    round = Round.query.filter_by(round_status=RoundStatus.BETTING, exchange_id=exchange_id).first()
    if round is None:
        return jsonify(status='failure', error='ZZZZ ZZZ ZZZZ.')  # usually this means that the round is in LOCKING_IN_BETS stage
    round_id, user_bets_amount, user_bet_direction, rise_bets_amount, fall_bets_amount = caching.get_betting_round_bets(exchange_id, current_user.id)
    if round_id != round.id:  # cached round settings are out of sync, disallow betting
        return jsonify(status='failure', error='ZZZZ ZZZZ ZZZ ZZZ, ZZZ ZZZZZ.')

    if bet_type == BetType.RISE.name:
        reached_max_bets = rise_bets_amount + amount > round.max_rise_bets_amount
    elif bet_type == BetType.FALL.name:
        reached_max_bets = fall_bets_amount + amount > round.max_fall_bets_amount
    else:
        assert False, bet_type
    if reached_max_bets:
        return jsonify(status='failure', error=f'{"ZZ"if bet_type == BetType.RISE.name else "ZZ"}ZZZZ ZZ.')

    if user_bets_amount + amount > MAXIMUM_AMOUNT_BET_PER_ROUND_PER_USER:
        return jsonify(status='failure', error=f'Z ZZZ {MAXIMUM_AMOUNT_BET_PER_ROUND_PER_USER/10000}ZZ ZZ ZZZ Z ZZZZ.')
    if user_bet_direction is not None:  # user already made bets this round, make sure the new bet is in the same direction (this prevents user from creating artificial volume to meet promotional requirements)
        if BetType(bet_type) != BetType(user_bet_direction):
            return jsonify(status='failure', error=f'{"ZZ" if user_bet_direction == BetType.RISE.name else "ZZ"}ZZZ ZZZ ZZZZ {"ZZ"if bet_type == BetType.FALL.name else "ZZ"}ZZZ ZZZ Z ZZZZ.')
    if bet_type == BetType.RISE.name:
        caching.add_betting_round_bets(exchange_id, current_user.id, amount, 0)
    elif bet_type == BetType.FALL.name:
        caching.add_betting_round_bets(exchange_id, current_user.id, 0, amount)

    # update user balance based on bet amount and house cut
    bet_commission = amount * BET_CUT_PERCENT
    if user.balance < amount + bet_commission:
        return jsonify(status='failure', error='ZZZZ ZZZZ ZZZ ZZZZ ZZZ Z ZZZZ.')
    prev_user_balance = user.balance
    user.balance -= amount + bet_commission
    user.pending_commissions += bet_commission  # this commission is moved into payable_commission after the round ends, by the price updater
    db.session.add(user)

    # create bet
    bet = Bet(
        user_id=user.id,
        round_id=round.id,
        bet_type=BetType[bet_type],
        bet_result=BetResult.PENDING,
        amount=amount,
        commission=bet_commission
    )

    db.session.add(bet)
    db.session.flush()

    # create balance change record
    balance_change_record = BalanceChangeRecord(
        user_id=user.id,
        bet_id=bet.id,
        balance_change_type=BalanceChangeType.BET,
        details=bet.bet_type.value,
        principal=bet.amount,
        before_balance=prev_user_balance,
        after_balance=user.balance,
    )
    db.session.add(balance_change_record)
    db.session.commit()
    caching.set_bet(bet.to_json())
    caching.set_user(user)  # caching takes place after commit, because we don't want to have the cache entry unless the transaction succeeded
    logger.info(f'Created bet {bet.id} as {bet.bet_type} for user {bet.user_id} with amount {bet.amount} for round {bet.round_id}.')

    # Broadcast bet to global bet history (strip out all sensitive fields)
    broadcast_bet = {
        "id": bet.id,
        "bet_type": bet.bet_type.value,
        "amount": bet.amount,
        "created_at": bet.created_at.replace(tzinfo=timezone.utc).isoformat()
    }
    partner_bet = {
        "id": bet.id,
        "user": bet.user.to_json(),
        "bet_type": bet.bet_type.value,
        "amount": bet.amount,
        "round": {"id": bet.round.id, "round_status": bet.round.round_status.value, 'round_number': bet.round.round_number},
        "created_at": bet.created_at.replace(tzinfo=timezone.utc).isoformat()
    }
    t = time.time()

    # broadcast public bet to everyone
    # TODO: socket.io needs redis to broadcast properly to every client
    socketio.emit('bet', broadcast_bet, broadcast=True)

    # emit sensitive info bet to partners up the chain
    # TODO: socket.io needs redis to broadcast properly to every client
    curr_user = bet.user.referring_user
    while curr_user is not None:
        socketio.emit('partner_bet', partner_bet, room=f'user_{curr_user.id}')
        curr_user = curr_user.referring_user

    logger.info(f"Broadcasted {bet} to {CONNECTED_SOCKETIO_CLIENTS} connected clients, took {time.time() - t} seconds")

    return jsonify(status='success', bet=bet.to_json())


@app.route('/api/bet')
@login_required
def list_global_bets():
    global_bets = [
        {
            'id': b['id'],
            'bet_type': b['bet_type'],
            'amount': b['amount'],
            'created_at': b['created_at'],
        } for b in reversed(sorted(caching.get_all_bets(), key=lambda r: r['created_at']))
    ]
    return jsonify(status='success', bets=global_bets)


@app.route('/api/partner/bet', methods=['POST'])
@partner_required
def list_partner_bets():
    round_id = request.json.get('round_id')
    user = User.query.get(current_user.id)
    if user.role == UserRole.HQ:
        bets_q = Bet.query.filter(Bet.user_id != user.id)
    elif user.role == UserRole.SOLE_DISTRIBUTOR:
        partners = user.referred_users
        franchisees = [franchisee for partner in partners for franchisee in partner.referred_users]
        users = [user for franchisee in franchisees for user in franchisee.referred_users]
        bets_q = Bet.query.filter(Bet.user_id.in_([u.id for u in users]))
    elif user.role == UserRole.PARTNER:
        franchisees = user.referred_users
        users = [user for franchisee in franchisees for user in franchisee.referred_users]
        bets_q = Bet.query.filter(Bet.user_id.in_([u.id for u in users]))
    elif user.role == UserRole.FRANCHISEE:
        users = user.referred_users
        bets_q = Bet.query.filter(Bet.user_id.in_([u.id for u in users]))

    bets = bets_q.filter_by(round_id=round_id).order_by(Bet.created_at.desc()).all()
    return jsonify(
        status='success',
        bets=[
            {
                'id': b.id,
                'round': {'id': b.round.id, 'round_status': b.round.round_status, 'round_number': b.round.round_number},
                'user': b.user.to_json(),
                'bet_type': b.bet_type.value,
                'amount': b.amount,
                'created_at': b.created_at.replace(tzinfo=timezone.utc).isoformat(),
            }
            for b in bets
        ]
    )


@app.route('/api/me/bet')
@login_required
def list_bets():
    user_bets = [
        b.to_json()
        for b in Bet.query.filter_by(user_id=current_user.id).order_by(Bet.created_at.desc()).limit(caching.BETS_HISTORY_LENGTH).all()
    ]
    return jsonify(status='success', bets=user_bets)


@app.route('/api/me/balance_change_records')
@login_required
def list_balance_change_records():
    records = [
        r.to_json()
        for r in BalanceChangeRecord.query.filter_by(user_id=current_user.id).order_by(BalanceChangeRecord.created_at.desc()).limit(BALANCE_CHANGE_RECORDS_HISTORY_LENGTH).all()
    ]
    return jsonify(status='success', records=records)


@app.route('/api/exchange')
def list_all_exchanges():
    return jsonify(status='success', exchanges=caching.get_all_exchanges())


@app.route('/api/round/<int:exchange_id>')
def list_rounds(exchange_id):
    all_rounds_json = list(reversed(sorted(caching.get_exchange_rounds(exchange_id), key=lambda r: r['start_time'])))
    return jsonify(status='success', rounds=all_rounds_json)


@app.route('/api/me/tickets', methods=['POST'])
@login_required
def create_ticket():
    subject, message = request.json.get('subject'), request.json.get('message')
    if len(subject) > 255:
        return jsonify(status='failure', error='255ZZZ ZZZZZZ.')

    sanitized_subject = html.escape(subject)
    sanitized_message = html.escape(message)

    new_ticket = Ticket(
        user_id=current_user.id,
        subject=sanitized_subject,
        user_message=sanitized_message,
    )
    db.session.add(new_ticket)
    db.session.commit()
    return jsonify(status='success', ticket=new_ticket.to_json())


@app.route('/api/me/tickets', methods=['GET'])
@login_required
def get_tickets_for_user():
    user_tickets = [
        t.to_json()
        for t in Ticket.query.filter_by(user_id=current_user.id).order_by(Ticket.created_at.desc())
    ]
    return jsonify(status='success', tickets=user_tickets)


@app.route('/api/me/tickets/<int:ticket_id>', methods=['GET'])
@login_required
def get_ticket(ticket_id):
    ticket = Ticket.query.filter_by(id=ticket_id, user_id=current_user.id).first()
    if not ticket:
        return jsonify(status='failure', error='ZZZ ZZ Z ZZZZ.')

    return jsonify(status='success', ticket=ticket.to_json())


@app.route('/api/announcements/<int:page_id>', methods=['GET'])
def get_announcements(page_id):
    announcement_page = Announcement.query.order_by(Announcement.created_at.desc()).paginate(page=page_id, per_page=10)
    announcements = [
        a.to_json()
        for a in announcement_page.items
    ]
    pages = announcement_page.pages
    # don't increment view counts when getting all announcements
    return jsonify(status='success', announcements=announcements, pages=pages)


@app.route('/api/announcement/<int:announcement_id>', methods=['GET'])
def get_announcement_by_id(announcement_id):
    announcement = Announcement.query.filter_by(id=announcement_id).first()
    if not announcement:
        return jsonify(status='failure', error='ZZZ ZZ Z ZZZZ.')

    # increment view count when the specific announcement is grabbed.
    announcement.view_count = announcement.view_count + 1
    db.session.add(announcement)
    db.session.commit()

    return jsonify(status='success', announcement=announcement.to_json())


@app.route('/api/bet_management/decrease_max_lots', methods=['POST'])
@hq_required
def decrease_max_lots():
    round_id, bet_type, decrease_amount = request.json.get('round_id'), request.json.get('bet_type'), request.json.get('decrease_amount')
    round = Round.query.filter_by(id=round_id).first()
    if round.round_status != RoundStatus.BETTING:
        return jsonify(status='failure', error='Round is not in betting stage')
    if bet_type not in BetType.__members__:
        return jsonify(status='failure', error='Bet type {} does not exist.'.format(bet_type))
    if bet_type == BetType.RISE.value:
        round.max_rise_bets_amount -= decrease_amount * KRW_PER_LOT
    elif bet_type == BetType.FALL.value:
        round.max_fall_bets_amount -= decrease_amount * KRW_PER_LOT
    db.session.add(round)
    db.session.commit()
    caching.set_round(round.to_json())
    return jsonify(status='success')


@app.route('/api/bet_management/lot_status', methods=['POST'])
@hq_required
def set_lot_statuses():
    round_id, bet_type, status_10_lot, status_5_lot, status_1_lot, status_0_5_lot, status_0_1_lot, status_0_05_lot = request.json.get('round_id'), request.json.get('bet_type'), request.json.get('status_10_lot'), request.json.get('status_5_lot'), request.json.get('status_1_lot'), request.json.get('status_0_5_lot'), request.json.get('status_0_1_lot'), request.json.get('status_0_05_lot')
    round = Round.query.filter_by(id=round_id).first()
    if round.round_status != RoundStatus.BETTING:
        return jsonify(status='failure', error='Round is not in betting stage')
    if bet_type not in BetType.__members__:
        return jsonify(status='failure', error='Bet type {} does not exist.'.format(bet_type))
    if status_10_lot not in RoundLotTypeStatus.__members__:
        return jsonify(status='failure', error='10 lot type status {} does not exist.'.format(status_10_lot))
    if status_5_lot not in RoundLotTypeStatus.__members__:
        return jsonify(status='failure', error='5 lot type status {} does not exist.'.format(status_5_lot))
    if status_1_lot not in RoundLotTypeStatus.__members__:
        return jsonify(status='failure', error='1 lot type status {} does not exist.'.format(status_1_lot))
    if status_0_5_lot not in RoundLotTypeStatus.__members__:
        return jsonify(status='failure', error='0.5 lot type status {} does not exist.'.format(status_0_5_lot))
    if status_0_1_lot not in RoundLotTypeStatus.__members__:
        return jsonify(status='failure', error='0.1 lot type status {} does not exist.'.format(status_0_1_lot))
    if status_0_05_lot not in RoundLotTypeStatus.__members__:
        return jsonify(status='failure', error='0.05 lot type status {} does not exist.'.format(status_0_05_lot))

    if bet_type == BetType.RISE.value:    
        round.rise_status_10_lot = RoundLotTypeStatus[status_10_lot]
        round.rise_status_5_lot = RoundLotTypeStatus[status_5_lot]
        round.rise_status_1_lot = RoundLotTypeStatus[status_1_lot]
        round.rise_status_0_5_lot = RoundLotTypeStatus[status_0_5_lot]
        round.rise_status_0_1_lot = RoundLotTypeStatus[status_0_1_lot]
        round.rise_status_0_05_lot = RoundLotTypeStatus[status_0_05_lot]
    elif bet_type == BetType.FALL.value:
        round.fall_status_10_lot = RoundLotTypeStatus[status_10_lot]
        round.fall_status_5_lot = RoundLotTypeStatus[status_5_lot]
        round.fall_status_1_lot = RoundLotTypeStatus[status_1_lot]
        round.fall_status_0_5_lot = RoundLotTypeStatus[status_0_5_lot]
        round.fall_status_0_1_lot = RoundLotTypeStatus[status_0_1_lot]
        round.fall_status_0_05_lot = RoundLotTypeStatus[status_0_05_lot]
    db.session.add(round)
    db.session.commit()
    caching.set_round(round.to_json())
    return jsonify(status='success')


@app.route('/api/bet_management/set_exchange_round_decided_threshold', methods=['POST'])
@hq_required
def set_exchange_round_decided_threshold():
    exchange_id, new_threshold = request.json.get('exchange_id'), request.json.get('new_threshold')
    exchange = Exchange.query.filter_by(id=exchange_id).first()
    if not exchange:
        return jsonify(status='failure', error='Exchange does not exist')
    exchange.round_decided_threshold = float(new_threshold)
    db.session.add(exchange)
    db.session.commit()
    caching.set_exchange(exchange.to_json())
    return jsonify(status='success')




@app.route('/api/reports/sales/daily', methods=['GET'])
@hq_required
def get_daily_sales():
    page_id = int(request.args.get('page', 1))
    report_date = request.args.get('date', date.today())

    rise_amount = db.session.query(
        Bet.round_id,
        db.func.sum(Bet.amount).label('bet_amount'),
        db.func.sum(Bet.commission).label('bet_commission'),
    ).filter(
        Bet.bet_type == BetType.RISE.value,
        Bet.bet_result != BetResult.CANCELLED,
    ).group_by(Bet.round_id).subquery()

    fall_amount = db.session.query(
        Bet.round_id,
        db.func.sum(Bet.amount).label('bet_amount'),
        db.func.sum(Bet.commission).label('bet_commission'),
    ).filter(
        Bet.bet_type == BetType.FALL.value,
        Bet.bet_result != BetResult.CANCELLED,
    ).group_by(Bet.round_id).subquery()

    report = db.session.query(
        Round,
        rise_amount.c.bet_amount,
        rise_amount.c.bet_commission,
        fall_amount.c.bet_amount,
        fall_amount.c.bet_commission,
    ).filter(
        Round.round_date == report_date
    ).outerjoin(
        rise_amount,
        Round.id == rise_amount.c.round_id
    ).outerjoin(
        fall_amount,
        Round.id == fall_amount.c.round_id
    ).options(
        db.joinedload(Round.exchange).load_only(Exchange.name)
    ).order_by(
        Round.created_at.desc()
    )

    # I can't be bothered to learn sql again for this on a deadline so here goes
    updated_report = []
    
    # there must be a better way to get the total company profit...
    # QILE TODO: fix this to b better. There's absolutely a better way. But not right now.
    total_company_profit = 0
    for (idx, row) in enumerate(report.all()):
        round, rise_amount, rise_commission, fall_amount, fall_commission = row
        rise_amount = 0 if rise_amount is None else rise_amount
        fall_amount = 0 if fall_amount is None else fall_amount
        rise_commission = 0 if rise_commission is None else rise_commission
        fall_commission = 0 if fall_commission is None else fall_commission
        company_winnings = rise_amount if round.round_result == RoundResult.FALL else fall_amount
        company_losses = rise_amount if round.round_result == RoundResult.RISE else fall_amount
        company_profit = company_winnings - company_losses + rise_commission + fall_commission

        total_company_profit = total_company_profit + company_profit
        
        if (idx < page_id * 10 and idx >= ( page_id - 1 ) * 10):
            updated_report.append({
                "id": (idx + 1),
                "round": round.to_json(),
                "company_winnings": company_winnings,
                "company_losses": company_losses,
                "rise_amount": rise_amount,
                "fall_amount": fall_amount,
                "spread": (rise_amount + fall_amount) * 0.1,
                "company_profit": company_profit
            })
    total = report.count()
    pages = report.count() // 10 + 1

    return jsonify(status='success', sales=updated_report, pages=pages, total=total, profit=total_company_profit)

@app.route('/api/reports/member_management/member_deposit_status', methods=['GET'])
@partner_required
def get_member_deposit_status():
    page_id = int(request.args.get('page', 1))
    type = request.args.get('type')
    query = request.args.get('query')
    user = User.query.get(current_user.id)

    deposit = db.session.query(
        Transaction.user_id,
        db.func.sum(Transaction.amount).label('total_amount_deposited')
    ).filter(
        Transaction.transaction_type == TransactionType.DEPOSIT.value,
        Transaction.status == TransactionStatus.COMPLETE.value
    ).group_by(Transaction.user_id).subquery()
    withdrawal = db.session.query(
        Transaction.user_id,
        db.func.sum(Transaction.amount).label('total_amount_withdrawn')
    ).filter(
        Transaction.transaction_type == TransactionType.WITHDRAWAL.value,
        Transaction.status == TransactionStatus.COMPLETE.value
    ).group_by(Transaction.user_id).subquery()

    winning_bet = db.session.query(Bet.user_id, db.func.sum(Bet.amount).label('total_amount_won')).filter_by(bet_result=BetResult.WON.value).group_by(Bet.user_id).subquery()
    cancelled_bet = db.session.query(Bet.user_id, db.func.sum(Bet.amount).label('total_amount_refunded')).filter_by(bet_result=BetResult.CANCELLED.value).group_by(Bet.user_id).subquery()
    all_bet = db.session.query(Bet.user_id, db.func.count(Bet.id).label('total_num_bets'), db.func.sum(Bet.amount).label('total_amount_bet')).group_by(Bet.user_id).subquery()
    user_page = (
        db.session.query(
            User,
            all_bet.c.total_num_bets,
            winning_bet.c.total_amount_won,
            cancelled_bet.c.total_amount_refunded,
            all_bet.c.total_amount_bet,
            deposit.c.total_amount_deposited,
            withdrawal.c.total_amount_withdrawn,
        )
        .outerjoin(all_bet, User.id == all_bet.c.user_id)
        .outerjoin(winning_bet, User.id == winning_bet.c.user_id)
        .outerjoin(cancelled_bet, User.id == cancelled_bet.c.user_id)
        .outerjoin(deposit, User.id == deposit.c.user_id)
        .outerjoin(withdrawal, User.id == withdrawal.c.user_id)
    )
    total_balance = db.session.query(db.func.sum(User.balance))

    query_filtered_user_ids = get_query_filtered_user_ids(type, query)
    if query_filtered_user_ids is not None:
        user_page = user_page.filter(User.id.in_(query_filtered_user_ids))
        total_balance = total_balance.filter(User.id.in_(query_filtered_user_ids))

    # if user is not HQ, restrict their view to descendants
    if user.role != UserRole.HQ:
        user_ids = get_user_and_descendant_user_ids(user)
        user_page = user_page.filter(User.id.in_(user_ids))
        total_balance = total_balance.filter(User.id.in_(user_ids))

    user_page = user_page.paginate(page=page_id, per_page=10)
    statuses = [
        {
            "no": (idx + 1) + (page_id - 1) * 10,
            "user": user.to_json(),
            "total_num_bets": total_num_bets or 0,
            "total_amount_won": total_amount_won,
            "total_amount_refunded": total_amount_refunded,
            "total_amount_bet": total_amount_bet,
            "total_amount_deposited": total_amount_deposited,
            "total_amount_withdrawn": total_amount_withdrawn,
        }
        for idx, (user, total_num_bets, total_amount_won, total_amount_refunded, total_amount_bet, total_amount_deposited, total_amount_withdrawn) in enumerate(user_page.items)
    ]
    return jsonify(status='success', statuses=statuses, total_balance=total_balance.scalar(), pages=user_page.pages, total=user_page.total)


@app.route('/api/reports/member_management/profile', methods=['GET'])
@partner_required
def get_member_management_profiles():
    page_id = int(request.args.get('page', 1))
    type = request.args.get('type')
    query = request.args.get('query')
    user = User.query.get(current_user.id)

    user_page = User.query

    query_filtered_user_ids = get_query_filtered_user_ids(type, query)
    if query_filtered_user_ids is not None:
        user_page = user_page.filter(User.id.in_(query_filtered_user_ids))

    # if user is not HQ, restrict view to descendants
    if current_user.role != UserRole.HQ:
        user_page = user_page.filter(User.id.in_(get_user_and_descendant_user_ids(user)))

    user_page = user_page.order_by(User.created_at.desc()).paginate(page=page_id, per_page=10)

    users = [{**u.to_json(), "no" : (idx + 1) + (page_id - 1) * 10} for idx, u in enumerate(user_page.items)]
    return jsonify(status='success', users=users, pages=user_page.pages, total=user_page.total)


@app.route('/api/reports/member_management/point_payment_history', methods=['GET'])
@partner_required
def get_point_payment_history():
    page_id = int(request.args.get('page', 1))
    type = request.args.get('type')
    query = request.args.get('query')
    date = request.args.get('date')
    user = User.query.get(current_user.id)

    balance_change_page = db.session.query(BalanceChangeRecord).filter(BalanceChangeRecord.balance_change_type == BalanceChangeType.MANUAL).order_by(BalanceChangeRecord.created_at.desc())
    if date is not None:
        balance_change_page = balance_change_page.filter(db.func.date(BalanceChangeRecord.created_at) == date)

    query_filtered_user_ids = get_query_filtered_user_ids(type, query)
    if query_filtered_user_ids is not None:
        balance_change_page = balance_change_page.join(User).filter(User.id.in_(query_filtered_user_ids))

    # if user is not HQ, restrict view to descendants
    if user.role != UserRole.HQ:
        balance_change_page = balance_change_page.filter(BalanceChangeRecord.user_id.in_(get_user_and_descendant_user_ids(user)))

    balance_change_page = balance_change_page.paginate(page=page_id, per_page=10)

    records = [r.to_json() for r in balance_change_page.items]
    return jsonify(status='success', records=records, pages=balance_change_page.pages, total=balance_change_page.total)


@app.route('/api/reports/member_management/partner_management', methods=['GET'])
@partner_required
def get_partner_status():
    page_id = int(request.args.get('page', 1))
    type = request.args.get('type')
    query = request.args.get('query')
    date = request.args.get('date')
    user = User.query.get(current_user.id)

    user_page = User.query

    if date is not None:
        user_page = user_page.filter(db.func.date(User.created_at) == date)

    query_filtered_user_ids = get_query_filtered_user_ids(type, query)
    if query_filtered_user_ids is not None:
        user_page = user_page.filter(User.id.in_(query_filtered_user_ids))

    # if user is not HQ, restrict view to descendants
    if user.role != UserRole.HQ:
        user_page = user_page.filter(User.id.in_(get_user_and_descendant_user_ids(user)))

    user_page = user_page.paginate(page=page_id, per_page=10)
    users = [
        {
            "no": (idx + 1) + (page_id - 1) * 10,
            "id": u.id,
            "name": u.name,
            "username": u.username,
            "sole_distributor": u.get_sole_distributor(),
            "branch": u.get_branch(),
            "franchisee": u.get_franchisee(),
            "phone": u.phone.to_json(),
            "bank_name": u.bank_name,
            "bank_account_number": u.bank_account_number,
            "created_at": u.created_at,
        }
        for idx, u in enumerate(user_page.items)
    ]

    pages = user_page.pages
    total = user_page.total

    return jsonify(status='success', users=users, pages=pages, total=total)


@app.route('/api/reports/income', methods=['GET'])
@hq_required
def get_income_report():
    '''
    Date (YYYY-MM-DD)
    Number of people who deposited on this date (Int)  
    Total Amount Deposited (Eg: 12.5M KRW)
    Number of people who withdrew on this date (Int)
    Total Amount Withdrawn (Eg: 12.5M KRW)
    Total Number of Bets
    Total Volume of Bets (How much did people bet in total that day. Eg: 10 people bet 10k won rising, 10 people bet 5k falling. Regardless of if they win or lose. You calculate by 10ppl * 10k KRW + 10ppl * 5k KRW = 150k KRW)
    Total number of bets that lost money (so the company makes money, int)
    Total amount for bets that lost money (in KRW, without including commission)
    Total number of bets that won money (so the company loses money, int)
    Total amount for bets that won money (in KRW, without including commission)
    Total number of bets that were cancelled (int)
    Total amount for bets that were cancelled (in KRW, without including commission)
    Total commission/transaction spread (the 10% fee off of every bet, in KRW)
    Total profit (copy the same P&L from the top right corner of the daily sales table)
    '''
    page_id = int(request.args.get('page', 1))
    report_date = request.args.get('date')

    report_query = db.session.query(
        db.func.date(Bet.created_at),
        db.func.count(Bet.id).label('bet_count'),
        db.func.sum(Bet.amount).label('bet_sum'),
        db.func.count(db.case([(Transaction.transaction_type == TransactionType.DEPOSIT, Transaction.id)])).label('deposit_count'),
        db.func.sum(db.case([(Transaction.transaction_type == TransactionType.DEPOSIT, Transaction.amount)], else_=0)).label('deposit_amount'),
        db.func.count(db.case([(Transaction.transaction_type == TransactionType.WITHDRAWAL, Transaction.id)])).label('withdrawal_count'),
        db.func.sum(db.case([(Transaction.transaction_type == TransactionType.WITHDRAWAL, Transaction.amount)], else_=0)).label('withdrawal_amount'),
        db.func.count(db.case([(Bet.bet_result == BetResult.WON, Bet.id)])).label('winning_bet_count'),
        db.func.sum(db.case([(Bet.bet_result == BetResult.WON, Bet.amount)], else_=0)).label('winning_bet_amount'),
        db.func.sum(db.case([(Bet.bet_result == BetResult.WON, Bet.commission)], else_=0)).label('winning_bet_commission'),
        db.func.count(db.case([(Bet.bet_result == BetResult.LOST, Bet.id)])).label('losing_bet_count'),
        db.func.sum(db.case([(Bet.bet_result == BetResult.LOST, Bet.amount)], else_=0)).label('losing_bet_amount'),
        db.func.sum(db.case([(Bet.bet_result == BetResult.LOST, Bet.commission)], else_=0)).label('losing_bet_commission'),
        db.func.count(db.case([(Bet.bet_result == BetResult.CANCELLED, Bet.id)])).label('cancelled_bet_count'),
        db.func.sum(db.case([(Bet.bet_result == BetResult.CANCELLED, Bet.amount)], else_=0)).label('cancelled_bet_amount'),
        db.func.sum(db.case([(Bet.bet_result == BetResult.CANCELLED, Bet.commission)], else_=0)).label('cancelled_bet_commission'),
    ).outerjoin(
        Transaction,
        db.func.date(Bet.created_at) == db.func.date(Transaction.created_at)
    ).group_by(
        db.func.date(Bet.created_at)
    ).order_by(
        db.func.date(Bet.created_at).desc()
    )

    if report_date:
        report_query = report_query.having(
            db.func.date(Bet.created_at) == report_date
        )
    
    report_query = report_query.paginate(page=page_id, per_page=10)

    updated_report = []
    for (idx, row) in enumerate(report_query.items):
        updated_report.append({
            "id": (idx + 1) + (page_id - 1) * 10,
            "date": date.isoformat(row[0]),
            "bet_count": row[1],
            "bet_amount": row[2],
            "deposit_count": row[3],
            "deposit_amount": row[4],
            "withdrawal_count": row[5],
            "withdrawal_amount": row[6],
            "winning_bet_count": row[7],
            "winning_bet_amount": row[8],
            "winning_bet_commission": row[9],
            "losing_bet_count": row[10],
            "losing_bet_amount": row[11],
            "losing_bet_commission": row[12],
            "cancelled_bet_amount": row[13],
            "cancelled_bet_count": row[14],
            "cancelled_bet_commission": row[15],
            "spread": row[2]*0.1,
            # profit = losing_bet_amount - winning_bet_amount + losing_bet_commission + winning_bet_commission
            "profit": row[11] - row[8] + row[9] + row[12], 
        })

    return jsonify(status='success', report=updated_report, pages=report_query.pages, total=report_query.total)


@app.route('/api/reports/member_managmement/daily_deposit_status', methods=['GET'])
@partner_required
def get_daily_deposit_status():
    page_id = int(request.args.get('page', 1))
    start_date = request.args.get('startdate')
    end_date = request.args.get('enddate')
    query = request.args.get('query')
    user = User.query.get(current_user.id)

    bet_query = db.session.query(
        Bet.user_id.label('user_id'),
        db.func.count(Bet.id).label('bet_count'),
        db.func.sum(Bet.amount).label('bet_sum'),db.func.sum(db.case([(Bet.bet_result == BetResult.WON, Bet.amount)], else_=0)).label('winning_bet_amount'),
        db.func.sum(db.case([(Bet.bet_result == BetResult.WON, Bet.commission)], else_=0)).label('winning_bet_commission'),
        db.func.sum(db.case([(Bet.bet_result == BetResult.LOST, Bet.amount)], else_=0)).label('losing_bet_amount'),
        db.func.sum(db.case([(Bet.bet_result == BetResult.LOST, Bet.commission)], else_=0)).label('losing_bet_commission'),
        db.func.sum(db.case([(Bet.bet_result == BetResult.CANCELLED, Bet.amount)], else_=0)).label('cancelled_bet_amount'),
        db.func.sum(db.case([(Bet.bet_result == BetResult.CANCELLED, Bet.commission)], else_=0)).label('cancelled_bet_commission'),
    ).group_by(
        Bet.user_id, db.func.date(Bet.created_at)
    )

    transaction_query = db.session.query(
        Transaction.user_id.label('user_id'),
        db.func.sum(db.case([(Transaction.transaction_type == TransactionType.DEPOSIT, Transaction.amount)], else_=0)).label('deposit_amount'),
        db.func.sum(db.case([(Transaction.transaction_type == TransactionType.WITHDRAWAL, Transaction.amount)], else_=0)).label('withdrawal_amount'),
    ).filter(
        Transaction.status == TransactionStatus.COMPLETE.value
    ).group_by(
        Transaction.user_id, db.func.date(Transaction.created_at)
    )

    query_filtered_user_ids = get_query_filtered_user_ids(type, query)
    if query_filtered_user_ids is not None:
        bet_query = bet_query.filter(
            Bet.user_id.in_(query_filtered_user_ids)
        )
        transaction_query = transaction_query.filter(
            Transaction.user_id.in_(query_filtered_user_ids)
        )

    # if user is not HQ, restrict view to descendants
    if user.role != UserRole.HQ:
        user_ids = get_user_and_descendant_user_ids(user)
        bet_query = bet_query.filter(Bet.user_id.in_(user_ids))
        transaction_query = transaction_query.filter(Transaction.user_id.in_(user_ids))

    if (end_date is not None and start_date is not None):
        bet_query = bet_query.filter(
            db.func.date(Bet.created_at) <= end_date,
            db.func.date(Bet.created_at) >= start_date
        )
        transaction_query = transaction_query.filter(
            db.func.date(Transaction.created_at) <= end_date,
            db.func.date(Transaction.created_at) >= start_date
        )

    bet_query = bet_query.subquery()
    transaction_query = transaction_query.subquery()
    
    report = db.session.query(
            User,
            bet_query.c.bet_count,
            transaction_query.c.deposit_amount,
            bet_query.c.winning_bet_amount,
            bet_query.c.winning_bet_commission,
            bet_query.c.losing_bet_amount,
            bet_query.c.losing_bet_commission,
            bet_query.c.cancelled_bet_amount,
            bet_query.c.cancelled_bet_commission,
            transaction_query.c.withdrawal_amount,
            bet_query.c.bet_sum,
        ).outerjoin(
            bet_query,
            bet_query.c.user_id == User.id
        ).outerjoin(
            transaction_query,
            transaction_query.c.user_id == User.id,
        ).filter(
            db.or_(
                bet_query.c.bet_count != None,
                transaction_query.c.deposit_amount != None,
                transaction_query.c.withdrawal_amount != None,
            )
        )

    report_page = report.paginate(page=page_id, per_page=10)

    updated_report = []
    for (idx, row) in enumerate(report_page.items):
        user = row[0]
        updated_report.append({
            "no": (idx + 1) + (page_id - 1) * 10,
            "user_id": user.id,
            "username": user.username,
            "name": user.name,
            "franchisee": user.get_franchisee(),
            "branch": user.get_branch(),
            "distributor": user.get_sole_distributor(),
            "phone": user.phone.phone,
            "bet_count": row[1],
            "deposit_amount": row[2],
            "winning_bet_amount": row[3],
            "winning_commission": row[4],
            "losing_bet_amount": row[5],
            "losing_bet_commission": row[6],
            "cancelled_bet_amount": row[7],
            "cancelled_bet_commission": row[8],
            "withdrawal_amount": row[9],
            "bet_sum": row[10],
        })

    return jsonify(status='success', statuses=updated_report, pages=report_page.pages, total=report_page.total)


@app.route('/api/reports/member_management/member_order_history', methods=['GET'])
@partner_required
def get_member_order_history():
    page_id = int(request.args.get('page', 1))
    date = request.args.get('date')
    type = request.args.get('type')
    query = request.args.get('query')
    user = User.query.get(current_user.id)

    first_balance_change_records = db.session.query(
        db.func.max(BalanceChangeRecord.id),
    ).filter(
        BalanceChangeRecord.bet_id.isnot(None),
        BalanceChangeRecord.user_id.isnot(None),
    ).group_by(
        BalanceChangeRecord.user_id, BalanceChangeRecord.bet_id
    ).subquery()

    report = db.session.query(
        Bet,
        User,
        Round,
        BalanceChangeRecord,
    ).filter(
        User.id == Bet.user_id
    ).filter(
        Round.id == Bet.round_id
    ).filter(
        BalanceChangeRecord.bet_id == Bet.id,
        BalanceChangeRecord.user_id == User.id
    ).filter(
        BalanceChangeRecord.id.in_(first_balance_change_records)
    )

    if (date is not None):
        report = report.filter(
            db.func.date(Bet.created_at) == date
        )

    query_filtered_user_ids = get_query_filtered_user_ids(type, query)
    if query_filtered_user_ids is not None:
        report = report.filter(User.id.in_(query_filtered_user_ids))

    # if user is not HQ, restrict view to descendants
    if current_user.role != UserRole.HQ:
        report = report.filter(User.id.in_(get_user_and_descendant_user_ids(user)))

    report_page = report.paginate(page=page_id, per_page=10)

    histories = []
    for idx, (bet, user, round, balance_change_record) in enumerate(report_page.items):
        if bet.bet_result == BetResult.WON:
            print(bet.id, bet.amount, balance_change_record.arbitrage)
            assert bet.amount == balance_change_record.arbitrage
            total_return = bet.amount
            refund = 0
        elif bet.bet_result == BetResult.LOST:
            assert balance_change_record.arbitrage == 0
            total_return = - bet.amount
            refund = 0
        elif bet.bet_result == BetResult.CANCELLED:
            assert bet.amount == balance_change_record.principal
            total_return = 0
            refund = bet.amount

        histories.append({
            "id": (idx + 1) + (page_id - 1) * 10,
            'username': user.username,
            'name': user.name,
            'round_id': round.id,
            'bet_type': bet.bet_type.value,
            'bet_amount': bet.amount,
            'total_return': total_return,
            'refund': refund,
            'after_balance': balance_change_record.after_balance,
            'round_start_time': round.start_time,
            'round_result': round.round_result.value,
        })
    pages = report_page.pages
    total = report_page.total

    return jsonify(status='success', histories=histories, pages=pages, total=total)


@app.route('/api/reports/merchant_management/daily_fee_counting', methods=['GET'])
@partner_required
def get_daily_fees():
    start_date = request.args.get('startDate')
    end_date = request.args.get('endDate')
    type = request.args.get('type')
    query = request.args.get('query')
    user = User.query.get(current_user.id)

    if start_date is None and end_date is None:
        start_date = date.today()
        end_date = date.today()
    elif start_date is None:
        start_date = parser.parse(end_date).date()
        end_date = parser.parse(end_date).date()
    elif end_date is None:
        end_date = parser.parse(start_date).date()
        start_date = parser.parse(start_date).date()
    else:
        start_date = parser.parse(start_date).date()
        end_date = parser.parse(end_date).date()

    if user.role == UserRole.HQ:
        sole_distributors = User.query.filter(User.referring_user_id == user.id).all()
        branches = User.query.filter(User.referring_user_id.in_([u.id for u in sole_distributors])).all()
        franchisees = User.query.filter(User.referring_user_id.in_([u.id for u in branches])).all()
        partners = franchisees + branches + sole_distributors + [user]
    elif user.role == UserRole.SOLE_DISTRIBUTOR:
        branches = User.query.filter(User.referring_user_id == user.id).all()
        franchisees = User.query.filter(User.referring_user_id.in_([u.id for u in branches])).all()
        partners = franchisees + branches + [user]
    elif user.role == UserRole.PARTNER:
        franchisees = User.query.filter(User.referring_user_id == user.id).all()
        partners = franchisees + [user]
    elif user.role == UserRole.FRANCHISEE:
        partners = [user]
    else:
        assert False, user

    client_ids = get_descendant_user_ids(partners)
    user_children = defaultdict(set)
    for parent_id, child_id in db.session.query(User.referring_user_id, User.id).filter(User.referring_user_id.in_([u.id for u in partners])).all():
        user_children[parent_id].add(child_id)

    commissions = {
        (user_id, bet_date): commission
        for user_id, bet_date, commission in db.session.query(
            Bet.user_id,
            db.func.date(Bet.created_at).label('date'),
            db.func.sum(Bet.commission).label('commissions')
        ).filter(
            Bet.user_id.in_(client_ids),
            db.func.date(Bet.created_at) >= start_date,
            db.func.date(Bet.created_at) <= end_date,
            Bet.bet_result != BetResult.CANCELLED.value,
        ).group_by(Bet.user_id, db.func.date(Bet.created_at)).all()
    }

    bet_by_outcome = db.session.query(
        Bet.bet_result,
        Bet.user_id,
        db.func.date(Bet.created_at),
        db.func.sum(Bet.amount).label('amount_won'),
        db.func.count(Bet.id).label('num_bets')
    ).filter(
        Bet.user_id.in_(client_ids),
        Bet.bet_result == BetResult.WON.value,
        db.func.date(Bet.created_at) >= start_date,
        db.func.date(Bet.created_at) <= end_date
    ).group_by(Bet.bet_result, Bet.user_id, db.func.date(Bet.created_at)).all()

    all_bet, won_bet, lost_bet, cancelled_bet = {}, {}, {}, {}
    for bet_result, user_id, bet_date, total_amount_bet, num_bets in bet_by_outcome:
        if bet_result == BetResult.WON:
            won_bet[(user_id, bet_date)] = (total_amount_bet, num_bets)
        elif bet_result == BetResult.LOST:
            lost_bet[(user_id, bet_date)] = (total_amount_bet, num_bets)
        elif bet_result == BetResult.CANCELLED:
            cancelled_bet[(user_id, bet_date)] = (total_amount_bet, num_bets)
        else:
            assert False, bet_result
        all_total, all_num = all_bet.get((user_id, bet_date), (0, 0))
        all_bet[(user_id, bet_date)] = (total_amount_bet + all_total, num_bets + all_num)

    records = []
    num_days = (int)((end_date - start_date).days) + 1
    for curr_date in (end_date - timedelta(days=n) for n in range(num_days)):
        for partner in partners:
            if type == 'fbname' and query is not None and query.lower() not in partner.get_franchisee().lower() and query.lower() not in partner.get_branch().lower():
                continue

            # BFS to find all descendants
            to_visit = {partner.id}
            partner_descendant_ids = {partner.id}
            while to_visit:
                current_id = to_visit.pop()
                new_nodes = user_children[current_id] - partner_descendant_ids
                to_visit |= new_nodes
                partner_descendant_ids |= new_nodes
            partner_descendant_ids.remove(partner.id)

            record = {
                'sole_distributor': partner.get_sole_distributor(),
                'branch': partner.get_branch(),
                'franchisee': partner.get_franchisee(),
                'date': curr_date.isoformat(),
                'total_num_bets': 0,
                'total_amount_bet': 0,
                'total_num_bets_won': 0,
                'total_amount_won': 0,
                'total_num_bets_lost': 0,
                'total_amount_lost': 0,
                'total_num_bets_cancelled': 0,
                'total_amount_refunded': 0,
                'commission_revenue': 0,
            }
            for client_id in partner_descendant_ids:
                total_amount_bet, num_bets = all_bet.get((client_id, curr_date), (None, None))
                total_amount_bet_won, num_bets_won = won_bet.get((client_id, curr_date), (None, None))
                total_amount_bet_lost, num_bets_lost = lost_bet.get((client_id, curr_date), (None, None))
                total_amount_bet_cancelled, num_bets_cancelled = cancelled_bet.get((client_id, curr_date), (None, None))
                if total_amount_bet is not None:
                    record['total_num_bets'] += num_bets
                    record['total_amount_bet'] += total_amount_bet or 0
                if total_amount_bet_won is not None:
                    record['total_num_bets_won'] += num_bets_won
                    record['total_amount_won'] += total_amount_bet_won or 0
                if total_amount_bet_lost is not None:
                    record['total_num_bets_lost'] += num_bets_lost
                    record['total_amount_lost'] += total_amount_bet_lost or 0
                if total_amount_bet_cancelled is not None:
                    record['total_num_bets_cancelled'] += num_bets_cancelled
                    record['total_amount_refunded'] += total_amount_bet_cancelled or 0
                record['commission_revenue'] += commissions.get((client_id, curr_date)) or 0
            records.append(record)
    return jsonify(status='success', records=records)


def broadcast_current_round():
    global last_broadcast_time  # healthcheck will check this to ensure that this loop is still running
    last_exchange_rounds = None
    while True:
        before_time = time.time()

        exchange_rounds = {}
        for exchange_json in caching.get_all_exchanges():
            latest_rounds = list(reversed(sorted(caching.get_exchange_rounds(exchange_json['id'], 3), key=lambda r: r['start_time'])))
            exchange_rounds[exchange_json['id']] = latest_rounds

        last_broadcast_time = time.time()

        if exchange_rounds != last_exchange_rounds:
            # broadcast it to all connected clients
            # TODO: socket.io needs redis to broadcast properly to every client
            socketio.emit('round', exchange_rounds, broadcast=True)
            after_time = time.time()
            logger.info(f"Broadcasted rounds from {len(exchange_rounds)} exchange(s) to {CONNECTED_SOCKETIO_CLIENTS} connected clients, took {after_time - last_broadcast_time} seconds (retrieval took {last_broadcast_time - before_time} seconds)")
        else:
            after_time = time.time()
            logger.info(f"Skipping rounds broadcast (retrieval took {last_broadcast_time - before_time} seconds)")

        if after_time - before_time < ROUND_UPDATE_PERIOD:
            socketio.sleep(ROUND_UPDATE_PERIOD - (after_time - before_time))
        else:
            logger.warning(f"Backend falling behind expected frequency of 1 update per {ROUND_UPDATE_PERIOD} seconds; last update took {after_time - before_time} seconds")

        last_exchange_rounds = exchange_rounds


socketio.start_background_task(broadcast_current_round)


@app.after_request
def after_request(response):
    header = response.headers
    header['Access-Control-Allow-Origin'] = FRONTEND_URL
    header['Access-Control-Allow-Credentials'] = 'true'
    header['Access-Control-Allow-Headers'] = 'Origin, X-Requested-With, Content-Type, Accept'
    header['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS, DELETE, PATCH'
    header['Access-Control-Max-Age'] = '86400'  # cache this for up to 24 hours, useful for avoiding pre-flight requests

    return response


# use X-Forwarded-For and X-Forwarded-Host header values for request.remote_addr instead of the actual remote address
# NOTE: this should not be used in prod if not behind a load balancer/reverse proxy, since otherwise arbitrary users can manipulate the value of `request.remote_addr` (that said, we shouldn't rely on the value of `request.remote_addr` for anything important anyways)
app = ProxyFix(app, x_for=1, x_host=1)
