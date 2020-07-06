import hashlib
import secrets
import uuid

from werkzeug.security import generate_password_hash, check_password_hash

OTP_LENGTH = 6  # 6 digit code for SMS verification
SECONDARY_PASSWORD_LENGTH = 4  # 4 digit secondary password


def generate_otp_hash(value):
    # 5000000 iterations was chosen to defeat brute-force attack in combination with rate limiting on the OTP-checking endpoints
    return generate_password_hash(value, method="pbkdf2:sha256:5000000")


def check_otp_hash(otp_hash, value):
    return check_password_hash(otp_hash, value)


def generate_otp():
    return ''.join(str(secrets.randbelow(10)) for _ in range(OTP_LENGTH))


def generate_verification_code():
    return secrets.token_hex(16)


def generate_uuid():
    return str(uuid.uuid4())


def generate_secondary_password():
    return ''.join(str(secrets.randbelow(10)) for _ in range(SECONDARY_PASSWORD_LENGTH))
