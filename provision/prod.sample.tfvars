aws_access_key_id="TODO"
aws_secret_access_key="TODO"
aws_region="us-east-2"

bastion_ssh_pubkey = "TODO"

backend_image_port = 5000
backend_image_healthcheck_path = "/api/healthcheck"
backend_cpu = 512
backend_memory = 1024

admin_image_port = 4000
admin_image_healthcheck_path = "/api/healthcheck"

num_availability_zones = 2

db_master_password = "TODO"

# app configuration
FLASK_SECRET_KEY = "TODO"
TWILIO_ACCOUNT_SID = "TODO"
TWILIO_AUTH_TOKEN = "TODO"
TWILIO_FROM_PHONE_NUMBER = "TODO"
SENDGRID_API_KEY = "TODO"
SENDGRID_FROM_EMAIL = "support@forecast.example.com"
FRONTEND_URL = "https://forecast.example.com"
ADMIN_URL = "https://admin.forecast.example.com"
ADMIN_FLASK_SECRET_KEY = "TODO"
ADMIN_USERS = "[{\"credential_id\":\"TODO\",\"id\":\"TODO\",\"public_key\":\"TODO\",\"username\":\"az\",\"password_hash\":\"pbkdf2:sha256:150000$qx6GHWmj$40792e8a653049ba04f9969479ecbf7249ccfdf16e8183e91a104b50dca9d530\"}]" # JSON value, array of dicts printed by going through the "Register" flow in the admin Yubikey Login page
