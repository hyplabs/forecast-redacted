# echo "ERROR: PLEASE ENTER CREDENTIALS IN config.sh, THEN COMMENT OUT THIS LINE" && exit 1

export TWILIO_ACCOUNT_SID=''
export TWILIO_AUTH_TOKEN=''
export TWILIO_FROM_PHONE_NUMBER='+11234567890'
export SENDGRID_API_KEY=''
export SENDGRID_FROM_EMAIL='support@forecast.example.com'
export FRONTEND_URL='http://localhost:3000'
export ADMIN_URL='http://localhost:8888'
export ADMIN_USERS='[{"credential_id":"TODO","id":"TODO","public_key":"TODO","username":"az","password_hash":"pbkdf2:sha256:150000$qx6GHWmj$40792e8a653049ba04f9969479ecbf7249ccfdf16e8183e91a104b50dca9d530"}]' # JSON value, array of dicts printed by going through the "Register" flow in the admin Yubikey Login page
