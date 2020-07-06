#!/usr/bin/env bash

USERNAME="tester1"
PHONE="+15555555555"
EMAIL="test@gmail.com"
OTHER_EMAIL="other_test@gmail.com"
HOST="http://localhost:5000"
# HOST="https://api.forecast.example.com"

# registration flow
echo 'Verifying phone number'
curl -X POST $HOST/api/send_sms_verification -H 'Content-Type: application/json' -d '{"phone": "'$PHONE'"}'
read -p "SMS code: " SMS_CODE
curl -X POST $HOST/api/verify_phone -H 'Content-Type: application/json' -d '{"phone": "'$PHONE'", "otp": "'$SMS_CODE'"}'
echo 'Check username'
curl -X POST $HOST/api/register/check -H 'Content-Type: application/json' -d '{"username": "'$USERNAME'"}'
echo 'Register with the verified phone number and verify email'
curl -X POST $HOST/api/register -H 'Content-Type: application/json' -d '{"email": "'$EMAIL'", "username": "'$USERNAME'", "phone": "'$PHONE'", "password": "test123", "bank_name": "BANKBANK", "bank_account_number": "BANKNUMBER"}'
read -p "SMS secondary password: " SECONDARY_PASSWORD
read -p "Email verification token: " EMAIL_VERIFICATION_TOKEN
curl $HOST/api/verify_email/$EMAIL_VERIFICATION_TOKEN
echo 'Reset password'
curl -X POST $HOST/api/login/forgot -H 'Content-Type: application/json' -d '{"email": "'$EMAIL'"}'
read -p "Email verification token: " EMAIL_VERIFICATION_TOKEN
curl -X POST $HOST/api/reset_password -H 'Content-Type: application/json' -d '{"email": "'$EMAIL'", "reset_code": "'$EMAIL_VERIFICATION_TOKEN'", "new_password": "test456"}'
echo 'Login with reset password'
curl -X POST $HOST/api/login -H 'Content-Type: application/json' -d '{"username": "'$USERNAME'", "password": "test456", "secondary_password": "'$SECONDARY_PASSWORD'"}' -c cookies.txt

# login/logout flow
echo 'Profile when logged in'
curl $HOST/api/me -b cookies.txt | jq
echo 'Log out'
curl -X POST $HOST/api/logout -b cookies.txt -c cookies.txt
echo 'Profile when logged out'
curl $HOST/api/me -b cookies.txt | jq
echo 'Log back in'
curl -X POST $HOST/api/login -H 'Content-Type: application/json' -d '{"username": "'$USERNAME'", "password": "test456", "secondary_password": "'$SECONDARY_PASSWORD'"}' -c cookies.txt

# edit profile flow
echo 'Change email and password and verify email again'
curl -X PATCH $HOST/api/me -H 'Content-Type: application/json' -d '{"email": "'$OTHER_EMAIL'", "password": "test456", "new_password": "test789"}' -b cookies.txt | jq
read -p "Email verification token: " EMAIL_VERIFICATION_TOKEN
curl $HOST/api/verify_email/$EMAIL_VERIFICATION_TOKEN
echo 'Log in again with new password'
curl -X POST $HOST/api/login -H 'Content-Type: application/json' -d '{"username": "'$USERNAME'", "password": "test789", "secondary_password": "'$SECONDARY_PASSWORD'"}' -c cookies.txt

# create/read transactions
echo 'Creating deposit and withdrawal'
curl -X POST $HOST/api/me/transactions/deposits -H 'Content-Type: application/json' -d '{"amount": 1000000}' -b cookies.txt
curl -X POST $HOST/api/me/transactions/withdrawals -H 'Content-Type: application/json' -d '{"amount": 500000}' -b cookies.txt
echo 'Listing all deposits and withdrawals'
curl $HOST/api/me/transactions -b cookies.txt | jq

# get user to update balance
read -p 'Use `make enter_db` to run the SQL `update "user" set balance = 1000000 where username = '"'$USERNAME'"';`, then press enter: '

# create/read/update/delete bets
EXCHANGE_ID=$(curl $HOST/api/exchange -b cookies.txt | jq '.exchanges[0].id')
echo 'Bet on current betting round'
curl -X POST $HOST/api/me/bet -H 'Content-Type: application/json' -d '{"exchange_id": '$EXCHANGE_ID', "bet_type": "RISE", "amount": 5000}' -b cookies.txt | jq
echo 'Update bet on current betting round'
curl -X POST $HOST/api/me/bet -H 'Content-Type: application/json' -d '{"exchange_id": '$EXCHANGE_ID', "bet_type": "RISE", "amount": 12345}' -b cookies.txt | jq

# get bets
echo 'Get bets'
curl $HOST/api/bet -b cookies.txt | jq

# get exchanges
echo 'Get exchanges'
curl $HOST/api/exchange -b cookies.txt | jq

# get rounds
echo 'Get current betting round'
curl $HOST/api/round -b cookies.txt | jq '.rounds[0]'

rm cookies.txt
