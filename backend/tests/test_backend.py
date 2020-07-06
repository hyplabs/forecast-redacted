import pytest
from werkzeug.security import check_password_hash
from datetime import datetime, timedelta

from models import db, User, Exchange, TransactionStatus, TransactionType, RoundStatus, Round, BetType, Bet, TicketStatus
from server import app, socketio, limiter, FREE_WITHDRAWALS_PER_30_DAYS, DAILY_WITHDRAWAL_LIMIT, BET_CUT_PERCENT
from tests.fixtures import *


@pytest.fixture
def client():
    app.config['TESTING'] = True
    limiter.reset()  # reset all rate limits
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.session.remove()
            db.drop_all()


def test_login_flow(client, user):
    r = client.post("/api/login", json={"username": "a", "password": "pass", "secondary_password": "1234"})
    assert r.json['status'] == 'success'
    assert r.json['user']['email'] == 'a@a'


def test_logout(client, user):
    login = client.post("/api/login", json={"username": "a", "password": "pass", "secondary_password": "1234"})
    cookies = login.headers['set-cookie']
    r = client.post("/api/logout", headers={'Cookie': cookies})
    assert r.json['status'] == 'success'


def test_get_profile(client, user):
    login = client.post("/api/login", json={"username": "a", "password": "pass", "secondary_password": "1234"})
    cookies = login.headers['set-cookie']
    r = client.get("/api/me", headers={'Cookie': cookies})
    assert r.json['status'] == 'success'
    assert r.json['user']['email'] == 'a@a'


def test_edit_profile(client, user):
    login = client.post("/api/login", json={"username": "a", "password": "pass", "secondary_password": "1234"})
    cookies = login.headers['set-cookie']

    # no changes
    r = client.patch('/api/me', headers={'Cookie': cookies}, json={'new_password': '', 'new_secondary_password': ''})
    assert r.json['status'] == 'success'
    assert r.json['user']['email'] == 'a@a'
    user = User.query.filter_by(id=user.id).first()
    assert check_password_hash(user.password_hash, 'pass')
    assert check_password_hash(user.secondary_password_hash, '1234')

    # attempt to change password
    r = client.patch('/api/me', headers={'Cookie': cookies}, json={'new_password': 'asdf', 'new_secondary_password': ''})
    assert r.json['status'] == 'success'
    user = User.query.filter_by(id=user.id).first()
    assert check_password_hash(user.password_hash, 'asdf')
    assert check_password_hash(user.secondary_password_hash, '1234')

    # attempt to change secondary password
    r = client.patch('/api/me', headers={'Cookie': cookies}, json={'new_password': '', 'new_secondary_password': '4321'})
    assert r.json['status'] == 'success'
    user = User.query.filter_by(id=user.id).first()
    assert check_password_hash(user.password_hash, 'asdf')
    assert check_password_hash(user.secondary_password_hash, '4321')


def test_get_user_transactions(client, user, transactions):
    login = client.post("/api/login", json={"username": "a", "password": "pass", "secondary_password": "1234"})
    cookies = login.headers['set-cookie']
    r = client.get('/api/me/transactions', headers={'Cookie': cookies})
    assert r.json['status'] == 'success'
    assert r.json['transactions'] == transactions


def test_create_deposit(client, user):
    login = client.post("/api/login", json={"username": "a", "password": "pass", "secondary_password": "1234"})
    cookies = login.headers['set-cookie']
    r = client.post('/api/me/transactions/deposits', headers={'Cookie': cookies}, json={'amount': 10000})
    assert r.json['status'] == 'success'
    assert r.json['transaction']['user_id'] == user.id
    assert r.json['transaction']['amount'] == 10000
    assert r.json['transaction']['status'] == TransactionStatus.PENDING.value
    assert r.json['transaction']['transaction_type'] == TransactionType.DEPOSIT.value


def test_create_withdrawal(client, user, otp_hash):
    login = client.post("/api/login", json={"username": "a", "password": "pass", "secondary_password": "1234"})
    cookies = login.headers['set-cookie']

    # need sms verification first
    user = User.query.filter_by(id=user.id).first()
    user.phone.confirm_otp_hash = otp_hash
    user.phone.confirm_otp_hash_expiry = datetime.utcnow() + timedelta(minutes=5)

    r = client.post('/api/me/transactions/withdrawals', headers={'Cookie': cookies}, json={'amount': 5000, 'otp': '1'})
    assert r.json['status'] == 'success'
    assert r.json['transaction']['user_id'] == user.id
    assert r.json['transaction']['amount'] == 5000
    assert r.json['transaction']['status'] == TransactionStatus.PENDING.value
    assert r.json['transaction']['transaction_type'] == TransactionType.WITHDRAWAL.value


def test_create_withdrawal_insufficient_funds(client, user, otp_hash):
    login = client.post("/api/login", json={"username": "a", "password": "pass", "secondary_password": "1234"})
    cookies = login.headers['set-cookie']

    for i in range(FREE_WITHDRAWALS_PER_30_DAYS):
        # need sms verification first
        user = User.query.filter_by(id=user.id).first()
        user.phone.confirm_otp_hash = otp_hash
        user.phone.confirm_otp_hash_expiry = datetime.utcnow() + timedelta(minutes=5)

        r = client.post('/api/me/transactions/withdrawals', headers={'Cookie': cookies}, json={'amount': 0, 'otp': '1'})
        assert r.json['status'] == 'success'
        assert r.json['transaction']['user_id'] == user.id
        assert r.json['transaction']['amount'] == 0
        assert r.json['transaction']['status'] == TransactionStatus.PENDING.value
        assert r.json['transaction']['transaction_type'] == TransactionType.WITHDRAWAL.value

    # need sms verification first
    user = User.query.filter_by(id=user.id).first()
    user.phone.confirm_otp_hash = otp_hash
    user.phone.confirm_otp_hash_expiry = datetime.utcnow() + timedelta(minutes=5)

    r = client.post('/api/me/transactions/withdrawals', headers={'Cookie': cookies}, json={'amount': user.balance, 'otp': '1'})
    assert r.json['status'] == 'failure'
    assert r.json['error'] == 'Insufficient funds'


def test_create_withdraw_over_max(client, user, otp_hash):
    login = client.post("/api/login", json={"username": "a", "password": "pass", "secondary_password": "1234"})
    cookies = login.headers['set-cookie']

    # need sms verification first
    user = User.query.filter_by(id=user.id).first()
    user.phone.confirm_otp_hash = otp_hash
    user.phone.confirm_otp_hash_expiry = datetime.utcnow() + timedelta(minutes=5)

    r = client.post('/api/me/transactions/withdrawals', headers={'Cookie': cookies}, json={'amount': DAILY_WITHDRAWAL_LIMIT + 5000, 'otp': '1'})
    assert r.json['status'] == 'failure'
    assert r.json['error'] == 'Daily withdrawal limit reached.'


def test_username_check(client, user):
    r = client.post('/api/register/check', json={'username': 'a'})
    assert r.json['status'] == 'failure'
    r = client.post('/api/register/check', json={'username': 'b'})
    assert r.json['status'] == 'success'


def test_socketio_connect(client, user, round_1_5sec):
    r = client.post("/api/login", json={"username": "a", "password": "pass", "secondary_password": "1234"})
    cookies = r.headers['set-cookie']

    sio = socketio.test_client(app, headers={'Cookie': cookies})
    assert sio.is_connected()
    assert sio.get_received() == []
    sio.disconnect()


def test_rate_limiter_authorized(client, user, user_2):
    r1 = client.post("/api/login", json={"username": "a", "password": "pass", "secondary_password": "1234"})
    user_1_cookies = r1.headers['set-cookie']

    resp_statuses_1 = []
    for i in range(0, 76):
        c = client.get("/api/ping", headers={'Cookie': user_1_cookies})
        resp_statuses_1.append(c.status)

    # assert that rate limiting for first user is correct
    assert all(code == '200 OK' for code in resp_statuses_1[:75])
    assert resp_statuses_1[75] == '429 TOO MANY REQUESTS'

    # For some reason I need to log in with the second user here, or the first
    # batch of requests goes through as though the second user executed them.
    r2 = client.post("/api/login", json={"username": "b", "password": "pass", "secondary_password": "1234"})
    user_2_cookies = r2.headers['set-cookie']

    resp_statuses_2 = []
    for j in range(0, 76):
        c = client.get("/api/ping", headers={'Cookie': user_2_cookies})
        resp_statuses_2.append(c.status)

    # assert that rate limiting for second user is independent of first user
    assert all(code == '200 OK' for code in resp_statuses_2[:75])
    assert resp_statuses_2[75] == '429 TOO MANY REQUESTS'


def test_rate_limiter_anonymous(client, user):
    resp_statuses_anonymous = []
    for i in range(0, 76):
        c = client.get('/api/ping')
        resp_statuses_anonymous.append(c.status)

    # assert that rate limiting for anonymous users is correct (done by IP)
    assert all(code == '200 OK' for code in resp_statuses_anonymous[:75])
    assert resp_statuses_anonymous[75] == '429 TOO MANY REQUESTS'

    # authorize a user to test that endpoints for users function independently
    # of anonymous users.
    r = client.post("/api/login", json={"username": "a", "password": "pass", "secondary_password": "1234"})
    cookies = r.headers['set-cookie']

    resp_statuses_authorized = []
    for j in range(0, 76):
        c = client.get("/api/ping", headers={'Cookie': cookies})
        resp_statuses_authorized.append(c.status)

    # assert that rate limiting for user is independent of anonymous users
    assert all(code == '200 OK' for code in resp_statuses_authorized[:75])
    assert resp_statuses_authorized[75] == '429 TOO MANY REQUESTS'


def test_create_bet(
    client,
    user,
    exchange_5sec,
    round_1_5sec,
):
    r = client.post("/api/login", json={"username": "a", "password": "pass", "secondary_password": "1234"})
    cookies = r.headers['set-cookie']

    bet_amount = 100000
    original_user_balance = user.balance
    req = client.post("/api/me/bet", headers={'Cookie': cookies}, json={
        "exchange_id": exchange_5sec.id,
        "bet_type": BetType.RISE.value,
        "amount": bet_amount,
    })
    r = req.json
    assert r['status'] == 'success'
    assert 'id' in r['bet']
    assert r['bet']['round']['id'] == round_1_5sec.id
    assert r['bet']['bet_type'] == BetType.RISE.value
    assert r['bet']['amount'] == bet_amount
    assert r['bet']['commission'] == bet_amount * 0.1

    # check that balance has been updated
    user = User.query.filter_by(id=user.id).first()
    assert user.balance == original_user_balance - bet_amount - (bet_amount * BET_CUT_PERCENT)


def test_create_bet_over_limit(
    client,
    user,
    exchange_5sec,
    round_1_5sec,
):
    r = client.post("/api/login", json={"username": "a", "password": "pass", "secondary_password": "1234"})
    cookies = r.headers['set-cookie']

    req = client.post("/api/me/bet", headers={'Cookie': cookies}, json={
        "exchange_id": exchange_5sec.id,
        "bet_type": BetType.RISE.value,
        "amount": exchange_5sec.max_bet_amount + 500000,
    })
    r = req.json
    assert r['status'] == 'failure'
    assert r['error'] == f'Bet cannot exceed max amount of {exchange_5sec.max_bet_amount} for this exchange.'


def test_create_bet_insufficient_balance(
    client,
    user,
    exchange_5sec,
    round_1_5sec,
):
    r = client.post("/api/login", json={"username": "a", "password": "pass", "secondary_password": "1234"})
    cookies = r.headers['set-cookie']

    req = client.post("/api/me/bet", headers={'Cookie': cookies}, json={
        "exchange_id": exchange_5sec.id,
        "bet_type": BetType.RISE.value,
        "amount": 950000,
    })
    r = req.json
    assert r['status'] == 'failure'
    assert r['error'] == 'Cannot bet more money than is in user balance.'


def test_create_bet_reached_max_lots(
    client,
    exchange_with_max_lots,
    round_with_max_lots,
    user,
    user_2,
):
    r1 = client.post("/api/login", json={"username": "a", "password": "pass", "secondary_password": "1234"})
    user_1_cookies = r1.headers['set-cookie']

    # user 1 creates 1 lot RISE bet (reaches max of 1 lot for RISE bets for this round)
    req = client.post("/api/me/bet", headers={'Cookie': user_1_cookies}, json={
        "exchange_id": exchange_with_max_lots.id,
        "bet_type": BetType.RISE.value,
        "amount": 100000,
    })
    r = req.json
    assert r['status'] == 'success'

    r2 = client.post("/api/login", json={"username": "b", "password": "pass", "secondary_password": "1234"})
    user_2_cookies = r2.headers['set-cookie']

    # user 2 attempts to create 1 lot RISE bet, fails
    req = client.post("/api/me/bet", headers={'Cookie': user_2_cookies}, json={
        "exchange_id": exchange_with_max_lots.id,
        "bet_type": BetType.RISE.value,
        "amount": 100000,
    })
    r = req.json
    assert r['status'] == 'failure'
    assert r['message'] == 'Maximum number of RISE bets reached for this round.'

    # user 2 creates 1 lot FALL bet, succeeds (reaches max of 1 lot for FALL bets for this round)
    req = client.post("/api/me/bet", headers={'Cookie': user_2_cookies}, json={
        "exchange_id": exchange_with_max_lots.id,
        "bet_type": BetType.FALL.value,
        "amount": 100000,
    })
    r = req.json
    assert r['status'] == 'success'


def test_create_support_ticket(
    client,
    user,
):
    r = client.post("/api/login", json={"username": "a", "password": "pass", "secondary_password": "1234"})
    cookies = r.headers['set-cookie']

    req = client.post("/api/me/tickets", headers={'Cookie': cookies}, json={
        "subject": "test ticket",
        "message": "test message"
    })

    r = req.json
    assert r['status'] == 'success'
    assert r['ticket'] is not None
    assert r['ticket']['user_id'] == user.id
    assert r['ticket']['subject'] == "test ticket"
    assert r['ticket']['status'] == TicketStatus.OPEN.value
    assert r['ticket']['user_message'] == "test message"


def test_list_announcements(
    client,
    announcements,
):
    req = client.get("/api/announcements/1")
    r = req.json
    assert r['status'] == 'success'
    assert r['announcements'] is not None
    assert len(r['announcements']) == len(announcements)


def test_get_announcement(
    client,
    announcements,
):
    req = client.get(f'/api/announcement/{announcements[0]["id"]}')
    r = req.json
    assert r['status'] == 'success'
    assert r['announcement'] is not None
    assert r['announcement']['id'] == announcements[0]['id']

    # check that view count has incremented from saved view count
    assert r['announcement']['view_count'] == announcements[0]['view_count'] + 1