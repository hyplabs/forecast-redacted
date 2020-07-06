from datetime import datetime, date

import pytest
from werkzeug.security import generate_password_hash

from models import (
    db, PhoneNumber, User, Transaction,
    TransactionType, TransactionStatus, Exchange,
    RoundStatus, Round, BetType, BetResult, Bet, Announcement,
    UserRole
)  # noqa: E402
from util import generate_uuid, generate_otp_hash


@pytest.fixture
def otp_hash():
    otp_hash = generate_otp_hash('1')
    yield otp_hash

@pytest.fixture
def phone_number():
    new_phone_number = PhoneNumber(phone="+15555555555", verified=True)
    db.session.add(new_phone_number)
    db.session.commit()
    yield new_phone_number


@pytest.fixture
def phone_number_2():
    new_phone_number_2 = PhoneNumber(phone="+15555555556", verified=True)
    db.session.add(new_phone_number_2)
    db.session.commit()
    yield new_phone_number_2

@pytest.fixture
def phone_number_sd():
    phone_number_sd = PhoneNumber(phone="+16555555556", verified=True)
    db.session.add(phone_number_sd)
    db.session.commit()
    yield phone_number_sd

@pytest.fixture
def phone_number_b():
    phone_number_b = PhoneNumber(phone="+16555555557", verified=True)
    db.session.add(phone_number_b)
    db.session.commit()
    yield phone_number_b

@pytest.fixture
def phone_number_f():
    phone_number_f = PhoneNumber(phone="+16555555558", verified=True)
    db.session.add(phone_number_f)
    db.session.commit()
    yield phone_number_f

@pytest.fixture
def phone_number_ru():
    phone_number_ru = PhoneNumber(phone="+16555555559", verified=True)
    db.session.add(phone_number_ru)
    db.session.commit()
    yield phone_number_ru

@pytest.fixture
def user(phone_number):
    new_user = User(
        uuid=generate_uuid(),
        email='a@a',
        email_confirmed=True,
        username='a',
        name='bob',
        dob='1/1/1991',
        password_hash=generate_password_hash('pass'),
        secondary_password_hash=generate_password_hash('1234'),
        is_suspended=False,
        phone_id=phone_number.id,
        bank_name='bankbankbank',
        bank_account_number='123-456',
        bank_account_holder='bob',
        balance=1000000,
        pending_commissions=0,
        payable_commissions=0,
        created_at=datetime(2000, 1, 1, 0, 5, 10),
        role=UserRole.HQ,
        partner_name="partner bob",
        partner_referral_code="test123",
    )
    db.session.add(new_user)
    db.session.commit()
    yield new_user


@pytest.fixture
def user_2(phone_number_2):
    new_user_2 = User(
        uuid=generate_uuid(),
        email='b@b',
        email_confirmed=True,
        username='b',
        name='bob',
        dob='1/1/1991',
        password_hash=generate_password_hash('pass'),
        secondary_password_hash=generate_password_hash('1234'),
        is_suspended=False,
        phone_id=phone_number_2.id,
        bank_name='bonk',
        bank_account_number='654-321',
        bank_account_holder='bob',
        balance=1000000,
        pending_commissions=0,
        payable_commissions=0,
        created_at=datetime(2000, 1, 1, 0, 5, 10),
        role=UserRole.REGULAR_USER,
    )
    db.session.add(new_user_2)
    db.session.commit()
    yield new_user_2

@pytest.fixture
def user_sd(phone_number_sd, user_1):
    u = User(
        uuid=generate_uuid(),
        email='sd@sd',
        email_confirmed=True,
        username='sd',
        name='sdsd',
        dob='1/1/1991',
        password_hash=generate_password_hash('pass'),
        secondary_password_hash=generate_password_hash('1234'),
        is_suspended=False,
        referring_user_id=user_1.id,
        phone_id=phone_number_sd.id,
        bank_name='sdbonk',
        bank_account_number='654-321',
        bank_account_holder='sd',
        balance=1000000,
        pending_commissions=0,
        payable_commissions=0,
        created_at=datetime(2000, 1, 1, 0, 5, 10),
        role=UserRole.SOLE_DISTRIBUTOR,
    )
    db.session.add(user_sd)
    db.session.commit()
    yield user_sd

@pytest.fixture
def user_b(phone_number_b, user_sd):
    u = User(
        uuid=generate_uuid(),
        email='b@b',
        email_confirmed=True,
        username='b',
        name='bb',
        dob='1/1/1991',
        password_hash=generate_password_hash('pass'),
        secondary_password_hash=generate_password_hash('1234'),
        is_suspended=False,
        referring_user_id=user_sd.id,
        phone_id=phone_number_b.id,
        bank_name='bbonk',
        bank_account_number='654-321',
        bank_account_holder='b',
        balance=1000000,
        pending_commissions=0,
        payable_commissions=0,
        created_at=datetime(2000, 1, 1, 0, 5, 10),
        role=UserRole.PARTNER,
    )
    db.session.add(user_b)
    db.session.commit()
    yield user_b


@pytest.fixture
def user_f(phone_number_f, user_b):
    u = User(
        uuid=generate_uuid(),
        email='f@f',
        email_confirmed=True,
        username='f',
        name='ff',
        dob='1/1/1991',
        password_hash=generate_password_hash('pass'),
        secondary_password_hash=generate_password_hash('1234'),
        is_suspended=False,
        referring_user_id=user_b.id,
        phone_id=phone_number_f.id,
        bank_name='fbonk',
        bank_account_number='654-321',
        bank_account_holder='f',
        balance=1000000,
        pending_commissions=0,
        payable_commissions=0,
        created_at=datetime(2000, 1, 1, 0, 5, 10),
        role=UserRole.FRANCHISEE,
    )
    db.session.add(user_f)
    db.session.commit()
    yield user_f


@pytest.fixture
def user_ru(phone_number_ru, user_f):
    u = User(
        uuid=generate_uuid(),
        email='ru@ru',
        email_confirmed=True,
        username='ru',
        name='ruru',
        dob='1/1/1991',
        password_hash=generate_password_hash('pass'),
        secondary_password_hash=generate_password_hash('1234'),
        is_suspended=False,
        referring_user_id=user_f.id,
        phone_id=phone_number_ru.id,
        bank_name='rubonk',
        bank_account_number='654-321',
        bank_account_holder='ru',
        balance=1000000,
        pending_commissions=0,
        payable_commissions=0,
        created_at=datetime(2000, 1, 1, 0, 5, 10),
        role=UserRole.REGULAR_USER,
    )
    db.session.add(user_ru)
    db.session.commit()
    yield user_ru

@pytest.fixture
def transactions(user):
    transaction1 = Transaction(
        user_id=user.id,
        transaction_type=TransactionType.WITHDRAWAL,
        amount=5000,
        status=TransactionStatus.PENDING,
        notes='Legit transaction',
        created_at=datetime(2000, 2, 1, 0, 5, 10),
    )
    transaction2 = Transaction(
        user_id=user.id,
        transaction_type=TransactionType.DEPOSIT,
        amount=10000,
        status=TransactionStatus.COMPLETE,
        notes='Legit transaction',
        created_at=datetime(2000, 1, 1, 0, 5, 10),
    )
    db.session.add(transaction1)
    db.session.add(transaction2)
    db.session.commit()
    yield [transaction1.to_json(), transaction2.to_json()]


@pytest.fixture
def exchange_3sec():
    new_exchange = Exchange(
        name="BTC/USD",
        description="BTC price in USD, 3 seconds to bet, 3 to wait",
        bet_and_lock_seconds=3,
        max_spin_seconds=3,
        round_decided_threshold=2,
        max_bet_amount=1000000,
    )
    db.session.add(new_exchange)
    db.session.commit()
    yield new_exchange


@pytest.fixture
def exchange_5sec():
    new_exchange = Exchange(
        name="ETH/USD",
        description="ETH price in USD, 5 seconds to bet, 5 to wait",
        bet_and_lock_seconds=5,
        max_spin_seconds=5,
        round_decided_threshold=2,
        max_bet_amount=1000000,
    )
    db.session.add(new_exchange)
    db.session.commit()
    yield new_exchange


@pytest.fixture
def exchange_with_max_lots():
    new_exchange = Exchange(
        name="BTC/USD",
        description="BTC price in USD, 5 seconds to bet, 5 to wait",
        bet_and_lock_seconds=5,
        max_spin_seconds=5,
        round_decided_threshold=2,
        max_bet_amount=1000000,
    )
    db.session.add(new_exchange)
    db.session.commit()
    yield new_exchange


@pytest.fixture
def round_with_max_lots(exchange_with_max_lots):
    new_round = Round(
        round_date=date(2000, 1, 1),
        round_number=27,
        exchange_id=exchange_with_max_lots.id,
        max_rise_bets_amount=100000,
        max_fall_bets_amount=100000,
        start_time=datetime(2000, 1, 1, 0, 5, 10),
        lock_in_bets_time=datetime(2000, 1, 1, 0, 5, 12),
        spinning_start_time=datetime(2000, 1, 1, 0, 5, 15),
        end_time=datetime(2000, 1, 1, 0, 5, 20),
        round_status=RoundStatus.BETTING,
        created_at=datetime(2000, 1, 1, 0, 5, 10),
        updated_at=datetime(2000, 1, 1, 0, 5, 10),
    )
    db.session.add(new_round)
    db.session.commit()
    yield new_round


@pytest.fixture
def round_1_5sec(exchange_5sec):
    new_round = Round(
        round_date=date(2000, 1, 1),
        round_number=27,
        exchange_id=exchange_5sec.id,
        start_time=datetime(2000, 1, 1, 0, 5, 10),
        lock_in_bets_time=datetime(2000, 1, 1, 0, 5, 12),
        spinning_start_time=datetime(2000, 1, 1, 0, 5, 15),
        end_time=datetime(2000, 1, 1, 0, 5, 20),
        round_status=RoundStatus.BETTING,
        created_at=datetime(2000, 1, 1, 0, 5, 10),
        updated_at=datetime(2000, 1, 1, 0, 5, 10),
    )
    db.session.add(new_round)
    db.session.commit()
    yield new_round


@pytest.fixture
def round_2_5sec(exchange_5sec):
    new_round = Round(
        round_date=date(2000, 1, 1),
        round_number=28,
        exchange_id=exchange_5sec.id,
        start_time=datetime(2000, 1, 1, 0, 5, 15),
        lock_in_bets_time=datetime(2000, 1, 1, 0, 5, 17),
        spinning_start_time=datetime(2000, 1, 1, 0, 5, 20),
        end_time=datetime(2000, 1, 1, 0, 5, 25),
        round_status=RoundStatus.SPINNING,
        created_at=datetime(2000, 1, 1, 0, 5, 15),
        updated_at=datetime(2000, 1, 1, 0, 5, 15),
    )
    db.session.add(new_round)
    db.session.commit()
    yield new_round


@pytest.fixture
def bet_1_5sec(user, exchange_5sec, round_1_5sec):
    new_bet = Bet(
        user_id=user.id,
        round_id=round_1_5sec.id,
        bet_type=BetType.FALL,
        bet_result=BetResult.PENDING,
        amount=1000000,
        commission=100000,
        created_at=datetime(2000, 1, 1, 0, 5, 10),
    )
    db.session.add(new_bet)
    db.session.commit()
    yield new_bet


@pytest.fixture
def bet_2_5sec(user, exchange_5sec, round_2_5sec):
    new_bet = Bet(
        user_id=user.id,
        round_id=round_2_5sec.id,
        bet_type=BetType.RISE,
        bet_result=BetResult.PENDING,
        amount=1000000,
        commission=100000,
        created_at=datetime(2000, 1, 1, 0, 5, 15),
    )
    db.session.add(new_bet)
    db.session.commit()
    yield new_bet


@pytest.fixture
def announcements():
    announcement1 = Announcement(
        title="Testing 1",
        content="test test 1",
        view_count=0,
        created_at=datetime(2000, 1, 1, 0, 5, 15),
        updated_at=datetime(2000, 1, 1, 0, 5, 15),
    )
    announcement2 = Announcement(
        title="Testing 2",
        content="test test 2",
        view_count=0,
        created_at=datetime(2000, 1, 1, 0, 5, 20),
        updated_at=datetime(2000, 1, 1, 0, 5, 20),
    )
    db.session.add(announcement1)
    db.session.add(announcement2)
    db.session.commit()
    yield [announcement1.to_json(), announcement2.to_json()]
