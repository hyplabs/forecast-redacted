from datetime import datetime
from unittest import mock

import pytest

from models import db, User, RoundStatus, Round, BetType, Bet, MAX_BETTING_AMOUNT_PER_ROUND
from tests.fixtures import *

import price_updater

@pytest.fixture(autouse=True)
def db_session():
    db.create_all()
    yield
    db.session.remove()
    db.drop_all()


def test_no_rounds(exchange_3sec, exchange_5sec):
    with mock.patch('price_updater.datetime', mock.Mock(utcnow=lambda: datetime(2000, 1, 1, 0, 5, 11))), \
         mock.patch.object(price_updater, "get_median_btc_spot_price", return_value=5000):
        price_updater.run_update()
    assert [r.to_json() for r in Round.query.order_by(Round.created_at.asc()).all()] == [
        {
            'created_at': mock.ANY,
            'end_price': None,
            'end_time': '2000-01-01T00:05:17+00:00',
            'exchange': exchange_3sec.to_json(),
            'id': 1,
            'lock_in_bets_time': '2000-01-01T00:05:11+00:00',
            'spinning_start_time': '2000-01-01T00:05:14+00:00',
            'round_date': '2000-01-01',
            'round_number': 103,
            'round_result': None,
            'round_result_decided_time': None,
            'round_result_decided_price': None,
            'round_status': 'LOCKING_IN_BETS',
            'max_price': None,
            'min_price': None,
            'start_price': None,
            'start_time': '2000-01-01T00:05:11+00:00',
            'updated_at': mock.ANY,
            'fall_status_0_05_lot': 'ENABLED',
            'fall_status_0_1_lot': 'ENABLED',
            'fall_status_0_5_lot': 'ENABLED',
            'fall_status_10_lot': 'ENABLED',
            'fall_status_1_lot': 'ENABLED',
            'fall_status_5_lot': 'ENABLED',
            'rise_status_0_05_lot': 'ENABLED',
            'rise_status_0_1_lot': 'ENABLED',
            'rise_status_0_5_lot': 'ENABLED',
            'rise_status_10_lot': 'ENABLED',
            'rise_status_1_lot': 'ENABLED',
            'rise_status_5_lot': 'ENABLED',
            'max_fall_bets_amount': MAX_BETTING_AMOUNT_PER_ROUND,
            'max_rise_bets_amount': MAX_BETTING_AMOUNT_PER_ROUND,
            'total_fall_bets_amount': 0,
            'total_rise_bets_amount': 0,
        },
        {
            'created_at': mock.ANY,
            'end_price': None,
            'end_time': '2000-01-01T00:05:21+00:00',
            'exchange': exchange_5sec.to_json(),
            'id': 2,
            'lock_in_bets_time': '2000-01-01T00:05:13+00:00',
            'spinning_start_time': '2000-01-01T00:05:16+00:00',
            'round_date': '2000-01-01',
            'round_number': 62,
            'round_result': None,
            'round_result_decided_time': None,
            'round_result_decided_price': None,
            'round_status': 'BETTING',
            'max_price': None,
            'min_price': None,
            'start_price': None,
            'start_time': '2000-01-01T00:05:11+00:00',
            'updated_at': mock.ANY,
            'fall_status_0_05_lot': 'ENABLED',
            'fall_status_0_1_lot': 'ENABLED',
            'fall_status_0_5_lot': 'ENABLED',
            'fall_status_10_lot': 'ENABLED',
            'fall_status_1_lot': 'ENABLED',
            'fall_status_5_lot': 'ENABLED',
            'rise_status_0_05_lot': 'ENABLED',
            'rise_status_0_1_lot': 'ENABLED',
            'rise_status_0_5_lot': 'ENABLED',
            'rise_status_10_lot': 'ENABLED',
            'rise_status_1_lot': 'ENABLED',
            'rise_status_5_lot': 'ENABLED',
            'max_fall_bets_amount': MAX_BETTING_AMOUNT_PER_ROUND,
            'max_rise_bets_amount': MAX_BETTING_AMOUNT_PER_ROUND,
            'total_fall_bets_amount': 0,
            'total_rise_bets_amount': 0,
        },
    ]
    assert [b.to_json() for b in Bet.query.order_by(Bet.created_at.asc()).all()] == []
    assert [b.to_json() for b in User.query.order_by(User.created_at.asc()).all()] == []


def test_lock_in_bet(exchange_5sec, round_1_5sec, bet_1_5sec):
    with mock.patch('price_updater.datetime', mock.Mock(utcnow=lambda: datetime(2000, 1, 1, 0, 5, 16))), \
         mock.patch.object(price_updater, "get_median_btc_spot_price", return_value=5000):
        price_updater.run_update()
        price_updater.run_update()
    assert [r.to_json() for r in Round.query.order_by(Round.created_at.asc()).all()] == [
        {
            'created_at': mock.ANY,
            'end_price': 5000.0,
            'end_time': '2000-01-01T00:05:20+00:00',
            'exchange': exchange_5sec.to_json(),
            'id': 1,
            'lock_in_bets_time': '2000-01-01T00:05:12+00:00',
            'spinning_start_time': '2000-01-01T00:05:15+00:00',
            'round_date': '2000-01-01',
            'round_number': 27,
            'round_result': None,
            'round_result_decided_time': None,
            'round_result_decided_price': None,
            'round_status': 'SPINNING',
            'max_price': 5000.0,
            'min_price': 5000.0,
            'start_price': 5000.0,
            'start_time': '2000-01-01T00:05:10+00:00',
            'updated_at': mock.ANY,
            'fall_status_0_05_lot': 'ENABLED',
            'fall_status_0_1_lot': 'ENABLED',
            'fall_status_0_5_lot': 'ENABLED',
            'fall_status_10_lot': 'ENABLED',
            'fall_status_1_lot': 'ENABLED',
            'fall_status_5_lot': 'ENABLED',
            'rise_status_0_05_lot': 'ENABLED',
            'rise_status_0_1_lot': 'ENABLED',
            'rise_status_0_5_lot': 'ENABLED',
            'rise_status_10_lot': 'ENABLED',
            'rise_status_1_lot': 'ENABLED',
            'rise_status_5_lot': 'ENABLED',
            'max_fall_bets_amount': MAX_BETTING_AMOUNT_PER_ROUND,
            'max_rise_bets_amount': MAX_BETTING_AMOUNT_PER_ROUND,
            'total_fall_bets_amount': 0,
            'total_rise_bets_amount': 0,
        },
        {
            'created_at': mock.ANY,
            'end_price': None,
            'end_time': '2000-01-01T00:05:26+00:00',
            'exchange': exchange_5sec.to_json(),
            'id': 2,
            'lock_in_bets_time': '2000-01-01T00:05:18+00:00',
            'spinning_start_time': '2000-01-01T00:05:21+00:00',
            'round_date': '2000-01-01',
            'round_number': 63,
            'round_result': None,
            'round_result_decided_time': None,
            'round_result_decided_price': None,
            'round_status': 'BETTING',
            'max_price': None,
            'min_price': None,
            'start_price': None,
            'start_time': '2000-01-01T00:05:16+00:00',
            'updated_at': mock.ANY,
            'fall_status_0_05_lot': 'ENABLED',
            'fall_status_0_1_lot': 'ENABLED',
            'fall_status_0_5_lot': 'ENABLED',
            'fall_status_10_lot': 'ENABLED',
            'fall_status_1_lot': 'ENABLED',
            'fall_status_5_lot': 'ENABLED',
            'rise_status_0_05_lot': 'ENABLED',
            'rise_status_0_1_lot': 'ENABLED',
            'rise_status_0_5_lot': 'ENABLED',
            'rise_status_10_lot': 'ENABLED',
            'rise_status_1_lot': 'ENABLED',
            'rise_status_5_lot': 'ENABLED',
            'max_fall_bets_amount': MAX_BETTING_AMOUNT_PER_ROUND,
            'max_rise_bets_amount': MAX_BETTING_AMOUNT_PER_ROUND,
            'total_fall_bets_amount': 0,
            'total_rise_bets_amount': 0,
        }
    ]
    assert [b.to_json() for b in Bet.query.order_by(Bet.created_at.asc()).all()] == [
        {
            'amount': 1000000,
            'commission': 100000,
            'bet_type': 'FALL',
            'created_at': '2000-01-01T00:05:10+00:00',
            'id': 1,
            'round': mock.ANY,
            'updated_at': '2000-01-01T00:05:10+00:00'
        },

    ]


def test_direct_to_to_spinning(exchange_5sec, round_1_5sec, bet_1_5sec):
    with mock.patch('price_updater.datetime', mock.Mock(utcnow=lambda: datetime(2000, 1, 1, 0, 5, 16))), \
         mock.patch.object(price_updater, "get_median_btc_spot_price", return_value=5000):
        price_updater.run_update()
        price_updater.run_update()
    assert [r.to_json() for r in Round.query.order_by(Round.created_at.asc()).all()] == [
        {
            'created_at': mock.ANY,
            'updated_at': mock.ANY,
            'end_price': 5000.0,
            'end_time': '2000-01-01T00:05:20+00:00',
            'exchange': exchange_5sec.to_json(),
            'id': 1,
            'lock_in_bets_time': '2000-01-01T00:05:12+00:00',
            'spinning_start_time': '2000-01-01T00:05:15+00:00',
            'round_date': '2000-01-01',
            'round_number': 27,
            'round_result': None,
            'round_result_decided_time': None,
            'round_result_decided_price': None,
            'round_status': 'SPINNING',
            'max_price': 5000.0,
            'min_price': 5000.0,
            'start_price': 5000.0,
            'start_time': '2000-01-01T00:05:10+00:00',
            'fall_status_0_05_lot': 'ENABLED',
            'fall_status_0_1_lot': 'ENABLED',
            'fall_status_0_5_lot': 'ENABLED',
            'fall_status_10_lot': 'ENABLED',
            'fall_status_1_lot': 'ENABLED',
            'fall_status_5_lot': 'ENABLED',
            'max_fall_bets_amount': 10000000,
            'max_rise_bets_amount': 10000000,
            'rise_status_0_05_lot': 'ENABLED',
            'rise_status_0_1_lot': 'ENABLED',
            'rise_status_0_5_lot': 'ENABLED',
            'rise_status_10_lot': 'ENABLED',
            'rise_status_1_lot': 'ENABLED',
            'rise_status_5_lot': 'ENABLED',
            'total_fall_bets_amount': 0,
            'total_rise_bets_amount': 0,
        },
        {
            'created_at': mock.ANY,
            'updated_at': mock.ANY,
            'end_price': None,
            'end_time': '2000-01-01T00:05:26+00:00',
            'exchange': exchange_5sec.to_json(),
            'id': 2,
            'lock_in_bets_time': '2000-01-01T00:05:18+00:00',
            'spinning_start_time': '2000-01-01T00:05:21+00:00',
            'round_date': '2000-01-01',
            'round_number': 63,
            'round_result': None,
            'round_result_decided_time': None,
            'round_result_decided_price': None,
            'round_status': 'BETTING',
            'max_price': None,
            'min_price': None,
            'start_price': None,
            'start_time': '2000-01-01T00:05:16+00:00',
            'fall_status_0_05_lot': 'ENABLED',
            'fall_status_0_1_lot': 'ENABLED',
            'fall_status_0_5_lot': 'ENABLED',
            'fall_status_10_lot': 'ENABLED',
            'fall_status_1_lot': 'ENABLED',
            'fall_status_5_lot': 'ENABLED',
            'max_fall_bets_amount': 10000000,
            'max_rise_bets_amount': 10000000,
            'rise_status_0_05_lot': 'ENABLED',
            'rise_status_0_1_lot': 'ENABLED',
            'rise_status_0_5_lot': 'ENABLED',
            'rise_status_10_lot': 'ENABLED',
            'rise_status_1_lot': 'ENABLED',
            'rise_status_5_lot': 'ENABLED',
            'total_fall_bets_amount': 0,
            'total_rise_bets_amount': 0,
        }
    ]
    assert [b.to_json() for b in Bet.query.order_by(Bet.created_at.asc()).all()] == [
        {
            'amount': 1000000,
            'commission': 100000,
            'bet_type': 'FALL',
            'created_at': '2000-01-01T00:05:10+00:00',
            'id': 1,
            'round': {
                'created_at': mock.ANY,
                'end_price': 5000,
                'end_time': '2000-01-01T00:05:20+00:00',
                'exchange': exchange_5sec.to_json(),
                'id': 1,
                'lock_in_bets_time': '2000-01-01T00:05:12+00:00',
                'spinning_start_time': '2000-01-01T00:05:15+00:00',
                'round_date': '2000-01-01',
                'round_number': 27,
                'round_result': None,
                'round_result_decided_time': None,
                'round_result_decided_price': None,
                'round_status': 'SPINNING',
                'max_price': 5000,
                'min_price': 5000,
                'start_price': 5000,
                'start_time': '2000-01-01T00:05:10+00:00',
                'updated_at': mock.ANY,
                'fall_status_0_05_lot': 'ENABLED',
                'fall_status_0_1_lot': 'ENABLED',
                'fall_status_0_5_lot': 'ENABLED',
                'fall_status_10_lot': 'ENABLED',
                'fall_status_1_lot': 'ENABLED',
                'fall_status_5_lot': 'ENABLED',
                'max_fall_bets_amount': 10000000,
                'max_rise_bets_amount': 10000000,
                'rise_status_0_05_lot': 'ENABLED',
                'rise_status_0_1_lot': 'ENABLED',
                'rise_status_0_5_lot': 'ENABLED',
                'rise_status_10_lot': 'ENABLED',
                'rise_status_1_lot': 'ENABLED',
                'rise_status_5_lot': 'ENABLED',
                'total_fall_bets_amount': 0,
                'total_rise_bets_amount': 0,
            },
            'updated_at': '2000-01-01T00:05:10+00:00'
        },

    ]


def test_split_commissions_regular_user(user_ru, user_f, user_b, user_sd, user_1, round_1_5sec):
    pending_commissions = 100000
    user_ru.pending_commissions = pending_commissions
    db.session.add(user_ru)
    db.session.flush()

    user_f_balance = user_f.balance
    user_b_balance = user_b.balance
    user_sd_balance = user_sd.balance
    user_1_balance = user_1.balance

    price_updater.collect_commission(user_ru, round_1_5sec)

    for user in [user_ru, user_f, user_b, user_sd, user_1]:
        db.session.refresh(user)

    assert user_ru.pending_commissions == 0
    assert user_f.balance == user_f_balance + pending_commissions * price_updater.FRANCHISEE_CUT
    assert user_b.balance == user_b_balance + pending_commissions * price_updater.PARTNER_CUT
    assert user_sd.balance == user_sd_balance + pending_commissions * price_updater.SOLE_DISTRIBUTOR_CUT
    assert user_1.balance == user_1_balance + pending_commissions * price_updater.HQ_CUT
