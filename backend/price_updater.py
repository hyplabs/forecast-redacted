from typing import Optional
import time
import sys
import logging
from datetime import datetime, timedelta
import asyncio
import statistics
import random
import signal

from sqlalchemy import func
import aiohttp

from models import db, User, Exchange, RoundResult, RoundStatus, Round, BetType, BetResult, Bet, BalanceChangeRecord, BalanceChangeType, UserRole
import caching

"""
A `Round` represents some fixed time intervals over which users can place bets, and over which the bet outcome is calculated. A `Round` transitions through different `RoundStatus`s at different times. The following example shows 3 rounds in the 1-minute exchange:

┌─ bet_and_lock_seconds ──┐┌─── max_spin_seconds ────┐
create                     start         decide       end
0s                   57s   60s           96s?         120s
┌────────────────────┬─────┬─────────────┬────────────┬─────────────────────────────────────────────────────────────────────
│BETTING             │LOCK │SPINNING     │DECIDED     │COMPLETED (RISE/FALL)
└────────────────────┴─────┴─────────────┴────────────┴─────────────────────────────────────────────────────────────────────
                           ↓                          ↓
                           ┌─ bet_and_lock_seconds ──┐┌─── max_spin_seconds ────┐
                           0s                   57s   60s      70s?              120s
                           ┌────────────────────┬─────┬────────┬─────────────────┬───────────────────────────────────────────
                           │BETTING             │LOCK │SPINNING│DECIDED          │COMPLETED (NO_CHANGE)
                           └────────────────────┴─────┴────────┴─────────────────┴───────────────────────────────────────────
                                                      ↓                          ↓
                                                      ┌─ bet_and_lock_seconds ──┐┌─── max_spin_seconds ────┐
                                                      0s                   57s   60s                108s?   120s
                                                      ┌────────────────────┬─────┬──────────────────┬───────┬─────────────────────
                                                      │BETTING             │LOCK │SPINNING          │DECIDED│COMPLETED (RISE/FALL)
                                                      └────────────────────┴─────┴──────────────────┴───────┴─────────────────────

Times that have a `?` after them (e.g., `96s?`) are dependent on price movement - they may be different depending on how the price moves.

The transition from `SPINNING` to `DECIDED` always occurs based on price movement; if the price does not move enough the `Round`'s spinning period will simply time out, so `SPINNING` goes directly to `COMPLETED` with no `DECIDED` state in between.

All other transitions have fixed offsets from `create`, as follows:
- The time between `create` and `start` is called the `bet_and_lock_seconds`.
- The time between `start` and `end` is called the `max_spin_seconds`.
- The length of time in the `LOCKING_IN_BETS` state is called `LOCK_IN_BETS_TIME_DELAY`.

`bet_and_lock_seconds` and `max_spin_seconds` are set per exchange, while `LOCK_IN_BETS_TIME_DELAY` is the same for each exchange.

At any point in time there is exactly one `Round` whose status is either `BETTING` or `LOCKING_IN_BETS`. New bets and bets from previous NO_CHANGE rounds always go into this round. There are no other guarantees about rounds existing.

The price updater runs in a loop; every iteration it pulls price data and changes the round_status of eligible rounds. It runs the transition in back-to-front order to maintain the invariant that there is always one `BETTING`/`LOCKING_IN_BETS` round. In particular, NO_CHANGE rounds relies on this invariant, because when this happens, all bets must be moved to the current `BETTING`/`LOCKING_IN_BETS` round.

Price data is pulled from multiple independent sources: Gemini, Kraken, and Coinbase. We take the median of these sources as the true price. The median has several useful properties here: 1) a median of 3 or more values is robust against a single outlier in either direction, so a rogue exchange would be unable to affect the price (since it would become an outlier and be ignored), and 2) a median_low is always equal to one of the values in its input dataset (unlike the mean, which might result in a value that is not any of Gemini/Kraken/Coinbase's prices).
"""

WATCHDOG_TIMEOUT_SECONDS = 30  # number of seconds without petting the watchdog, before watchdog kills this process
PRICE_UPDATE_PERIOD = 2  # check BTC price and update rounds once per PRICE_UPDATE_PERIOD seconds
PRICE_REQUEST_TIMEOUT = 1  # number of seconds to allow for price requests, must be at most PRICE_UPDATE_PERIOD seconds
LOCK_IN_BETS_TIME_DELAY = 10  # seconds to lock betting at the end of the betting period (prevents people with a slightly faster feed from being able to gain an advantage)

FRANCHISEE_CUT = 0.5  # half of commission
SOLE_DISTRIBUTOR_CUT = 0.1
PARTNER_CUT = 0.1
HQ_CUT = 0.3

logging.basicConfig(level=logging.WARN)
logger = logging.getLogger("price_updater")
logger.setLevel(logging.INFO)


# set up watchdog timer via the UNIX alarm signal
def watchdog_timeout(sig, frm):
    logger.critical(f"Price Update Service frozen for over {WATCHDOG_TIMEOUT_SECONDS} seconds; watchdog activated")
    sys.exit(1)
signal.signal(signal.SIGALRM, watchdog_timeout)
def pet_watchdog():
    signal.alarm(WATCHDOG_TIMEOUT_SECONDS)


# trading volume isn't the actual trading volume of Forecast, but rather a realistic-looking simulation meant to behave like real trading volume
# according to http://cbpfindex.cbpf.br/publication_pdfs/SMDQ-vol-review.2016_01_06_12_54_56.pdf, the volume should be modelled using a lognormal distribution
# I messed around with the numbers until I got something that looked alright, assuming 9k users making 5kWon bets regularly, this seems pretty decent
def get_trading_volume():
    return random.lognormvariate(17.5, 0.25)


async def fetch_json(url):
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=PRICE_REQUEST_TIMEOUT)) as session:
        async with session.get(url) as resp:
            return await resp.json()


async def get_gemini_btc_spot_price():
    result = None
    try:
        # see https://docs.gemini.com/rest-api/#ticker for reference
        # rate limiting info: https://docs.gemini.com/rest-api/#rate-limits
        result = await fetch_json('https://api.gemini.com/v1/pubticker/btcusd')
        return float(result['last'])
    except Exception as e:
        logger.warning(f"Could not obtain Gemini BTC-USD price (result: {result}): {e}")
    return None


async def get_kraken_btc_spot_price():
    result = None
    try:
        # see https://www.kraken.com/features/api#get-ticker-info for reference
        # rate limiting info: https://support.kraken.com/hc/en-us/articles/206548367-What-are-the-REST-API-rate-limits-#1
        result = await fetch_json('https://api.kraken.com/0/public/Ticker?pair=XBTUSD')
        assert isinstance(result.get('error'), list) and not result['error']
        return float(result['result']['XXBTZUSD']['c'][0])
    except Exception as e:
        logger.warning(f"Could not obtain Kraken BTC-USD price (result: {result}): {e}")
    return None


async def get_coinbase_btc_spot_price():
    result = None
    try:
        # see https://developers.coinbase.com/api/v2#get-spot-price for reference
        # rate limiting info: https://help.coinbase.com/en/pro/other-topics/api/faq-on-api.html
        result = await fetch_json('https://api.coinbase.com/v2/prices/BTC-USD/spot')
        return float(result['data']['amount'])
    except Exception as e:
        logger.warning(f"Could not obtain Coinbase BTC-USD price (result: {result}): {e}")
    return None


def get_median_btc_spot_price():
    start_time = time.time()
    loop = asyncio.get_event_loop()
    gemini_price, kraken_price, coinbase_price = loop.run_until_complete(asyncio.gather(
        get_gemini_btc_spot_price(),
        get_kraken_btc_spot_price(),
        get_coinbase_btc_spot_price(),
    ))
    available_spot_prices = [price for price in [gemini_price, kraken_price, coinbase_price] if price is not None]
    if len(available_spot_prices) == 0:
        raise ValueError('No available BTC spot prices!')
    elif len(available_spot_prices) == 1:
        logger.warning('BTC spot price is only based on one exchange!')
    elif statistics.stdev(available_spot_prices) > 20:
        logger.warning(f'Unusually high standard deviation in BTC spot price between exchanges: {statistics.stdev(available_spot_prices)}')
    median_price = statistics.median_low(available_spot_prices)
    duration = time.time() - start_time
    logger.info(f"Obtained current median BTC price {median_price} (requests took {duration} seconds total): gemini={gemini_price}, kraken={kraken_price}, coinbase={coinbase_price}")
    return median_price


def start_new_round(exchange, now):
    round_number = (now.hour * 60 * 60 + now.minute * 60 + now.second) // exchange.bet_and_lock_seconds
    new_round = Round(
        round_date=now.date(),
        round_number=round_number,
        exchange_id=exchange.id,
        start_time=now,
        lock_in_bets_time=now + timedelta(seconds=exchange.bet_and_lock_seconds - LOCK_IN_BETS_TIME_DELAY),
        spinning_start_time=now + timedelta(seconds=exchange.bet_and_lock_seconds),
        end_time=now + timedelta(seconds=exchange.bet_and_lock_seconds + exchange.max_spin_seconds),
        start_price=None,
        end_price=None,
        round_result=None,
        round_result_decided_time=None,
        round_status=RoundStatus.BETTING,
    )
    db.session.add(new_round)
    db.session.flush()
    logger.info(f"Starting new round: {new_round}")
    return new_round


# NOTE: user must be row-level or table-level locked when using this function, to avoid race conditions
def adjust_user_balance_commission(user, details, amount):
    prev_balance = user.balance
    user.balance += amount
    balance_change_record = BalanceChangeRecord(
        user_id=user.id,
        balance_change_type=BalanceChangeType.COMMISSION,
        details=details,
        principal=0,
        arbitrage=0,
        commission=amount,
        before_balance=prev_balance,
        after_balance=user.balance
    )
    db.session.add_all([user, balance_change_record])


def collect_commission(user, round):
    if user.pending_commissions == 0:
        return
    payable_commissions = user.pending_commissions
    user.pending_commissions = 0
    db.session.add(user)

    if user.role == UserRole.REGULAR_USER and user.referring_user is not None and user.referring_user.role == UserRole.FRANCHISEE:
        franchise_user = user.referring_user
        assert franchise_user.referring_user is not None, franchise_user
        # Pay out franchisee
        logger.info(f'Paying {payable_commissions * FRANCHISEE_CUT} won to franchisee user {franchise_user.id} as commission for round {round.id}.')
        adjust_user_balance_commission(franchise_user, f'Commission for round {round.id}', payable_commissions * FRANCHISEE_CUT)

        # Pay out partner
        partner_user = franchise_user.referring_user
        assert partner_user.role == UserRole.PARTNER, partner_user
        assert partner_user.referring_user is not None, partner_user
        logger.info(f'Paying {payable_commissions * PARTNER_CUT} won to partner user {partner_user.id} as commission for round {round.id}.')
        adjust_user_balance_commission(partner_user, f'Commission for round {round.id}', payable_commissions * PARTNER_CUT)

        # Pay out SD
        sd_user = partner_user.referring_user
        # Ensure SD has connection to HQ (enforce pyramid)
        assert sd_user.role == UserRole.SOLE_DISTRIBUTOR, sd_user
        assert sd_user.referring_user is not None, sd_user
        logger.info(f'Paying {payable_commissions * SOLE_DISTRIBUTOR_CUT} won to sole distributor user {sd_user.id} as commission for round {round.id}.')
        adjust_user_balance_commission(sd_user, f'Commission for round {round.id}', payable_commissions * SOLE_DISTRIBUTOR_CUT)

        # Pay out HQ
        hq_user = sd_user.referring_user
        # Ensure partner has connection to HQ (enforce pyramid)
        assert hq_user.role == UserRole.HQ, hq_user
        logger.info(f'Paying {payable_commissions * HQ_CUT} won to HQ user {hq_user.id} as commission for round {round.id}.')
        adjust_user_balance_commission(hq_user, f'Commission for round {round.id}', payable_commissions * HQ_CUT)
    elif user.role == UserRole.FRANCHISEE and user.referring_user is not None and user.referring_user.role == UserRole.PARTNER:
        # Pay out partner
        partner_user = user.referring_user
        assert partner_user.referring_user_id is not None, partner_user
        logger.info(f'Paying {payable_commissions * (PARTNER_CUT + FRANCHISEE_CUT)} won to partner user {partner_user.id} as commission for round {round.id}.')
        adjust_user_balance_commission(partner_user, f'Commission for round {round.id}', payable_commissions * (PARTNER_CUT + FRANCHISEE_CUT))

        # Pay out SD
        sd_user = partner_user.referring_user
        assert sd_user.role == UserRole.SOLE_DISTRIBUTOR, sd_user
        assert sd_user.referring_user_id is not None, sd_user
        logger.info(f'Paying {payable_commissions * SOLE_DISTRIBUTOR_CUT} won to sole distributor user {sd_user.id} as commission for round {round.id}.')
        adjust_user_balance_commission(sd_user, f'Commission for round {round.id}', payable_commissions * SOLE_DISTRIBUTOR_CUT)

        # Pay out HQ
        hq_user = sd_user.referring_user
        assert hq_user.role == UserRole.HQ, hq_user
        logger.info(f'Paying {payable_commissions * HQ_CUT} won to HQ user {hq_user.id} as commission for round {round.id}.')
        adjust_user_balance_commission(hq_user, f'Commission for round {round.id}', payable_commissions * HQ_CUT)
    elif user.role == UserRole.PARTNER and user.referring_user is not None and user.referring_user.role == UserRole.SOLE_DISTRIBUTOR:
        # Pay out SD
        sd_user = user.referring_user
        assert sd_user.referring_user_id is not None, sd_user
        logger.info(f'Paying {payable_commissions * (PARTNER_CUT + FRANCHISEE_CUT + SOLE_DISTRIBUTOR_CUT)} won to sole distributor user {sd_user.id} as commission for round {round.id}.')
        adjust_user_balance_commission(sd_user, f'Commission for round {round.id}', payable_commissions * (PARTNER_CUT + FRANCHISEE_CUT + SOLE_DISTRIBUTOR_CUT))

        # Pay out HQ
        hq_user = sd_user.referring_user
        assert hq_user.role == UserRole.HQ, hq_user
        logger.info(f'Paying {payable_commissions * HQ_CUT} won to HQ user {hq_user.id} as commission for round {round.id}.')
        adjust_user_balance_commission(hq_user, f'Commission for round {round.id}', payable_commissions * HQ_CUT)
    elif user.role == UserRole.SOLE_DISTRIBUTOR and user.referring_user is not None and user.referring_user.role == UserRole.HQ:
        # pay out entire commission to HQ
        hq_user = user.referring_user
        assert hq_user.role == UserRole.HQ, hq_user
        logger.info(f'Paying {payable_commissions} won to HQ user {hq_user.id} as commission for round {round.id}.')
        adjust_user_balance_commission(hq_user, f'Commission for round {round.id}', payable_commissions)
    elif user.role == UserRole.HQ and user.referring_user is None:
        adjust_user_balance_commission(user, f'Commission for round {round.id}', payable_commissions)
        logger.info(f'Paying commmission to HQ user {user.id} for round {round.id} of {payable_commissions} with no referring user.')
    else:
        logger.error(f'Skipping user who does not fit into the hierarchy: {user.id}')
    db.session.flush()


def summarize_bets(locked_bets_round):
    assert locked_bets_round.round_status is RoundStatus.LOCKING_IN_BETS, locked_bets_round
    rise_bets_amount = db.session.query(func.sum(Bet.amount)).filter_by(round_id=locked_bets_round.id, bet_type=BetType.RISE).one()[0]
    fall_bets_amount = db.session.query(func.sum(Bet.amount)).filter_by(round_id=locked_bets_round.id, bet_type=BetType.FALL).one()[0]
    locked_bets_round.total_rise_bets_amount = 0 if rise_bets_amount is None else rise_bets_amount
    locked_bets_round.total_fall_bets_amount = 0 if fall_bets_amount is None else fall_bets_amount
    db.session.add(locked_bets_round)
    db.session.flush()


def refund_round(completed_round, now):
    assert completed_round.round_status is RoundStatus.COMPLETED, completed_round

    # determine users that bet during this round
    user_bets = db.session.query(User, Bet).filter(User.id == Bet.user_id).filter(Bet.round_id == completed_round.id).all()

    # refund all bets and pending commissions
    for user, bet in user_bets:
        logger.info(f"Refunding user {user.id} for bet {bet.id} of {bet.amount} bet in round {completed_round.id}")
        prev_user_balance = user.balance
        user.balance += bet.amount + bet.commission
        user.pending_commissions -= bet.commission
        db.session.add(user)
        bet.bet_result = BetResult.CANCELLED
        db.session.add(bet)
        db.session.flush()
        balance_change_record = BalanceChangeRecord(
            user_id=user.id,
            bet_id=bet.id,
            balance_change_type=BalanceChangeType.BET_REFUND,
            details=completed_round.round_result.value,
            principal=bet.amount,
            arbitrage=0,
            before_balance=prev_user_balance,
            after_balance=user.balance,
        )
        db.session.add(balance_change_record)
    db.session.flush()


def pay_out_round(decided_round, now):
    assert decided_round.round_status is RoundStatus.DECIDED, decided_round

    # determine users that bet during this round, and lock their rows
    q = db.session.query(User, Bet).filter(User.id == Bet.user_id).filter(Bet.round_id == decided_round.id)

    if decided_round.round_result == RoundResult.FALL:
        winners = q.filter(Bet.bet_type == BetType.FALL).all()
        losers = q.filter(Bet.bet_type != BetType.FALL).all()
        logger.info(f"Round {decided_round} ended as a FALL: paying out {len(winners)} winners, ignoring {len(losers)} losers")
    elif decided_round.round_result == RoundResult.RISE:
        winners = q.filter(Bet.bet_type == BetType.RISE).all()
        losers = q.filter(Bet.bet_type != BetType.RISE).all()
        logger.info(f"Round {decided_round} ended as a RISE: paying out {len(winners)} winners, ignoring {len(losers)} losers")
    else:
        assert False, decided_round  # unreachable

    # apply winnings to all users that won
    for user, bet in winners:
        logger.info(f"Paying out user {user.id} for bet {bet.id} of {bet.amount} bet in round {decided_round.id}")
        prev_user_balance = user.balance
        won_amount = bet.amount  # amount that user won, because they bet correctly
        user.balance += bet.amount + won_amount

        # # move pending commission into payable commission
        # user.payable_commissions += user.pending_commissions
        # user.pending_commissions = 0

        db.session.add(user)
        db.session.add(BalanceChangeRecord(
            user_id=user.id,
            bet_id=bet.id,
            balance_change_type=BalanceChangeType.BET_WINNINGS,
            details=bet.round.round_result.value,
            principal=bet.amount,
            arbitrage=won_amount,
            before_balance=prev_user_balance,
            after_balance=user.balance,
        ))

        bet.bet_result = BetResult.WON
        db.session.add(bet)
    for user, bet in losers:
        # # move pending commission into payable commission
        # user.payable_commissions += user.pending_commissions
        # user.pending_commissions = 0

        bet.bet_result = BetResult.LOST
        db.session.add(bet)
    db.session.flush()
    for user, _ in q.all():
        collect_commission(user, decided_round)


def update_betting_round(exchange, now) -> Optional[Round]:  # transitions from BETTING -> LOCKING_IN_BETS
    # retrieve the current betting round
    betting_rounds = Round.query.filter_by(exchange_id=exchange.id, round_status=RoundStatus.BETTING).all()
    if not betting_rounds:
        return None
    assert len(betting_rounds) == 1, betting_rounds
    betting_round = betting_rounds[0]
    assert betting_round.round_status is RoundStatus.BETTING, betting_round

    # latest round's betting stage has ended, go to locked bets stage
    if now >= betting_round.lock_in_bets_time:
        logger.info(f"Betting period expired for round {betting_round} on exchange {exchange}, locking in bets and transitioning to locked in state")
        betting_round.round_status = RoundStatus.LOCKING_IN_BETS
        summarize_bets(betting_round)
        db.session.add(betting_round)
        db.session.flush()

        # usually we would do caching operations after db.session.commit(),
        # but when resetting we should do them before commit, because it's fine to reset even if the commit fails,
        # but it's not fine if we commit and the reset fails
        caching.reset_betting_round_bets(exchange.id)
    return betting_round


def update_locked_bets_round(exchange, now, current_price) -> Optional[Round]:  # transitions from LOCKING_IN_BETS -> SPINNING
    # retrieve the current locked bets round
    locked_bets_rounds = Round.query.filter_by(exchange_id=exchange.id, round_status=RoundStatus.LOCKING_IN_BETS).all()
    if not locked_bets_rounds:
        return None
    assert len(locked_bets_rounds) == 1, locked_bets_rounds
    locked_bets_round = locked_bets_rounds[0]
    assert locked_bets_round.round_status is RoundStatus.LOCKING_IN_BETS, locked_bets_round

    # lock-in bets delay has ended, go to spinning stage
    if now >= locked_bets_round.spinning_start_time:
        logger.info(f"Bet Lock-in period expired for round {locked_bets_round} on exchange {exchange}. Starting spinning state.")
        locked_bets_round.start_price = current_price
        locked_bets_round.end_price = current_price
        locked_bets_round.max_price = current_price
        locked_bets_round.min_price = current_price
        locked_bets_round.trading_volume = get_trading_volume()
        locked_bets_round.round_status = RoundStatus.SPINNING
        db.session.add(locked_bets_round)
        db.session.flush()
    return locked_bets_round


def update_spinning_round(exchange, now, current_price) -> Optional[Round]:  # transitions from SPINNING -> DECIDED or SPINNING -> COMPLETED
    # retrieve the current spinning round
    spinning_rounds = Round.query.filter_by(exchange_id=exchange.id, round_status=RoundStatus.SPINNING).all()
    if not spinning_rounds:
        return None
    assert len(spinning_rounds) == 1, spinning_rounds
    spinning_round = spinning_rounds[0]
    assert spinning_round.round_status is RoundStatus.SPINNING, spinning_round

    # set current prices
    spinning_round.end_price = current_price
    if current_price > spinning_round.max_price:
        spinning_round.max_price = current_price
    if current_price < spinning_round.min_price:
        spinning_round.min_price = current_price

    if now >= spinning_round.end_time:  # spinning timed out without being decided, refund all bets (including commission)
        logger.info(f"Spinning period expired for round {spinning_round} on exchange {exchange} without a significant price move, refunding all bets (including commission)")
        if spinning_round.max_price - spinning_round.start_price < exchange.round_decided_threshold or spinning_round.start_price - spinning_round.max_price < exchange.round_decided_threshold:
            logger.error(f"Round {spinning_round.id} reached threshold for exchange {exchange.id} without being decided, likely due to an error when transitioning from SPINNING to DECIDED - round result should actually be RISE or FALL, not NO_CHANGE")
        spinning_round.round_result = RoundResult.NO_CHANGE
        spinning_round.round_status = RoundStatus.COMPLETED
        spinning_round.trading_volume = get_trading_volume()
        refund_round(spinning_round, now)
    elif abs(spinning_round.end_price - spinning_round.start_price) >= exchange.round_decided_threshold:  # price moved enough to potentially decide the round's result already, go to decided stage and pay out
        logger.info(f"Spinning period decided due to change of {spinning_round.end_price - spinning_round.start_price} for round {spinning_round} on exchange {exchange}, finishing round")
        spinning_round.round_result = RoundResult.FALL if spinning_round.end_price < spinning_round.start_price else RoundResult.RISE
        spinning_round.round_status = RoundStatus.DECIDED
        spinning_round.round_result_decided_time = now
        spinning_round.round_result_decided_price = current_price
        pay_out_round(spinning_round, now)
    db.session.add(spinning_round)
    db.session.flush()
    return spinning_round


def update_decided_round(exchange, now, current_price) -> Optional[Round]:  # transitions from DECIDED -> COMPLETED
    decided_rounds = Round.query.filter_by(exchange_id=exchange.id, round_status=RoundStatus.DECIDED).all()
    if not decided_rounds:
        return None
    assert len(decided_rounds) == 1, decided_rounds
    decided_round = decided_rounds[0]

    decided_round.end_price = current_price
    if current_price > decided_round.max_price:
        decided_round.max_price = current_price
    if current_price < decided_round.min_price:
        decided_round.min_price = current_price

    if now >= decided_round.end_time:  # latest round's decided stage has timed out, call this round complete
        logger.info(f"Decided period ended for round {decided_round} on exchange {exchange}, finishing round")
        decided_round.round_status = RoundStatus.COMPLETED
        decided_round.trading_volume = get_trading_volume()

    db.session.add(decided_round)
    db.session.flush()
    return decided_round


def ensure_bet_or_lock_exists(exchange, now, current_price) -> Optional[Round]:
    betting_or_locked = (
        Round.query.filter_by(exchange_id=exchange.id).filter((Round.round_status == RoundStatus.BETTING) | (Round.round_status == RoundStatus.LOCKING_IN_BETS)).all()
    )
    if betting_or_locked:
        assert len(betting_or_locked) == 1, betting_or_locked
        return None
    else:
        return start_new_round(exchange, now)


def run_update():
    try:
        # get time and BTC price
        now = datetime.utcnow()
        logger.info(f"Starting update at {now.isoformat()}")
        current_price = get_median_btc_spot_price()

        update_start_time = time.time()

        # set statement timeout to 1 second, in case we have any trouble obtaining locks
        # this causes the query to raise an exception, which gives us a better error message than if we relied on the watchdog
        db.session.execute('SET statement_timeout = 2000;')

        # lock all tables that will be used
        db.session.execute('LOCK TABLE "user", "exchange", "round", "bet" IN EXCLUSIVE MODE;')

        # acquire exclusive row-level lock over all exchange rows, this allows multiple instances of the price updater to run simultaneously without messing up the rounds
        exchanges = Exchange.query.all()
        rounds_to_cache = []
        exchanges_with_new_betting_round = []
        for exchange in exchanges:
            # update exchange in the cache
            caching.set_exchange(exchange.to_json())

            # NOTE: we must always lock rows in this order: User, Exchange, Round, Transaction/Bet, because this is the order that the server does it in

            # go through all the stages in reverse order, to ensure that there is always at most one round that's in BETTING, LOCKING_IN_BETS, or SPINNING
            # if we go through the stages in the forward order, it's possible that a round A could be at the very last stage of the SPINNING step, and the next round B is at the very first stage of SPINNING, so we then have two SPINNING rounds
            # by going through the stages in reverse order, we ensure that A vacates the "SPINNING spot", so B can take its place
            rounds_to_cache.append(update_decided_round(exchange, now, current_price))
            rounds_to_cache.append(update_spinning_round(exchange, now, current_price))
            rounds_to_cache.append(update_locked_bets_round(exchange, now, current_price))
            rounds_to_cache.append(update_betting_round(exchange, now))

            # create new round if none exist
            new_round = ensure_bet_or_lock_exists(exchange, now, current_price)
            if new_round:
                rounds_to_cache.append(new_round)
                exchanges_with_new_betting_round.append((exchange, new_round))
        db.session.commit()
        for r in rounds_to_cache:
            if r is not None:
                caching.set_round(r.to_json())
        for e, r in exchanges_with_new_betting_round:
            caching.enable_betting_round_bets(e.id, r.id)
        update_duration = time.time() - update_start_time
        logger.info(f"Price updater run completed, took {update_duration} seconds total, changed {sum(1 for r in rounds_to_cache if r is not None)} rounds")
    except Exception:
        db.session.rollback()
        logger.exception("Price Update Service update raised exception")


def populate_cache():
    # prepopulate the exchanges and rounds caches
    for exchange in Exchange.query.all():
        start_time = time.time()
        caching.set_exchange(exchange.to_json())
        exchange_rounds = Round.query.filter_by(exchange_id=exchange.id).order_by(Round.start_time.desc()).limit(20).all()
        for round in exchange_rounds:
            caching.set_round(round.to_json())
        logger.info(f"Populating exchange/rounds cache for exchange {exchange} with {len(exchange_rounds)} rounds (took {time.time() - start_time} seconds)")
    # NOTE: we don't populate bets here, because we're fine with bets history being cleared when redis is restarted, and it could take a long time if we have a lot of bets active


if __name__ == '__main__':
    populate_cache()
    while True:
        pet_watchdog()
        start_time = time.time()
        run_update()
        duration = time.time() - start_time
        if duration < PRICE_UPDATE_PERIOD:
            time.sleep(PRICE_UPDATE_PERIOD - duration)
        else:
            logger.warning(f"Price Update Service falling behind expected frequency of 1 update per {PRICE_UPDATE_PERIOD} seconds; last update took {duration} seconds")
