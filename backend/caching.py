import os
import json
from datetime import timedelta
import time

import redis
import rediscluster


from models import UserRole, User


ROUNDS_HISTORY_LENGTH = 300
BETS_HISTORY_LENGTH = 15
EXCHANGES_HISTORY_LENGTH = 20
EXCHANGE_TTL = timedelta(hours=2)
ROUND_TTL = timedelta(hours=6)
BET_TTL = timedelta(hours=2)
USER_TTL = timedelta(hours=1)

REDIS_URL = os.environ['REDIS_URL']

if REDIS_URL.startswith('redis://'):
    redis_client = redis.Redis.from_url(REDIS_URL)
elif REDIS_URL.startswith('redis+cluster://'):
    redis_client = rediscluster.RedisCluster.from_url(REDIS_URL, skip_full_coverage_check=True)
else:
    raise ValueError(f"Invalid REDIS_URL: {REDIS_URL}")


"""
Redis keys:

* `exchanges` -> Redis sorted set with keys of the form `<EXCHANGE_ID>` and the corresponding scores are UNIX timestamp of insertion date (this is used as an LRU cache)
* `exchange:<EXCHANGE_ID>` -> `models.Exchange.to_json()` as a string
* `rounds:<EXCHANGE_ID>` -> Redis sorted set with keys of the form `<ROUND_ID>` and the corresponding scores are UNIX timestamp of insertion date (this is used as an LRU cache)
* `round:<ROUND_ID>` -> `models.Round.to_json()` as a string
* `betting_round:<EXCHANGE_ID>:id` -> `models.Round.id` for EXCHANGE_ID's current betting round as a string
* `betting_round:<EXCHANGE_ID>:rise_bets_amount` -> `models.Round.total_rise_bets_amount` for EXCHANGE_ID's current betting round as a string, but updated in realtime (it's only updated at the end of a round in the DB by the price updater)
* `betting_round:<EXCHANGE_ID>:fall_bets_amount` -> `models.Round.total_fall_bets_amount` for EXCHANGE_ID's current betting round as a string, but updated in realtime (it's only updated at the end of a round in the DB by the price updater)
* `betting_round:<EXCHANGE_ID>:user_bets_amount` ->  Redis hashmap with keys as user IDs and the corresponding value is the total amount the user has bet (all types of bets)
* `betting_round:<EXCHANGE_ID>:user_bets_direction` ->  Redis hashmap with keys as user IDs and the corresponding value is the bet type that user is making this round (users can only make one type of bet per round)
* `bets` -> Redis sorted set with keys of the form `<ROUND_ID>` and the corresponding scores are UNIX timestamp of insertion date (this is used as an LRU cache)
* `bet:<BET_ID>` -> `models.Bet.to_json()` as a string
"""

# NOTE: we only cache Exchange, Round, and Bet, because these are largely public anyways - if the cache is accidentally exposed or stale, there's not really a big issue; that means we must never cache User or anything else that contains PII
# NOTE: a TTL is required on all keys in order to allow them to be evicted by AWS ElastiCache's default volatile-lru policy when Redis fills up - volatile-lru will only evict keys that have TTLs
# NOTE: we use sorted sets (zadd/zscan/zremrangebyrank commands) in order to implement LRU caching


def get_exchange(exchange_id):
    assert isinstance(exchange_id, int), exchange_id
    result = redis_client.get(f"exchange:{exchange_id}")
    if result is None:
        return None
    return json.loads(result)


def get_all_exchanges():
    all_exchange_json = redis_client.mget(f'exchange:{v.decode("ascii")}' for v, t in redis_client.zscan_iter('exchanges'))
    return [json.loads(exchange_json) for exchange_json in all_exchange_json if exchange_json is not None]


def set_exchange(exchange_json):
    redis_client.setex(f"exchange:{exchange_json['id']}", EXCHANGE_TTL, json.dumps(exchange_json))
    redis_client.zadd("exchanges", {exchange_json['id']: time.time()})
    redis_client.zremrangebyrank("exchanges", 0, -EXCHANGES_HISTORY_LENGTH - 1)


def get_round(round_id):
    assert isinstance(round_id, int), round_id
    result = redis_client.get(f"round:{round_id}")
    if result is None:
        return None
    return json.loads(result)


def get_exchange_rounds(exchange_id, limit=None):
    assert isinstance(exchange_id, int), exchange_id
    assert limit is None or (isinstance(limit, int) and limit > 0), limit
    if limit is None:
        all_rounds_json = redis_client.mget(
            f'round:{v.decode("ascii")}' for v, t in redis_client.zscan_iter(f'rounds:{exchange_id}')
        )
    else:
        all_rounds_json = redis_client.mget(
            f'round:{v.decode("ascii")}' for v in redis_client.zrevrange(f'rounds:{exchange_id}', 0, limit - 1)
        )
    return [json.loads(value) for value in all_rounds_json if value is not None]


def set_round(round_json):
    redis_client.setex(f"round:{round_json['id']}", ROUND_TTL, json.dumps(round_json))
    redis_client.zadd(f"rounds:{round_json['exchange']['id']}", {round_json['id']: time.time()})
    redis_client.zremrangebyrank(f"rounds:{round_json['exchange']['id']}", 0, -ROUNDS_HISTORY_LENGTH - 1)


def get_betting_round_bets(exchange_id, user_id):
    assert isinstance(exchange_id, int), exchange_id
    assert isinstance(user_id, int), user_id
    round_id = redis_client.get(f"betting_round:{exchange_id}:id")
    if round_id is None:
        return None, None, None, None, None
    rise_bets_amount = redis_client.get(f"betting_round:{exchange_id}:rise_bets_amount")
    fall_bets_amount = redis_client.get(f"betting_round:{exchange_id}:fall_bets_amount") or 0
    user_bets_amount = redis_client.hget(f"betting_round:{exchange_id}:user_bets_amount", user_id) or 0
    user_bet_direction = redis_client.hget(f"betting_round:{exchange_id}:user_bets_direction", user_id)

    rise_bets_amount = 0 if rise_bets_amount is None else int(rise_bets_amount)
    fall_bets_amount = 0 if fall_bets_amount is None else int(fall_bets_amount)
    user_bets_amount = 0 if user_bets_amount is None else int(user_bets_amount)
    user_bet_direction = None if user_bet_direction is None else user_bet_direction.decode('ascii')
    return int(round_id), user_bets_amount, user_bet_direction, rise_bets_amount, fall_bets_amount


def reset_betting_round_bets(exchange_id):
    assert isinstance(exchange_id, int), exchange_id
    redis_client.delete(
        f"betting_round:{exchange_id}:id",
        f"betting_round:{exchange_id}:rise_bets_amount",
        f"betting_round:{exchange_id}:fall_bets_amount",
        f"betting_round:{exchange_id}:user_bets_direction",
        f"betting_round:{exchange_id}:user_bets_amount",
    )


def enable_betting_round_bets(exchange_id, round_id):
    assert isinstance(exchange_id, int), exchange_id
    assert isinstance(round_id, int), round_id
    redis_client.set(f"betting_round:{exchange_id}:id", round_id)


def add_betting_round_bets(exchange_id, user_id, rise_bet_amount, fall_bet_amount):
    assert isinstance(exchange_id, int), exchange_id
    assert isinstance(rise_bet_amount, int), rise_bet_amount
    assert isinstance(fall_bet_amount, int), fall_bet_amount
    if rise_bet_amount:
        redis_client.incrby(f"betting_round:{exchange_id}:rise_bets_amount", rise_bet_amount)
        redis_client.hset(f"betting_round:{exchange_id}:user_bets_direction", user_id, 'RISE')
    if fall_bet_amount:
        redis_client.incrby(f"betting_round:{exchange_id}:fall_bets_amount", fall_bet_amount)
        redis_client.hset(f"betting_round:{exchange_id}:user_bets_direction", user_id, 'FALL')
    redis_client.hincrby(f"betting_round:{exchange_id}:user_bets_amount", user_id, rise_bet_amount + fall_bet_amount)


def get_bet(bet_id):
    assert isinstance(bet_id, int), bet_id
    result = redis_client.get(f"bet:{bet_id}")
    if result is None:
        return None
    return json.loads(result)


def get_all_bets():
    all_bet_json = redis_client.mget(f'bet:{v.decode("ascii")}' for v, t in redis_client.zscan_iter('bets'))
    return [json.loads(bet_json) for bet_json in all_bet_json if bet_json is not None]


def set_bet(bet_json):
    redis_client.setex(f"bet:{bet_json['id']}", BET_TTL, json.dumps(bet_json))
    redis_client.zadd("bets", {bet_json['id']: time.time()})
    redis_client.zremrangebyrank("bets", 0, -BETS_HISTORY_LENGTH - 1)


def get_user(user_id):
    assert isinstance(user_id, int), user_id
    result = redis_client.get(f"user:{user_id}")
    if result is None:
        return None
    user_json = json.loads(result)
    return User(
        id=user_json['id'],
        uuid=user_json['uuid'],
        username=user_json['username'],
        is_suspended=user_json['is_suspended'],
        email_confirmed=user_json['email_confirmed'],
        role=UserRole[user_json['role']],
    )


def set_user(user):
    assert isinstance(user, User), user
    user_json = {
        'id': user.id,
        'uuid': user.uuid,
        'username': user.username,
        'is_suspended': user.is_suspended,
        'email_confirmed': user.email_confirmed,
        'role': user.role.name,
    }
    redis_client.setex(f"user:{user_json['id']}", USER_TTL, json.dumps(user_json))


def delete_user(user_id):
    redis_client.delete(f"user:{user_id}")


def clear_all():
    redis_client.flushall()
