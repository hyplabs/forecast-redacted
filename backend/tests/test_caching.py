import caching


def test_exchanges():
    caching.clear_all()
    assert caching.get_all_exchanges() == []
    assert caching.get_exchange(0) is None
    for i in range(caching.EXCHANGES_HISTORY_LENGTH + 7):
        caching.set_exchange({'id': i})
    for i in range(caching.EXCHANGES_HISTORY_LENGTH):
        assert caching.get_exchange(i) == {'id': i}
    assert sorted(caching.get_all_exchanges(), key=lambda e: e['id']) == [{'id': i + 7} for i in range(caching.EXCHANGES_HISTORY_LENGTH)]


def test_bets():
    caching.clear_all()
    assert caching.get_all_bets() == []
    assert caching.get_bet(0) is None
    for i in range(caching.BETS_HISTORY_LENGTH + 7):
        caching.set_bet({'id': i})
    for i in range(caching.BETS_HISTORY_LENGTH):
        assert caching.get_bet(i) == {'id': i}
    assert sorted(caching.get_all_bets(), key=lambda b: b['id']) == [{'id': i + 7} for i in range(caching.BETS_HISTORY_LENGTH)]


def test_rounds():
    caching.clear_all()
    assert caching.get_exchange_rounds(123) == []
    assert caching.get_exchange_rounds(123, 5) == []
    assert caching.get_round(0) is None
    for i in range(caching.ROUNDS_HISTORY_LENGTH + 7):
        caching.set_round({'id': i, 'exchange': {'id': 123}})
    for i in range(caching.ROUNDS_HISTORY_LENGTH):
        assert caching.get_round(i) == {'id': i, 'exchange': {'id': 123}}
    assert sorted(caching.get_exchange_rounds(123), key=lambda r: r['id']) == [{'id': i + 7, 'exchange': {'id': 123}} for i in range(caching.ROUNDS_HISTORY_LENGTH)]
    assert sorted(caching.get_exchange_rounds(123, 5), key=lambda r: r['id']) == [{'id': caching.ROUNDS_HISTORY_LENGTH + 7 - 5 + i, 'exchange': {'id': 123}} for i in range(5)]


def test_betting_round():
    caching.clear_all()
    assert caching.get_betting_round_bets(12, 56) == (None, None, None, None, None)
    caching.reset_betting_round_bets(12)
    assert caching.get_betting_round_bets(12, 56) == (None, None, None, None, None)
    caching.enable_betting_round_bets(12, 34)
    assert caching.get_betting_round_bets(12, 56) == (34, 0, None, 0, 0)
    assert caching.get_betting_round_bets(12, 57) == (34, 0, None, 0, 0)
    caching.add_betting_round_bets(12, 56, 1000, 1001)
    assert caching.get_betting_round_bets(12, 56) == (34, 2001, 'FALL', 1000, 1001)
    assert caching.get_betting_round_bets(12, 57) == (34, 0, None, 1000, 1001)
    caching.add_betting_round_bets(12, 56, 1002, 1003)
    assert caching.get_betting_round_bets(12, 56) == (34, 4006, 'FALL', 2002, 2004)
    assert caching.get_betting_round_bets(12, 57) == (34, 0, None, 2002, 2004)
    caching.reset_betting_round_bets(12)
    assert caching.get_betting_round_bets(12, 56) == (None, None, None, None, None)
    assert caching.get_betting_round_bets(12, 57) == (None, None, None, None, None)
