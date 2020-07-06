import os
from datetime import datetime, timezone
from enum import Enum

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_migrate import Migrate

app = Flask(__name__, static_folder=None)

# Flask-SQLAlchemy config
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 50,
    'max_overflow': 10,
    'pool_recycle': 60 * 60,  # expire and recycle connections after an hour
}

# database config
db: SQLAlchemy = SQLAlchemy(app)

# Flask-Migrate config
migrate = Migrate(app, db, compare_type=True)

KRW_PER_LOT = 100000
# max amount of won that can be bet per round for reach of rise and fall bets
MAX_BETTING_AMOUNT_PER_ROUND = 100 * KRW_PER_LOT
# default max amount for a single bet
MAXIMUM_BET_AMOUNT = 5000000  # 5mil KRW


class PhoneNumber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String, nullable=False, unique=True)
    verified = db.Column(db.Boolean, nullable=False)
    confirm_otp_hash = db.Column(db.String)
    confirm_otp_hash_expiry = db.Column(db.DateTime)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # display this as a string in the admin UI
    @property
    def admin_ui_summary(self):
        if self.verified:
            return self.phone
        else:
            return f'{self.phone} (unverified)'

    def __repr__(self):
        return f'<PhoneNumber id={self.id}, phone={self.phone}, verified={self.verified}>'

    def to_json(self):
        return {
            'id': self.id,
            'phone': self.phone,
            'verified': self.verified,
        }


class PromotionType(Enum):
    DEPOSIT_BONUS = "DEPOSIT_BONUS"


class Promotion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    promotion_type = db.Column(db.Enum(PromotionType))
    bonus_amount = db.Column(db.Integer, nullable=False, default=0)
    betting_volume_threshold = db.Column(db.Integer, nullable=False, default=0)
    user_balance_minimum = db.Column(db.Integer, nullable=False, default=0)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return (
            f'<Promotion id={self.id}, promotion_type={self.promotion_type.value}, '
            f'bonus_amount={self.bonus_amount}, betting_volume_threshold={self.betting_volume_threshold}, '
            f'user_balance_minimum={self.user_balance_minimum}'
            )

    def to_json(self):
        return {
            "id" : self.id,
            "promotion_type" : self.promotion_type.value,
            "bonus_amount" : self.bonus_amount,
            "betting_volume_threshold" : self.betting_volume_threshold,
            "user_balance_minimum" : self.user_balance_minimum,
            "created_at" : self.created_at,
            "updated_at" : self.updated_at,
        }
    
    def details(self):
        if self.promotion_type == PromotionType.DEPOSIT_BONUS:
            return f'{self.bonus_amount}Z ZZ ZZZ'
        else:
            return f'{self.promotion_type.value} not implemented'
    

class UserRole(Enum):
    HQ = "HQ"
    SOLE_DISTRIBUTOR = "SOLE_DISTRIBUTOR"
    PARTNER = "PARTNER"
    FRANCHISEE = "FRANCHISEE"
    REGULAR_USER = "REGULAR_USER"


USER_ROLE_TRANSLATIONS = {
    UserRole.HQ: "ZZ",
    UserRole.SOLE_DISTRIBUTOR: "ZZ",
    UserRole.PARTNER: "ZZ",
    UserRole.FRANCHISEE: "ZZ",
    UserRole.REGULAR_USER: "ZZ",
}


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String, unique=True)
    username = db.Column(db.String, nullable=False, unique=True)
    password_hash = db.Column(db.String, nullable=False)
    secondary_password_hash = db.Column(db.String, nullable=False)
    is_suspended = db.Column(db.Boolean, nullable=False)

    # personal info
    name = db.Column(db.String, nullable=False, index=True)
    email = db.Column(db.String, nullable=False, unique=True)
    dob = db.Column(db.String, nullable=False)
    phone_id = db.Column(db.Integer, db.ForeignKey('phone_number.id', ondelete='CASCADE'), nullable=False, unique=True)
    phone = db.relationship(PhoneNumber, backref='user')

    # required for KYC laws on all Korean betting sites
    # TODO: this is pretty sensitive PII, add a secrets service if there's time
    bank_name = db.Column(db.String, nullable=False)
    bank_account_number = db.Column(db.String, nullable=False)
    bank_account_holder = db.Column(db.String, nullable=False)  # name of the person who owns the bank account, not necessarily the same as the user's name

    # user account balance
    balance = db.Column(db.Integer, nullable=False)  # account balance in Won

    # it is only safe to decrease pending_commissions, never payable_commissions, because HQ admins may perform actions based on the value of payable_commissions that can't be undone
    # therefore, once commissions move from pending_commissions to payable_commissions, they also can no longer be undone
    pending_commissions = db.Column(db.Integer, nullable=False)  # commissions from this user's bets that are not yet ready to be paid to ancestors (usually because the round isn't over yet), in Won
    payable_commissions = db.Column(db.Integer, nullable=False)  # commissions from this user's bets that are ready to be paid to ancestors, in Won

    # Email Verification
    verification_code = db.Column(db.String)
    email_confirmed = db.Column(db.Boolean, nullable=False)

    # Forgot password
    reset_code = db.Column(db.String)
    reset_code_expiry = db.Column(db.DateTime)

    # Preferences
    agree_receive_email = db.Column(db.Boolean, default=False)
    agree_receive_text = db.Column(db.Boolean, default=False)

    # Partners
    role = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.REGULAR_USER)
    partner_name = db.Column(db.String, nullable=True, index=True)
    partner_referral_code = db.Column(db.String, unique=True)
    referring_user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True)
    referring_user = db.relationship('User', remote_side=[id], backref='referred_users')

    # Promotions
    owned_promotion_id = db.Column(db.Integer, db.ForeignKey('promotion.id', ondelete='SET NULL'), nullable=True)
    owned_promotion = db.relationship("Promotion", backref=db.backref("owner", uselist=False)) # one-to-one relationship

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    # todo(xuanji): should check that self.referring_user is not None
    def assert_hierarchy(self):
        if self.role == UserRole.HQ:
            assert self.referring_user is None, f"HQ {self.username} must not be referred by anyone"

        # populate referring_user
        db.session.refresh(self)
        assert self.referring_user is not None, f"User {self.username} must be referred by HQ, sole distributor, partner, or a franchisee"
        if self.role == UserRole.SOLE_DISTRIBUTOR:
            assert self.referring_user.role == UserRole.HQ, f"Sole distributor {self.username} must be referred by HQ"
        if self.role == UserRole.PARTNER:
            assert self.referring_user.role == UserRole.SOLE_DISTRIBUTOR, f"Partner {self.username} must be referred by a sole distributor"
        if self.role == UserRole.FRANCHISEE:
            assert self.referring_user.role == UserRole.PARTNER, f"Franchisee {self.username} must be referred by a partner"
        if self.role == UserRole.REGULAR_USER:
            assert self.referring_user.role == UserRole.FRANCHISEE, f"User {self.username} must be referred by a franchisee"

    def get_id(self):
        return f"{self.id}|{self.uuid}"

    def get_subordinate_role(self):
        return {
            UserRole.HQ: UserRole.SOLE_DISTRIBUTOR,
            UserRole.SOLE_DISTRIBUTOR: UserRole.PARTNER,
            UserRole.PARTNER: UserRole.FRANCHISEE,
            UserRole.FRANCHISEE: UserRole.REGULAR_USER
        }.get(self.role, UserRole.REGULAR_USER)

    # Flask-Login user methods
    @property
    def is_authenticated(self):
        return not self.is_suspended

    @property
    def is_partner(self):
        assert isinstance(self.role, UserRole), self.role
        return self.role in (UserRole.FRANCHISEE, UserRole.HQ, UserRole.SOLE_DISTRIBUTOR, UserRole.PARTNER)

    def get_franchisee(self):
        if self.role == UserRole.FRANCHISEE:
            return self.partner_name
        if self.referring_user is not None and self.referring_user.role == UserRole.FRANCHISEE:
            return self.referring_user.partner_name
        return ''

    def get_franchisee_username(self):
        if self.role == UserRole.FRANCHISEE:
            return self.username
        if self.referring_user is not None and self.referring_user.role == UserRole.FRANCHISEE:
            return self.referring_user.username
        return ''

    def get_branch(self):
        if self.role == UserRole.PARTNER:
            return self.partner_name
        if self.referring_user is not None:
            if self.referring_user.role == UserRole.PARTNER:
                return self.referring_user.partner_name
            elif self.referring_user.referring_user is not None and self.referring_user.referring_user.role == UserRole.PARTNER:
                return self.referring_user.referring_user.partner_name
        return ''

    def get_sole_distributor(self):
        if self.role == UserRole.SOLE_DISTRIBUTOR:
            return self.partner_name
        if self.referring_user is not None:
            if self.referring_user.role == UserRole.SOLE_DISTRIBUTOR: # partner
                return self.referring_user.partner_name
            elif self.referring_user.referring_user is not None:
                if self.referring_user.referring_user.role == UserRole.SOLE_DISTRIBUTOR: # franchisee
                    return self.referring_user.referring_user.partner_name
                elif (self.referring_user.referring_user.referring_user is not None 
                    and self.referring_user.referring_user.referring_user.role == UserRole.SOLE_DISTRIBUTOR):
                    return self.referring_user.referring_user.referring_user.partner_name
        return ''

    def __repr__(self):
        return f'<User {USER_ROLE_TRANSLATIONS.get(self.role)}, id={self.id}, username={self.username}, partner_name={self.partner_name}, referral_code={self.partner_referral_code}, name={self.name}, email={self.email}, balance={self.balance}>'

    def to_json(self):
        return {
            'id': self.id,
            'email': self.email,
            'email_confirmed': self.email_confirmed,
            'username': self.username,
            'name': self.name,
            'dob': self.dob,
            'phone': self.phone.to_json(),
            'bank_name': self.bank_name,
            'bank_account_number': self.bank_account_number,
            'bank_account_holder': self.bank_account_holder,
            'balance': self.balance,
            'pending_commissions': self.pending_commissions,
            'payable_commissions': self.payable_commissions,
            'role': self.role.value,
            'franchisee': self.get_franchisee(),
            'franchisee_username': self.get_franchisee_username(),
            'branch': self.get_branch(),
            'sole_distributor': self.get_sole_distributor(),
            'partner_name': self.partner_name,
            'partner_referral_code': self.partner_referral_code,
            'created_at': self.created_at.replace(tzinfo=timezone.utc).isoformat()
        }


class UserPromotion(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    promotion_id = db.Column(db.Integer, db.ForeignKey('promotion.id'), primary_key=True)
    promotion_activated = db.Column(db.Boolean, nullable=False, default=False)
    promotion_redeemed = db.Column(db.Boolean, nullable=False, default=False)

    user = db.relationship('User', backref='active_promotions')
    promotion = db.relationship('Promotion', backref='users_applied_to')

    def __repr__(self):
        return f'<UserPromotion user={self.user_id}, promotion={self.promotion_id}, promotion_redeemed={self.promotion_redeemed}>'

    def to_json(self):
        return {
            'user': self.user.to_json(),
            'promotion': self.promotion.to_json()
        }

    def apply_promotion_to_user(self, transaction):
        if (
            self.promotion.promotion_type == PromotionType.DEPOSIT_BONUS and  # this is a deposit bonus promotion
            (len(self.user.transactions) == 0 or (len(self.user.transactions) == 1 and self.user.transactions[0].id == transaction.id)) and  # this is the user's first transaction
            transaction.status == TransactionStatus.COMPLETE and  # this transaction is completed
            transaction.amount >= self.promotion.user_balance_minimum  # this transaction is above the promotion's eligibility minimum
        ):
            before_balance = self.user.balance
            self.user.balance += self.promotion.bonus_amount

            return BalanceChangeRecord(
                user_id=self.user.id,
                balance_change_type=BalanceChangeType.PROMOTION,
                details=self.promotion.details(),
                before_balance=before_balance,  # this is what John wants
                after_balance=self.user.balance,
            )
        return None

    def check_if_redeemable(self, transaction):
        if (self.promotion.promotion_type == PromotionType.DEPOSIT_BONUS):
            # can redeem if betting volume exceeds threshold
            bet_volume_query = db.session.query(
                db.func.sum(Bet.amount).label('bet_volume')
            ).filter(
                Bet.user_id == self.user.id
            ).filter(
                db.or_(Bet.bet_result != BetResult.CANCELLED,
                       Bet.bet_result != BetResult.PENDING)
            ).group_by(
                Bet.user_id
            ).one_or_none()
            bet_volume = bet_volume_query.bet_volume if bet_volume_query is not None else 0
            if bet_volume >= self.promotion.betting_volume_threshold:
                return True
        return False


class Exchange(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False, unique=True)
    description = db.Column(db.String, nullable=True)
    bet_and_lock_seconds = db.Column(db.Integer, nullable=False)
    max_spin_seconds = db.Column(db.Integer, nullable=False)
    round_decided_threshold = db.Column(db.Float, nullable=False)
    max_bet_amount = db.Column(db.Integer, nullable=False, default=MAXIMUM_BET_AMOUNT)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<Exchange {self.name} (#{self.id}), bet {self.bet_and_lock_seconds} seconds, wait {self.max_spin_seconds} seconds, round decided when change of {self.round_decided_threshold} detected>'

    def to_json(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'bet_and_lock_seconds': self.bet_and_lock_seconds,
            'max_spin_seconds': self.max_spin_seconds,
            'round_decided_threshold': self.round_decided_threshold,
            'max_bet_amount': self.max_bet_amount,
            'created_at': self.created_at.replace(tzinfo=timezone.utc).isoformat(),
        }


class RoundResult(Enum):
    NO_CHANGE = "NO_CHANGE"  # price didn't move at all, bets should be refunded (including commission)
    RISE = "RISE"  # price increased, bets of type BetType.RISE have won
    FALL = "FALL"  # price decreased, bets of type BetType.FALL have won


class RoundStatus(Enum):
    BETTING = "BETTING"  # The round is in the betting phase, bets can be placed until the round starts spinning (analogous to how you can place bets on a round of roulette up until they spin the wheel)
    LOCKING_IN_BETS = "LOCKING_IN_BETS"  # The round's bets have been locked in, but the spinning hasn't started yet.
    SPINNING = "SPINNING"  # round is currently being decided (analogous to a roulette wheel spinning)
    DECIDED = "DECIDED"  # round result is decided, so we're just waiting for this round to end while continuing to update the end price
    COMPLETED = "COMPLETED"  # the round has been completed, and is no longer being updated


class RoundLotTypeStatus(Enum):
    ENABLED = "ENABLED"    # This lot type is enabled for this round (i.e. the 10 lot option is enabled)
    ON_HOLD = "ON_HOLD"    # This lot type is on hold for this round, the admin may renable it later
    DISABLED = "DISABLED"  # This lot type is disabled for the rest of this round


class Round(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    round_date = db.Column(db.Date, nullable=False)
    round_number = db.Column(db.Integer, nullable=False)
    exchange_id = db.Column(db.Integer, db.ForeignKey('exchange.id', ondelete='CASCADE'), nullable=False)
    exchange = db.relationship(Exchange, backref='rounds')

    start_time = db.Column(db.DateTime, nullable=False)
    lock_in_bets_time = db.Column(db.DateTime, nullable=False)
    spinning_start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)

    total_rise_bets_amount = db.Column(db.Integer, nullable=False, default=0)
    total_fall_bets_amount = db.Column(db.Integer, nullable=False, default=0)
    max_rise_bets_amount = db.Column(db.Integer, nullable=False, default=MAX_BETTING_AMOUNT_PER_ROUND)
    max_fall_bets_amount = db.Column(db.Integer, nullable=False, default=MAX_BETTING_AMOUNT_PER_ROUND)

    rise_status_10_lot = db.Column(db.Enum(RoundLotTypeStatus), nullable=False, default=RoundLotTypeStatus.ENABLED)
    rise_status_5_lot = db.Column(db.Enum(RoundLotTypeStatus), nullable=False, default=RoundLotTypeStatus.ENABLED)
    rise_status_1_lot = db.Column(db.Enum(RoundLotTypeStatus), nullable=False, default=RoundLotTypeStatus.ENABLED)
    rise_status_0_5_lot = db.Column(db.Enum(RoundLotTypeStatus), nullable=False, default=RoundLotTypeStatus.ENABLED)
    rise_status_0_1_lot = db.Column(db.Enum(RoundLotTypeStatus), nullable=False, default=RoundLotTypeStatus.ENABLED)
    rise_status_0_05_lot = db.Column(db.Enum(RoundLotTypeStatus), nullable=False, default=RoundLotTypeStatus.ENABLED)
    fall_status_10_lot = db.Column(db.Enum(RoundLotTypeStatus), nullable=False, default=RoundLotTypeStatus.ENABLED)
    fall_status_5_lot = db.Column(db.Enum(RoundLotTypeStatus), nullable=False, default=RoundLotTypeStatus.ENABLED)
    fall_status_1_lot = db.Column(db.Enum(RoundLotTypeStatus), nullable=False, default=RoundLotTypeStatus.ENABLED)
    fall_status_0_5_lot = db.Column(db.Enum(RoundLotTypeStatus), nullable=False, default=RoundLotTypeStatus.ENABLED)
    fall_status_0_1_lot = db.Column(db.Enum(RoundLotTypeStatus), nullable=False, default=RoundLotTypeStatus.ENABLED)
    fall_status_0_05_lot = db.Column(db.Enum(RoundLotTypeStatus), nullable=False, default=RoundLotTypeStatus.ENABLED)

    # starting and ending BTC price (in USD) during SPINNING/DECIDED period for this round
    # note that we don't need exact price accuracy, so floats will do here
    start_price = db.Column(db.Float)
    end_price = db.Column(db.Float)
    max_price = db.Column(db.Float)
    min_price = db.Column(db.Float)
    trading_volume = db.Column(db.Float)
    round_result = db.Column(db.Enum(RoundResult), index=True)
    round_result_decided_time = db.Column(db.DateTime)
    round_result_decided_price = db.Column(db.Float)

    # The current status of the round. Use this to avoid using datetimes in code.
    round_status = db.Column(db.Enum(RoundStatus), nullable=False, index=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Round {self.id} on exchange {self.exchange_id}, {self.start_time} to {self.end_time}, status {self.round_status}, result {self.round_result}>'

    def to_json(self):
        return {
            'id': self.id,
            'round_date': self.round_date.isoformat(),
            'round_number': self.round_number,
            'start_time': self.start_time.replace(tzinfo=timezone.utc).isoformat(),
            'lock_in_bets_time': self.lock_in_bets_time.replace(tzinfo=timezone.utc).isoformat(),
            'spinning_start_time': self.spinning_start_time.replace(tzinfo=timezone.utc).isoformat(),
            'end_time': self.end_time.replace(tzinfo=timezone.utc).isoformat(),
            'total_rise_bets_amount': self.total_rise_bets_amount,
            'total_fall_bets_amount': self.total_fall_bets_amount,
            'max_rise_bets_amount': self.max_rise_bets_amount,
            'max_fall_bets_amount': self.max_fall_bets_amount,
            'rise_status_10_lot': self.rise_status_10_lot.value,
            'rise_status_5_lot': self.rise_status_5_lot.value,
            'rise_status_1_lot': self.rise_status_1_lot.value,
            'rise_status_0_5_lot': self.rise_status_0_5_lot.value,
            'rise_status_0_1_lot': self.rise_status_0_1_lot.value,
            'rise_status_0_05_lot': self.rise_status_0_05_lot.value,
            'fall_status_10_lot': self.fall_status_10_lot.value,
            'fall_status_5_lot': self.fall_status_5_lot.value,
            'fall_status_1_lot': self.fall_status_1_lot.value,
            'fall_status_0_5_lot': self.fall_status_0_5_lot.value,
            'fall_status_0_1_lot': self.fall_status_0_1_lot.value,
            'fall_status_0_05_lot': self.fall_status_0_05_lot.value,
            'start_price': self.start_price,
            'end_price': self.end_price,
            'max_price': self.max_price,
            'min_price': self.min_price,
            'trading_volume': self.trading_volume,
            'round_result': self.round_result and self.round_result.value,
            'round_result_decided_time': self.round_result_decided_time and self.round_result_decided_time.replace(tzinfo=timezone.utc).isoformat(),
            'round_result_decided_price': self.round_result_decided_price,
            'exchange': self.exchange.to_json(),
            'round_status': self.round_status.value,
            'created_at': self.created_at.replace(tzinfo=timezone.utc).isoformat(),
            'updated_at': self.updated_at.replace(tzinfo=timezone.utc).isoformat(),
        }


class BetType(Enum):
    FALL = "FALL"  # a bet that 1 BTC will be worth less USD later
    RISE = "RISE"  # a bet that 1 BTC will be worth more USD later


class BetResult(Enum):
    PENDING = "PENDING"  # bet result is still pending
    WON = "WON"  # bet was correct and should pay out
    LOST = "LOST"  # bet was incorrect and should not pay out
    CANCELLED = "CANCELLED"  # round was cancelled and the bet should be fully refunded, including commission


class Bet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    user = db.relationship(User, backref='bets')
    round_id = db.Column(db.Integer, db.ForeignKey('round.id', ondelete='CASCADE'), nullable=False)
    round = db.relationship(Round, backref='bets')
    bet_type = db.Column(db.Enum(BetType), nullable=False, index=True)
    amount = db.Column(db.Integer, nullable=False)  # bet amount in Won
    commission = db.Column(db.Integer, nullable=False)  # commission amount in Won
    bet_result = db.Column(db.Enum(BetResult), nullable=False, index=True)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<Bet for {self.bet_type.value} for user {self.user_id} of {self.amount} in round {self.round_id}>'

    def to_json(self):
        return {
            'id': self.id,
            'round': self.round.to_json(),
            'bet_type': self.bet_type.value,
            'amount': self.amount,
            'commission': self.commission,
            'created_at': self.created_at.replace(tzinfo=timezone.utc).isoformat(),
        }


class TransactionType(Enum):
    DEPOSIT = "DEPOSIT"  # money moves from user to Forecast
    WITHDRAWAL = "WITHDRAWAL"  # money moves from Forecast to user


class TransactionStatus(Enum):
    PENDING = "PENDING"  # transaction created by user, still needs to be confirmed by Forecast
    COMPLETE = "COMPLETE"  # transaction successfully confirmed by a human at Forecast
    ERROR = "ERROR"  # transaction could not be confirmed, according to a human at Forecast


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    user = db.relationship(User, backref='transactions')
    transaction_type = db.Column(db.Enum(TransactionType), nullable=False, index=True)
    amount = db.Column(db.Integer, nullable=False)  # transaction amount in Won
    status = db.Column(db.Enum(TransactionStatus), nullable=False, index=True)
    notes = db.Column(db.String)
    approval_date = db.Column(db.DateTime, nullable=True)
    fee = db.Column(db.Integer, nullable=False, default=0)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def relative_amount(self):
        if self.transaction_type == TransactionType.DEPOSIT:
            return self.amount - self.fee
        elif self.transaction_type == TransactionType.WITHDRAWAL:
            return -self.amount - self.fee
        else:
            raise ValueError(f"Unknown transaction type {self.transaction_type} for self: {self}")

    def details(self):
        if self.transaction_type == TransactionType.DEPOSIT:
            return f'{self.amount}Z ZZ'
        elif self.transaction_type == TransactionType.WITHDRAWAL:
            return f'{self.amount}Z ZZ'
        else:
            raise ValueError(f"Unknown transaction type {self.transaction_type} for self: {self}")

    def apply_new_status(self, new_status):
        old_status = self.status
        self.status = new_status
        if new_status == TransactionStatus.COMPLETE and old_status != TransactionStatus.COMPLETE:  # transaction was approved, apply transaction amount to user balance
            self.approval_date = datetime.utcnow()
            self.user.balance += self.relative_amount()
            return BalanceChangeRecord(
                user_id=self.user.id,
                balance_change_type=BalanceChangeType.TRANSACTION,
                details=self.details(),
                before_balance=self.user.balance,  # this is what John wants
                after_balance=self.user.balance,
            )
        elif new_status != TransactionStatus.COMPLETE and old_status == TransactionStatus.COMPLETE:  # transaction was unapproved, reverse effect of transaction on user balance
            self.user.balance -= self.relative_amount()
            return BalanceChangeRecord(
                user_id=self.user.id,
                balance_change_type=BalanceChangeType.REVERT_TRANSACTION,
                details=self.details() + '(cancelled)',
                before_balance=self.user.balance,  # this is what John wants
                after_balance=self.user.balance,
            )

    def __repr__(self):
        return f'<Transaction for {self.transaction_type.value} for user {self.user_id} of {self.amount} ({self.status.value})>'

    def to_json(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "transaction_type": self.transaction_type.value,
            "amount": self.amount,
            "status": self.status.value,
            "notes": self.notes,
            "created_at": self.created_at.replace(tzinfo=timezone.utc).isoformat(),
            "approval_date": self.approval_date.replace(tzinfo=timezone.utc).isoformat() if self.approval_date else None,
            "fee": self.fee,
        }


class BalanceChangeType(Enum):
    MANUAL = "MANUAL"
    COMMISSION = "COMMISSION"
    BET_WINNINGS = "BET_WINNINGS"
    BET = "BET"
    TRANSACTION = "TRANSACTION"
    PROMOTION = "PROMOTION"
    REVERT_TRANSACTION = "REVERT_TRANSACTION"
    BET_REFUND = "BET_REFUND"


class BalanceChangeRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    bet_id = db.Column(db.Integer, db.ForeignKey('bet.id', ondelete='CASCADE'))
    user = db.relationship(User, backref='balance_change_records')
    bet = db.relationship(Bet, backref='balance_change_records')
    balance_change_type = db.Column(db.Enum(BalanceChangeType), nullable=False, index=True)
    details = db.Column(db.String, nullable=False)
    principal = db.Column(db.Integer, nullable=False, default=0)
    arbitrage = db.Column(db.Integer, nullable=False, default=0)
    commission = db.Column(db.Integer, nullable=False, default=0)
    before_balance = db.Column(db.Integer, nullable=False)
    after_balance = db.Column(db.Integer, nullable=False)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f'<BalanceChangeRecord for user {self.user_id} regarding {self.details} changing balance from {self.before_balance} to {self.after_balance}>'

    def to_json(self):
        return {
            "id": self.id,
            "user": self.user.to_json(),
            "bet_id": self.bet_id,
            "balance_change_type": self.balance_change_type.value,
            "details": self.details,
            "principal": self.principal,
            "arbitrage": self.arbitrage,
            "commission": self.commission,
            "before_balance": self.before_balance,
            "after_balance": self.after_balance,
            "created_at": self.created_at.replace(tzinfo=timezone.utc).isoformat(),
        }


class TicketStatus(Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"


class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    user = db.relationship(User, backref='tickets')
    subject = db.Column(db.String, nullable=False)
    user_message = db.Column(db.String, nullable=False)
    admin_username = db.Column(db.String, nullable=True)
    admin_message = db.Column(db.String, nullable=True)
    status = db.Column(db.Enum(TicketStatus), nullable=False, index=True, default=TicketStatus.OPEN)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<Ticket (#{self.id}) "{self.subject}" status {self.status} for user {self.user_id} created at {self.created_at.isoformat()}'

    def to_json(self, include_messages=False):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "subject": self.subject,
            "status": self.status.value,
            "user_message": self.user_message,
            "admin_username": self.admin_username,
            "admin_message": self.admin_message,
            "created_at": self.created_at.replace(tzinfo=timezone.utc).isoformat(),
            "updated_at": self.updated_at.replace(tzinfo=timezone.utc).isoformat(),
        }


class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    content = db.Column(db.String, nullable=False)
    view_count = db.Column(db.Integer, default=0)

    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'Announcement {self.title} created at {self.created_at.isoformat()}'

    def to_json(self):
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "view_count": self.view_count,
            "created_at": self.created_at.replace(tzinfo=timezone.utc).isoformat(),
            "updated_at": self.updated_at.replace(tzinfo=timezone.utc).isoformat(),
        }
