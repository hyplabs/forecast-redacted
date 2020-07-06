import logging
import os
from os import path
from datetime import datetime

from flask import jsonify, request, flash
from werkzeug.security import generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_admin import Admin
from flask_admin.actions import action
from flask_admin.base import AdminIndexView
from flask_admin.form import SecureForm
from flask_admin.contrib.sqla import ModelView
from flask_babelex import Babel, lazy_gettext
from wtforms.fields import PasswordField, TextAreaField

import caching
from models import (
    app, db, PhoneNumber, User, Transaction, Ticket,
    Exchange, TransactionStatus, TransactionType, TicketStatus,
    Announcement, BalanceChangeRecord, BalanceChangeType, UserRole,
    Promotion, PromotionType, UserPromotion, USER_ROLE_TRANSLATIONS
)
from yubikey_auth import auth_init_app, auth_get_current_username
from util import generate_uuid

logging.basicConfig(level=logging.WARN)
logger = logging.getLogger("admin")
logger.setLevel(logging.INFO)

app.config['FLASK_ADMIN_SWATCH'] = 'flatly'

BASE_URL = '/admin'


###############
# set up auth #
###############

@app.route('/api/healthcheck')
def healthcheck():
    return jsonify(status='success')


app.secret_key = os.environ['ADMIN_FLASK_SECRET_KEY']
auth_init_app(app)


######################
# set up Flask-Admin #
######################

# NOTE: we have every ModelView implement its own create/update/delete functionality to make security review easier;
# Flask-Admin's SQLAlchemy integration is very expressive, but is very difficult to audit due to its extensive use of metaprogramming
# additionally, we further reduce attack surface by not depending on WTForms security guarantees
class CustomModelView(ModelView):
    form_base_class = SecureForm  # CSRF-protected form class
    column_display_pk = True  # show primary key columns

    can_create = False
    can_edit = False
    can_delete = False
    page_size = 10

    def validate_form(self, form):
        # delete any fields that are marked readonly, this avoids an error where readonly fields are submitted as empty and fail validation,
        # even though we're just going to throw away the result immediately afterwards anyway
        for field_name in form.data:
            render_kw = getattr(form, field_name).render_kw
            if render_kw is not None and render_kw.get('readonly'):
                delattr(form, field_name)
        return super().validate_form(form)

    def create_model(self, form):
        raise NotImplementedError()

    def update_model(self, form, model):
        raise NotImplementedError()

    def delete_model(self, model):
        raise NotImplementedError()


del ModelView  # don't allow ModelView to be used, use CustomModelView instead

############################
# set up Flask-Admin views #
############################


class PhoneNumberView(CustomModelView):
    column_labels = {
        "id": lazy_gettext("ID"),
        "phone": lazy_gettext("Phone"),
        "verified": lazy_gettext("Verified"),
        "created_at": lazy_gettext("Created"),
    }
    form_columns = ['phone', 'verified', 'created_at']
    column_editable_list = ['verified']
    column_list = ['id'] + form_columns
    column_filters = column_list
    column_display_actions = False
    can_create = True
    can_edit = True

    def create_model(self, form):
        try:
            assert isinstance(form.phone.data, str) and form.phone.data != '', form.phone.data
            assert isinstance(form.verified.data, bool), form.verified.data
            model = PhoneNumber(phone=form.phone.data, verified=form.verified.data)
            self.session.add(model)
            self.session.commit()
            logger.info(f'PhoneNumber create by admin {auth_get_current_username()}: {model.to_json()}')
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to create phone number. {str(ex)}', 'error')
            logger.exception(f'PhoneNumber update by admin {auth_get_current_username()} raised exception')
            return False
        return True

    def update_model(self, form, model):
        try:
            original_model_json = model.to_json()
            assert isinstance(form.verified.data, bool), form.verified.data
            model.verified = form.verified.data
            self.session.add(model)
            self.session.commit()
            logger.info(f'PhoneNumber update by admin {auth_get_current_username()}: {original_model_json} -> {model.to_json()}')
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to update phone number. {str(ex)}', 'error')
            logger.exception(f'PhoneNumber update by admin {auth_get_current_username()} raised exception')
            return False
        return True


class UserView(CustomModelView):
    column_labels = {
        "id": lazy_gettext("ID"),
        "username": lazy_gettext("Username"),
        "name": lazy_gettext("Name"),
        "email": lazy_gettext("Email"),
        "email_confirmed": lazy_gettext("Is Email Confirmed?"),
        "dob": lazy_gettext("Date Of Birth"),
        "pending_commissions": lazy_gettext("Pending Commissions"),
        "payable_commissions": lazy_gettext("Payable Commissions"),
        "agree_receive_email": lazy_gettext("Agreed To Receive Emails?"),
        "agree_receive_text": lazy_gettext("Agreed To Receive Texts?"),
        "phone": lazy_gettext("Phone"),
        "is_suspended": lazy_gettext("Is Suspended?"),
        "bank_name": lazy_gettext("Bank Name"),
        "bank_account_number": lazy_gettext("Bank Account Number"),
        "balance": lazy_gettext("Balance"),
        "created_at": lazy_gettext("Created"),
        "password": lazy_gettext("Password"),
        "secondary_password": lazy_gettext("Secondary Password"),
        "role": lazy_gettext("Role"),
        "partner_name": lazy_gettext("Partner Name"),
        "partner_referral_code": lazy_gettext("Referral Code"),
        "referring_user": lazy_gettext("Referred By"),
        "owned_promotion": lazy_gettext("Owned Promotion")
    }
    column_list =          ['id', 'username',                                   'is_suspended', 'name', 'email', 'dob', 'phone', 'bank_name', 'bank_account_number', 'bank_account_holder', 'balance', 'pending_commissions', 'payable_commissions', 'email_confirmed', 'agree_receive_email', 'agree_receive_text', 'role', 'partner_name', 'partner_referral_code', 'referring_user', 'owned_promotion', 'created_at']
    column_editable_list = [                                                    'is_suspended', 'name', 'email', 'dob',          'bank_name', 'bank_account_number', 'bank_account_holder', 'balance', 'pending_commissions', 'payable_commissions', 'email_confirmed', 'agree_receive_email', 'agree_receive_text', 'role', 'partner_name', 'partner_referral_code']
    form_columns =         [      'username', 'password', 'secondary_password', 'is_suspended', 'name', 'email', 'dob', 'phone', 'bank_name', 'bank_account_number', 'bank_account_holder', 'balance',                                                                                                               'role', 'partner_name', 'partner_referral_code', 'referring_user', 'owned_promotion', 'created_at']
    column_filters = [
        'id',
        'username',
        'name',
        'email',
        'partner_name',
        'is_suspended',
        'role',
        'phone.phone',
        'partner_referral_code',
    ]
    column_formatters = dict(role=lambda v, c, m, p: USER_ROLE_TRANSLATIONS.get(m.role, "None"))
    form_extra_fields = {
        'password': PasswordField(lazy_gettext('Password')),
        'secondary_password': PasswordField(lazy_gettext('Secondary Password'))
    }
    form_widget_args = {
        'created_at': {'readonly': True, 'required': False, 'default': datetime(1970, 1, 1)},
    }
    form_ajax_refs = {
        'phone': {'fields': ['id', 'phone'], 'page_size': 10, 'minimum_input_length': 0},
        'referring_user': {'fields': ['id', 'partner_name', 'username', 'partner_referral_code', 'name'], 'page_size': 10, 'minimum_input_length': 0},
    }
    can_create = True
    can_edit = True

    list_template = 'user_list.html'

    # comment this out because they want username to be editable...?
    # # only called in edit mode, use this to configure fields in the edit form but not in the create form
    # def on_form_prefill(self, form, id):
    #     form.username.render_kw = {'readonly': True, 'required': False}

    def create_model(self, form):
        form_data = form.data
        try:
            if form.password.data == '':
                raise Exception('Password cannot be empty')
            if form.secondary_password.data == '':
                raise Exception('Secondary password cannot be empty')
            if not isinstance(form.phone.data, PhoneNumber):
                raise Exception('Phone field must be a PhoneNumber object')
            model = User(
                uuid=generate_uuid(),
                username=form.username.data,
                phone_id=form.phone.data.id,
                password_hash=generate_password_hash(form.password.data),
                email_confirmed=True,
                agree_receive_email=True,
                agree_receive_text=True,
                pending_commissions=0,
                payable_commissions=0,
                secondary_password_hash=generate_password_hash(form.secondary_password.data),
                referring_user_id=form.referring_user.data.id if form.referring_user.data else None,
                owned_promotion_id=form.owned_promotion.data.id if form.owned_promotion.data else None,
            )
            for editable_column in self.column_editable_list:
                if editable_column in form_data:
                    setattr(model, editable_column, form_data[editable_column])
            # auto confirm email for partners
            if model.role != UserRole.REGULAR_USER.value:
                model.email_confirmed = True
            model.assert_hierarchy()
            self.session.add(model)
            self.session.commit()
            caching.set_user(model)
            logger.info(f'User create by admin {auth_get_current_username()}: {model.to_json()}')
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to create user. {str(ex)}', 'error')
            logger.exception(f'User create by admin {auth_get_current_username()} raised exception')
            return False
        return True

    def update_model(self, form, model):
        form_data = form.data
        try:
            original_model_json = model.to_json()
            # referring_user can't be in the column_editable_list because it's not supported for inline edits.
            for editable_column in self.column_editable_list + ['referring_user', 'username']:
                if editable_column in form_data:
                    setattr(model, editable_column, form_data[editable_column])
            if form.role.data != UserRole.FRANCHISEE.value:
                assert model.owned_promotion is None and form_data['owned_promotion'] is None
            # TODO: check to make sure a promotion isn't being taken away from another user
            if form.password.data != '':  # reset password if new password entered
                assert isinstance(form.password.data, str), form.password.data
                model.uuid = generate_uuid()  # log the user out of all existing sessions
                model.password_hash = generate_password_hash(form.password.data)
                logger.info(f'User update by admin {auth_get_current_username()} was a password reset for {model}')
            if form.secondary_password.data != '':  # reset secondary password if new secondary password entered
                assert isinstance(form.secondary_password.data, str), form.secondary_password.data
                model.uuid = generate_uuid()  # log the user out of all existing sessions
                model.secondary_password_hash = generate_password_hash(form.secondary_password.data)
                logger.info(f'User update by admin {auth_get_current_username()} was a secondary password reset for {model}')
            if form.is_suspended.data != model.is_suspended:  # user suspended or unsuspended
                assert isinstance(form.is_suspended.data, bool), form.is_suspended.data
                model.uuid = generate_uuid()  # log the user out of all existing sessions
            if form.owned_promotion.data:
                model.owned_promotion_id = form.owned_promotion.data.id
            model.assert_hierarchy()
            self.session.add(model)
            self.session.commit()
            caching.set_user(model)
            logger.info(f'User updated by admin {auth_get_current_username()}: {original_model_json} -> {model.to_json()}')
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to update user. {str(ex)}', 'error')
            logger.exception(f'User update by admin {auth_get_current_username()} raised exception')
            return False
        return True


TRANSACTION_COLUMN_LABELS = {
    "id": lazy_gettext("ID"),
    "user.username": lazy_gettext("Username"),
    "user.name": lazy_gettext("Name"),
    "user.phone.admin_ui_summary": lazy_gettext("Phone"),
    "user.bank_name": lazy_gettext("Bank Name"),
    "user.bank_account_number": lazy_gettext("Bank Account Number"),
    "user.bank_account_holder": lazy_gettext("Account Holder"),
    "amount" : lazy_gettext("Amount"),
    "transaction_type": lazy_gettext("Transaction Type"),
    "transaction_status": lazy_gettext("Transaction Status"),
    "status": lazy_gettext("Transaction Status"),
    "notes": lazy_gettext("Notes"),
    "created_at": lazy_gettext("Created"),
    "approval_date": lazy_gettext("Date Approved"),
    "fee": lazy_gettext("Fee"),
}


class MassApproveDepositsView(CustomModelView):
    def get_query(self):
        return super(MassApproveDepositsView, self).get_query().filter(Transaction.transaction_type == TransactionType.DEPOSIT).filter(Transaction.status == TransactionStatus.PENDING)

    @action('approve', 'Approve', 'are you want to mass approve deposits?')
    def action_approve(self, ids):
        query = Transaction.query.filter(Transaction.id.in_(ids))
        for transaction in query.all():
            balance_change_record = transaction.apply_new_status(TransactionStatus.COMPLETE)
            if balance_change_record:
                self.session.add(balance_change_record)

            for user_promotion in UserPromotion.query.filter_by(user_id=transaction.user_id, promotion_activated=False):
                promotion_balance_change_record = user_promotion.apply_promotion_to_user(transaction)
                if promotion_balance_change_record:
                    self.session.add(promotion_balance_change_record)
                    user_promotion.promotion_activated = True
                    self.session.add(user_promotion)

            self.session.add(transaction)
        self.session.commit()

    column_labels = TRANSACTION_COLUMN_LABELS
    column_list = ['created_at', 'user.username', 'user.name', 'user.phone.admin_ui_summary', 'user.bank_name', 'user.bank_account_number', 'user.bank_account_holder', 'amount', 'transaction_type', 'status', 'notes']


class MassApproveWithdrawalsView(CustomModelView):
    def get_query(self):
        return super(MassApproveWithdrawalsView, self).get_query().filter(Transaction.transaction_type == TransactionType.WITHDRAWAL).filter(Transaction.status == TransactionStatus.PENDING)

    @action('approve', 'Approve', 'are you want to mass approve deposits?')
    def action_approve(self, ids):

        query = Transaction.query.filter(Transaction.id.in_(ids))
        for transaction in query.all():
            balance_change_record = transaction.apply_new_status(TransactionStatus.COMPLETE)
            if balance_change_record:
                self.session.add(balance_change_record)
            self.session.add(transaction)

        self.session.commit()

    column_labels = TRANSACTION_COLUMN_LABELS
    column_list = ['created_at', 'user.username', 'user.name', 'user.phone.admin_ui_summary', 'user.bank_name', 'user.bank_account_number', 'user.bank_account_holder', 'amount', 'transaction_type', 'status', 'fee', 'notes']


class TransactionView(CustomModelView):
    column_labels = TRANSACTION_COLUMN_LABELS
    column_list =          ['created_at', 'user.username', 'user.name', 'user.phone.admin_ui_summary', 'user.bank_name', 'user.bank_account_number', 'user.bank_account_holder', 'amount', 'transaction_type', 'status', 'approval_date', 'fee', 'notes']
    column_editable_list = ['amount', 'status', 'notes']
    column_filters = []
    column_display_actions = False
    can_edit = False

    def update_model(self, form, model):
        try:
            if form.amount is not None:
                assert isinstance(form.amount.data, int) and form.amount.data > 0, form.amount.data
                model.amount = form.amount.data
            if form.notes is not None:
                assert isinstance(form.notes.data, str), form.notes.data
                model.notes = form.notes.data

            if form.status is not None:
                new_status = TransactionStatus[form.status.data]
                balance_change_record = model.apply_new_status(new_status)
                if balance_change_record:
                    self.session.add(balance_change_record)

            for user_promotion in UserPromotion.query.filter_by(user_id=model.user_id, promotion_activated=False):
                promotion_balance_change_record = user_promotion.apply_promotion_to_user(model)
                if promotion_balance_change_record:
                    self.session.add(promotion_balance_change_record)
                    user_promotion.promotion_activated = True
                    self.session.add(user_promotion)

            self.session.add(model)
            self.session.commit()
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to update transaction. {str(ex)}', 'error')
            logger.exception(f'Transaction update by admin {auth_get_current_username()} raised exception')
            return False
        return True


class BalanceChangeRecordView(CustomModelView):
    column_list = ['user.username', 'user.name', 'before_balance', 'amount', 'after_balance', 'created_at', 'balance_change_type', 'details', 'principal', 'arbitrage', 'commission']

    can_create = True
    form_create_rules = ('user', 'details', 'principal')

    def create_model(self, form):


        try:
            user_id = form.user.data.id
            amount = form.principal.data

            assert isinstance(form.details.data, str)
            assert isinstance(amount, int)
            assert isinstance(user_id, int)

            user = User.query.filter_by(id=user_id).one()

            balance_change_record = BalanceChangeRecord(
                user_id=user.id,
                balance_change_type=BalanceChangeType.MANUAL,
                details=form.details.data,
                principal=form.principal.data,
                before_balance=user.balance,
                after_balance=user.balance + amount,
            )

            user.balance += amount
            self.session.add(user)
            self.session.add(balance_change_record)
            self.session.commit()

            return True
        except Exception as ex:
            flash(f'Failed to create charge/discharge. {str(ex)}', 'error')
            return False


class TicketView(CustomModelView):
    column_labels = {
        "id": lazy_gettext("ID"),
        "user": lazy_gettext("User"),
        "subject": lazy_gettext("Subject"),
        "user_message": lazy_gettext("Message"),
        "admin_username": lazy_gettext("Administrator"),
        "admin_message": lazy_gettext("Administrator Response"),
        "status": lazy_gettext("Ticket Status"),
        "created_at": lazy_gettext("Created"),
        "updated_at": lazy_gettext("Updated")
    }
    column_list = ['id', 'user', 'subject', 'user_message', 'admin_username', 'admin_message', 'status', 'created_at', 'updated_at']
    column_editable_list = ['admin_message', 'status']
    column_filters = ['user.username']
    form_columns = ['user', 'subject', 'user_message', 'admin_username', 'admin_message', 'status']
    form_overrides = {
        'user_message': lambda *args, **kwargs: TextAreaField(*args, **kwargs),
        'admin_message': lambda *args, **kwargs: TextAreaField(*args, **kwargs),
    }
    form_widget_args = {
        'user': {'readonly': True },
        'subject': {'readonly': True },
        'user_message': {'readonly': True },
        'admin_username': {'readonly': True },
    }
    column_display_actions = True
    can_edit = True

    edit_template = 'ticket_edit.html'

    def update_model(self, form, model):
        try:
            original_model_json = model.to_json()
            if form.status is not None:
                model.status = TicketStatus[form.status.data]
            if form.admin_message is not None:
                assert isinstance(form.admin_message.data, str) and form.admin_message.data != '', form.admin_message.data
                model.admin_message = form.admin_message.data

            model.admin_username = auth_get_current_username()
            self.session.add(model)
            self.session.commit()
            logger.info(f'Ticket update by admin {auth_get_current_username()}: {original_model_json} -> {model.to_json()}')
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to update ticket. {str(ex)}', 'error')
            logger.exception(f'Ticket update by admin {auth_get_current_username()} raised exception')
            return False
        return True


class ExchangeView(CustomModelView):
    column_labels = {
        "id": lazy_gettext("ID"),
        "name": lazy_gettext("Name"),
        "description": lazy_gettext("Description"),
        "bet_and_lock_seconds": lazy_gettext("Bet Time (Seconds)"),
        "max_spin_seconds": lazy_gettext("Wait Time (Seconds)"),
        "round_decided_threshold": lazy_gettext("Round Decided Threshold"),
        "max_bet_amount": lazy_gettext("Max Bet Amount (Won)"),
        "created_at": lazy_gettext("Created")
    }
    column_list =          ['id', 'name', 'description', 'bet_and_lock_seconds', 'max_spin_seconds', 'round_decided_threshold', 'max_bet_amount', 'created_at']
    column_editable_list = [                                                                         'round_decided_threshold', 'max_bet_amount']
    column_filters = ['name', 'bet_and_lock_seconds', 'max_spin_seconds']
    column_display_actions = False
    can_edit = True

    def update_model(self, form, model):
        try:
            original_model_json = model.to_json()
            if form.max_bet_amount is not None:
                assert isinstance(form.max_bet_amount.data, int) and form.max_bet_amount.data >= 0, form.max_bet_amount.data
                model.max_bet_amount = form.max_bet_amount.data
            self.session.add(model)
            self.session.commit()
            logger.info(f'Exchange update by admin {auth_get_current_username()}: {original_model_json} -> {model.to_json()}')
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to update exchange. {str(ex)}', 'error')
            logger.exception(f'Exchange update by admin {auth_get_current_username()} raised exception')
            return False
        return True


class AnnouncementView(CustomModelView):
    column_labels = {
        "id": lazy_gettext("ID"),
        "title": lazy_gettext("Title"),
        "content": lazy_gettext("Content"),
        "view_count": lazy_gettext("Views"),
        "created_at": lazy_gettext("Created"),
        "updated_at": lazy_gettext("Updated"),
    }
    column_list =          ['id', 'title', 'content', 'view_count', 'created_at', 'updated_at']
    column_default_sort = ('created_at', True)
    column_editable_list = [      'title', 'content']
    form_columns =         [      'title', 'content']
    action_disallowed_list = ['delete']
    form_overrides = {
        'content': lambda *args, **kwargs: TextAreaField(*args, **kwargs),
    }
    can_create = True
    can_edit = True
    can_delete = True
    page_size = 10

    def create_model(self, form):
        try:
            assert isinstance(form.content.data, str) and form.content.data != '', form.content.data
            assert isinstance(form.title.data, str) and form.title.data != '', form.title.data
            model = Announcement(
                title=form.title.data,
                content=form.content.data,
            )
            self.session.add(model)
            self.session.commit()
            logger.info(f'Announcement create by admin {auth_get_current_username()}: {model.to_json()}')
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to create announcement. {str(ex)}', 'error')
            logger.exception(f'Announcement create by admin {auth_get_current_username()} raised exception')
            return False
        return True

    def update_model(self, form, model):
        try:
            original_model_json = model.to_json()
            if form.content is not None:
                assert isinstance(form.content.data, str) and form.content.data != '', form.content.data
                model.content = form.content.data
            if form.title is not None:
                assert isinstance(form.title.data, str) and form.title.data != '', form.title.data
                model.title = form.title.data

            self.session.add(model)
            self.session.commit()
            logger.info(f'Announcement update by admin {auth_get_current_username()}: {original_model_json} -> {model.to_json()}')
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to update announcement. {str(ex)}', 'error')
            logger.exception(f'Announcement update by admin {auth_get_current_username()} raised exception')
            return False
        return True

    def delete_model(self, model):
        try:
            self.session.delete(model)
            self.session.commit()
            logger.info(f'Announcement delete by admin {auth_get_current_username()}: {model.to_json()}')
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to delete announcement. {str(ex)}', 'error')
            logger.exception(f'Announcement delete by admin {auth_get_current_username()} raised exception')
            return False
        return True 

class PromotionView(CustomModelView):
    column_labels = {
        "id" : lazy_gettext("ID"),
        "promotion_type" : lazy_gettext("Promotion Type"),
        "bonus_amount" : lazy_gettext("Bonus Amount"),
        "betting_volume_threshold" : lazy_gettext("Betting Volume Threshold"),
        "user_balance_minimum" : lazy_gettext("User Balance Minimum"),
        "created_at" : lazy_gettext("Created"),
        "updated_at" : lazy_gettext("Updated"),
    }

    form_columns = ['promotion_type', 'bonus_amount', 'betting_volume_threshold', 'user_balance_minimum']

    can_create = True
    can_edit = True
    can_delete = True

    def create_model(self, form):
        try:
            assert form.promotion_type is not None and form.promotion_type.data in PromotionType.__members__
            assert isinstance(form.bonus_amount.data, int) and form.bonus_amount.data > 0
            assert isinstance(form.betting_volume_threshold.data, int) and form.bonus_amount.data > 0
            assert isinstance(form.user_balance_minimum.data, int) and form.bonus_amount.data > 0
            model = Promotion(
                promotion_type=PromotionType[form.promotion_type.data],
                bonus_amount=form.bonus_amount.data,
                betting_volume_threshold=form.betting_volume_threshold.data,
                user_balance_minimum=form.user_balance_minimum.data
            )
            self.session.add(model)
            self.session.commit()
            logger.info(f'Promotion created by admin {auth_get_current_username()}: {model.to_json()}')
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to create promotion. {str(ex)}', 'error')
            logger.exception(f'Promotion create by admin {auth_get_current_username()} raised exception')
            return False
        return True

    def update_model(self, form, model):
        try:
            original_model_json = model.to_json()
            if form.promotion_type is not None:
                assert form.promotion_type.data in PromotionType.__members__
                model.promotion_type = PromotionType[form.promotion_type.data]
            if form.bonus_amount is not None:
                assert isinstance(form.bonus_amount.data, int) and form.bonus_amount.data > 0
                model.bonus_amount = form.bonus_amount.data
            if form.betting_volume_threshold is not None:
                assert isinstance(form.betting_volume_threshold.data, int) and form.bonus_amount.data > 0
                model.betting_volume_threshold = form.betting_volume_threshold.data
            if form.user_balance_minimum is not None:
                assert isinstance(form.user_balance_minimum.data, int) and form.bonus_amount.data > 0
            self.session.add(model)
            self.session.commit()
            logger.info(f'Promotion update by admin {auth_get_current_username()}: {original_model_json} -> {model.to_json()}')
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to update promotion. {str(ex)}', 'error')
            logger.exception(f'Promotion update by admin {auth_get_current_username()} raised exception')
            return False
        return True

    def delete_model(self, model):
        try:
            self.session.delete(model)
            self.session.commit()
            logger.info(f'Promotion delete by admin {auth_get_current_username()}: {model.to_json()}')
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to delete promotion. {str(ex)}', 'error')
            logger.exception(f'Promotion delete by admin {auth_get_current_username()} raised exception')
            return False
        return True 


USER_PROMOTION_COLUMN_LABELS = {
        'user' : lazy_gettext("User"),
        'promotion' : lazy_gettext("Promotion"),
        'promotion_redeemed' : lazy_gettext("Is Promotion Redeemed?"),
        'promotion_activated' : lazy_gettext("Is Promotion Activated?")
    }


class MassChangeUserPromotionView(CustomModelView):
    column_labels = USER_PROMOTION_COLUMN_LABELS
    column_filters = [
        'user.referring_user.partner_referral_code',
        'promotion.id',
        'promotion_redeemed',
        'promotion_activated',
    ]
    can_delete = True
    list_template = 'mass_change_user_promotion_list.html'

    @action('batch_change_promotion', lazy_gettext('Mass Change User Promotion'), lazy_gettext("Are you sure you want to mass change UserPromotions?"))
    def action_batch_alter(self, ids):
        try:
            if request.form['promotion_id'] is '':
                raise Exception(lazy_gettext('No new promotion ID entered.'))
            new_promotion_id = int(request.form['promotion_id'])
            new_promotion = Promotion.query.filter_by(id=new_promotion_id).one_or_none()
            if new_promotion is None:
                raise Exception(lazy_gettext('New promotion not found.'))
            
            user_promotion_ids = [(id_pair.split(',')[0], id_pair.split(',')[1]) for id_pair in ids]
            user_promotions = UserPromotion.query.filter(
                    db.or_(
                        db.and_(UserPromotion.user_id == user_id, UserPromotion.promotion_id == promotion_id)
                        for user_id, promotion_id in user_promotion_ids
                    ))
            count = 0
            for user_promotion in user_promotions.all():
                user_promotion.promotion_id = new_promotion_id
                self.session.add(user_promotion)
                count += 1
            self.session.commit()
            flash(lazy_gettext("Successfully Changed") + f" {count} " + lazy_gettext("Records"))
            logger.info(f'Batch UserPromotion change by admin {auth_get_current_username()} changed {count} UserPromotions')
        except Exception as ex:
            self.session.rollback()
            flash(lazy_gettext("Error ") + f"{str(ex)}")
            logger.exception(f'Batch UserPromotion change by admin {auth_get_current_username()} raised exception')


class UserPromotionView(CustomModelView):
    column_labels = USER_PROMOTION_COLUMN_LABELS
    can_create = True
    can_delete = True

    column_editable_list = ['promotion']

    column_filters = [
        'user.referring_user.partner_referral_code',
        'promotion.id',
        'promotion_redeemed',
        'promotion_activated',
    ]

    def create_model(self, form):
        try:
            if form.user.data.role != UserRole.REGULAR_USER:
                raise Exception('Can only apply promotions to regular users')
            model = UserPromotion(
                user=form.user.data,
                promotion=form.promotion.data
            )
            self.session.add(model)
            self.session.commit()
            logger.info(f'UserPromotion created by admin {auth_get_current_username()}: {model.to_json()}')
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to create user promotion relationship. {str(ex)}', 'error')
            logger.exception(f'UserPromotion create by admin {auth_get_current_username()} raised exception')
            return False
        return True

    def delete_model(self, model):
        try:
            self.session.delete(model)
            self.session.commit()
            logger.info(f'UserPromotion delete by admin {auth_get_current_username()}: {model.to_json()}')
        except Exception as ex:
            self.session.rollback()
            flash(f'Failed to delete UserPromotion. {str(ex)}', 'error')
            logger.exception(f'UserPromotion delete by admin {auth_get_current_username()} raised exception')
            return False
        return True


# set up Flask-Admin
admin = Admin(app, name='Forecast', base_template='layout.html', template_mode='bootstrap3', index_view=AdminIndexView(url=BASE_URL), static_url_path="static")
admin.add_view(PhoneNumberView(PhoneNumber, db.session, name=lazy_gettext("Phone"), url=f"{BASE_URL}/phone_number"))
admin.add_view(UserView(User, db.session, name=lazy_gettext("User"), category=lazy_gettext("Member Management"), url=f"{BASE_URL}/user"))
admin.add_view(MassApproveDepositsView(Transaction, db.session, name=lazy_gettext("Mass Approve Deposits"), endpoint="approve-deposits", category="Member Management", url=f"{BASE_URL}/mass_approve_deposits"))
admin.add_view(MassApproveWithdrawalsView(Transaction, db.session, name=lazy_gettext("Mass Approve Withdrawals"), endpoint="approve-withdrawals", category="Member Management", url=f"{BASE_URL}/mass_approve_withdrawals"))
admin.add_view(BalanceChangeRecordView(BalanceChangeRecord, db.session, name=lazy_gettext("Balance Change Records/Charge/Discharge"), endpoint="balance-changes", category="Member Management", url=f"{BASE_URL}/balance_change_record"))
admin.add_view(TransactionView(Transaction, db.session, name=lazy_gettext("Transaction"), category="Member Management", url=f"{BASE_URL}/transaction"))
admin.add_view(TicketView(Ticket, db.session, name=lazy_gettext("Ticket"), url=f"{BASE_URL}/ticket"))
admin.add_view(ExchangeView(Exchange, db.session, name=lazy_gettext("Exchange"), url=f"{BASE_URL}/exchange"))
admin.add_view(AnnouncementView(Announcement, db.session, name=lazy_gettext("Announcement"), url=f"{BASE_URL}/announcement"))
admin.add_view(PromotionView(Promotion, db.session, name=lazy_gettext("Promotion"), category=lazy_gettext("Promotion Management"), url=f"{BASE_URL}/promotion"))
admin.add_view(MassChangeUserPromotionView(UserPromotion, db.session, name=lazy_gettext("Mass Change User Promotion"), endpoint="change-user-promotion", category=lazy_gettext("Promotion Management"), url=f"{BASE_URL}/mass_change_user_promotion"))
admin.add_view(UserPromotionView(UserPromotion, db.session, name=lazy_gettext("User Promotion"), category=lazy_gettext("Promotion Management"), url=f"{BASE_URL}/user_promotion"))


########################
# set up Flask-BabelEx #
########################

# to manage these translations, see the commands in https://pythonhosted.org/Flask-BabelEx/#translating-applications (these commands can be run in the `make enter_web` shell)
# we used the following commands to set things up: `cd /app/backend/admin; pybabel extract -F babel.cfg -k lazy_gettext -o messages.pot .; pybabel init -i messages.pot -d translations -l ko; pybabel init -i messages.pot -d translations -l en`, and after updating the `.po` files, `pybabel compile -d translations`
# when you add/remove any strings in the code, modify `messages.pot` as well, then run `pybabel update -i messages.pot -d translations`. modify each `.po` file, then run `pybabel compile -d translations` again
app.root_path = path.dirname(path.realpath(__file__))  # workaround for Flask-BabelEx issue where there's no way to configure the translations folder
babel = Babel(app, default_locale="en")


# use X-Forwarded-For and X-Forwarded-Host header values for request.remote_addr instead of the actual remote address
# NOTE: this should not be used in prod if not behind a load balancer/reverse proxy, since otherwise arbitrary users can manipulate the value of `request.remote_addr` (that said, we shouldn't rely on the value of `request.remote_addr` for anything important anyways)
app = ProxyFix(app, x_for=1, x_host=1)


if __name__ == "__main__":
    app.run()
