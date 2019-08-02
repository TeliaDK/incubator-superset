from flask_babel import lazy_gettext
from wtforms import PasswordField, StringField
from wtforms.validators import DataRequired, Email, EqualTo

from flask_appbuilder.fieldwidgets import BS3PasswordFieldWidget, BS3TextFieldWidget
from flask_appbuilder.forms import DynamicForm
from flask_appbuilder.views import expose, PublicFormView
from flask_appbuilder._compat import as_unicode
from flask_appbuilder.security.sqla.models import User
from flask_appbuilder.urltools import Stack

from flask_login.utils import logout_user, login_user

from flask import redirect, flash, request, url_for, render_template, g, session
from superset import appbuilder, db, cache, app
from superset.utils.core import send_email_smtp
import random, string, logging, time

from cryptography.fernet import Fernet

from flask_appbuilder.security.views import AuthDBView
AuthDBView.login_template = "/superset/fab_overrides/general/security/login_db.html"

class ForgotPasswordForm(DynamicForm):
    email = StringField(
        lazy_gettext("Email"),
        validators=[DataRequired(), Email()],
        widget=BS3TextFieldWidget(),
        description=lazy_gettext("We will send a reset password link to your email."
            " You need to click on the link in order to activate your new password."
            " Link will expire in 1 hour"
        )
    )


class ResetLinkManager():
    SEPARATOR = "@@@@"
    LINK_TIME_TO_LIVE = (60 * 60)

    def find_user(self, email):
        return db.session.query(User).filter_by(email=email).first()

    def send_link(self, form):
        logging.info("Send link")
        user = self.find_user(form.email.data)
        if user is None:
            return False

        code = self.generateCode(user)
        data = {
            "username": user.username,
            "email": form.email.data,
            "code": code,
            "url": "%s%s?code=%s" % (request.host_url[0:-1], url_for("ForgotPassword.activate"), code)
        }
        logging.info("Send link data: %s" % data)

        return self.send_link_by_email(data)

    def getEncryptKey(self):
        key = app.config.get("SECURITY_FERNET_KEY")
        logging.info("SECURITY_FERNET_KEY: %s" % key)
        return key.encode()

    def encrypt(self, message: string) -> string:
        key = self.getEncryptKey()
        return Fernet(key).encrypt(message.encode()).decode()

    def decrypt(self, token: string) -> string:
        key = self.getEncryptKey()
        return Fernet(key).decrypt(token.encode(), ttl=self.LINK_TIME_TO_LIVE).decode()

    def generateCode(self, user):
        return self.encrypt(user.email)

    def build_email_body(self, data):
        body = render_template(
                "appbuilder/general/security/reset_my_password_email.html",
                data=data
            )
        return body 

    def send_link_by_email(self, data):
        try:
            res = send_email_smtp(
                data['email'],
                str(lazy_gettext("Reset password")),
                self.build_email_body(data),
                app.config
            )
            logging.info("Email send by smtp lib: %s" % res)
        except Exception as ex:
            logging.info("Error sending email by smtp")
            logging.info(ex)
            raise ex
        return True

    def getUserFromCode(self, linkCode):
        email = self.decrypt(linkCode)
        user = self.find_user(email)
        return user

    def activate(self):
        linkCode = request.args.get('code')
        user = self.getUserFromCode(linkCode)
        logging.info("**** Data: %s" % user)
        return user and self.update_pwd(user)

    def update_pwd(self, user):
        logging.info("Setting dummy password for user: %s", user.id)
        appbuilder.sm.reset_password(user.id, "JustADummyPassword!")
        login_user(user)
        return True


class ForgotPassword(PublicFormView):
    """
        View for resetting own user password
    """

    route_base = "/forgotpassword"
    form = ForgotPasswordForm
    form_title = lazy_gettext("Reset passsword")
    redirect_url = "/"
    message = lazy_gettext("Link sent. Remember to check your email and follow it to activate!")
    message_error = lazy_gettext("Ops! We could not send the link. Please contact with the administrator")
    message_activated = lazy_gettext("Your new password has been activated.")
    message_not_valid = lazy_gettext("Invalid link. Please try to reset password again.")
    link_man = ResetLinkManager()
    
    @expose("/activate", methods=["GET"])
    def activate(self):
        if self.link_man.activate():
            flash(as_unicode(self.message_activated), "info")
            # next= parameter is ignored
            page_history = Stack(session.get("page_history", []))
            page_history.push("/") # Will force a redirect to home page
            return redirect("/resetmypassword/form")
        flash(as_unicode(self.message_not_valid), "danger")
        return redirect("/")

    @expose("/send_link", methods=["GET"])
    def send_link(self):
        form = ForgotPasswordForm(request.args, meta={'csrf': False})
        logging.info("Form data: %s" % [form.username.data, form.email.data, form.password.data, form.conf_password.data])
        if form.validate():
            logging.info("Form is valid")
            self.form_post(form)
        return redirect("/")


    def form_post(self, form):
        if self.link_man.send_link(form):
            flash(as_unicode(self.message), "info")
            if g.user:
                logout_user()
            return redirect("/")
        else:
            flash(as_unicode(self.message_error), "danger")


appbuilder.add_view_no_menu(ForgotPassword)