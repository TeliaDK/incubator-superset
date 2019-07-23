from flask_babel import lazy_gettext
from wtforms import PasswordField, StringField
from wtforms.validators import DataRequired, Email, EqualTo

from flask_appbuilder.fieldwidgets import BS3PasswordFieldWidget, BS3TextFieldWidget
from flask_appbuilder.forms import DynamicForm
from flask_appbuilder.views import expose, PublicFormView
from flask_appbuilder._compat import as_unicode
from flask_appbuilder.security.sqla.models import User
from flask_login.utils import logout_user

from flask import redirect, flash, request, url_for, render_template, g
from superset import appbuilder, db, cache, app
from superset.utils.core import send_email_smtp
import random, string

from flask_appbuilder.security.views import AuthDBView
AuthDBView.login_template = "/superset/fab_overrides/general/security/login_db.html"

class ForgotPasswordForm(DynamicForm):
    username = StringField(
        lazy_gettext("Username"),
        validators=[DataRequired()],
        widget=BS3TextFieldWidget(),
        description=""
    )
    email = StringField(
        lazy_gettext("Email"),
        validators=[DataRequired(), Email()],
        widget=BS3TextFieldWidget(),
        description=lazy_gettext("We will send a reset password link to your email."
            " You need to click on the link in order to activate your new password."
            " Link will expire in 1 hour"
        )
    )
    password = PasswordField(
        lazy_gettext("Password"),
        description=lazy_gettext(
            "Please use a good password policy,"
            " this application does not check this for you"
        ),
        validators=[DataRequired()],
        widget=BS3PasswordFieldWidget(),
    )
    conf_password = PasswordField(
        lazy_gettext("Confirm Password"),
        description=lazy_gettext("Please rewrite the password to confirm"),
        validators=[DataRequired(), EqualTo("password", message=lazy_gettext("Passwords must match"))],
        widget=BS3PasswordFieldWidget(),
    )


class ResetLinkManager():
    def find_user(self, username, email):
        return db.session.query(User).filter_by(email=email, username=username).first()

    def send_link(self, form):
        print("Sendf link")
        if form.password.data != form.conf_password.data:
            raise "Password does not match"
        user = self.find_user(form.username.data, form.email.data)
        code = "".join(map(lambda x: random.choice(string.ascii_letters), range(0, 30)))
        data = {
            "email": form.email.data,
            "pwd": form.password.data,
            "username": form.username.data,
            "code": code,
            "url": "%s%s?code=%s" % (request.host_url[0:-1], url_for("ForgotPassword.activate"), code),
            "valid_user": user != None
        }
        print("Send link data: %s" % data)
        
        return data['valid_user'] and \
            self.store_link(data) and \
            self.send_link_by_email(data)
    
    def get_cache_key(self, code):
        return "reset_password_%s" % code

    def store_link(self, data):
        key = self.get_cache_key(data['code'])
        try:
            cache.set(key, data, timeout=60*60)
            print("Link key stored")
            return True
        except Exception as ex:
            print("Error storing link key")
            print(ex)
        return False

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
            print("Email send by smtp lib: %s" % res)
        except Exception as ex:
            print("Error sending email by smtp")
            print(ex)
            raise ex
        return True
        
    def get_code_info(self, code):
        key = self.get_cache_key(code)
        data = cache.get(key)
        if data:
            cache.delete(key)
        return data

    def activate(self):
        code = request.args.get('code')
        data = self.get_code_info(code)
        print("**** Data: %s" % data)
        return data and self.update_pwd(data)

    def update_pwd(self, data):
        user = self.find_user(data['username'], data['email'])
        print("Setting password for user: %s - %s", (user.id, data['pwd']))
        appbuilder.sm.reset_password(user.id, data['pwd'])
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
            return redirect("/login/")
        flash(as_unicode(self.message_not_valid), "danger")
        return redirect("%s/form" % self.route_base)

    @expose("/send_link", methods=["GET"])
    def send_link(self):
        form = ForgotPasswordForm(request.args, meta={'csrf': False})
        print("Form data: %s" % [form.username.data, form.email.data, form.password.data, form.conf_password.data])
        if form.validate():
            print("Form is valid")
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