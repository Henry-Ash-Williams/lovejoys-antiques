from flask import Blueprint, render_template, request, redirect, url_for, flash, Markup
from flask_login import current_user, login_user, logout_user, login_required
from . import db, env, secret_key, limiter
from .models import User, PasswordReset
from werkzeug.security import generate_password_hash, check_password_hash
from .utils import is_bot, password_meets_security_requirements
from itsdangerous import URLSafeTimedSerializer
import resend
from datetime import datetime
from urllib import parse
from uuid import uuid4
from .config import PASSWORD_RESET_TIMEOUT
import requests


auth = Blueprint("auth", __name__)


@auth.route("/login", methods=["POST"])
@limiter.limit("5/minute")
def login_post():
    email = request.form.get("email")
    password = request.form.get("password")
    remember = True if request.form.get("remember") else False
    
    user = User.query.filter_by(email=email).first()

    if user is None:
        flash("User does not exist, sign up instead?")
        return redirect(url_for("auth.signup_get"))

    if not check_password_hash(user.password, password):
        flash("Incorrect login credentials")
        return redirect(url_for("auth.login_get"))

    if is_bot(request):
        flash("Captcha failed")
        return redirect(url_for("auth.login_get"))

    login_user(user, remember=remember)
    return redirect(url_for("main.profile"))


@auth.route("/login", methods=["GET"])
def login_get():
    return render_template("login.html", captcha_sitekey=env['RECAPTCHA_PUBLIC_KEY'])


@auth.route("/confirm/<token>")
@login_required
def confirm_email(token):
    if current_user.email_verified:
        flash("Account is already confirmed")
        return redirect(url_for("main.profile"))

    email = confirm_token(token)
    user = User.query.filter_by(email=current_user.email).first()

    if user.email == email:
        print("Verifying user")
        user.email_verified = True
        db.session.commit()
    else:
        print("User email mismatched with token")

    return redirect(url_for("main.profile"))


@auth.route("/signup", methods=["POST"])
@limiter.limit("5/minute")
def signup_post():
    email = request.form.get("email")
    username = request.form.get("username")
    password = request.form.get("password")
    phone_no = request.form.get("phone-no")

    user = User.query.filter_by(email=email).first()

    # Using `Markup` like this is only a security risk if unsantised user 
    # input gets in it so this is fine 
    if user:
        flash(
            Markup(
                'This email already has an account!  Go to <a href="/login">login page</a>.'
            )
        )
        return redirect(url_for("auth.signup_get"))

    if not password_meets_security_requirements(password):
        flash(Markup('Password is not strong enough!! See <a href="/password_policy">our password policy</a> for more info'))
        return redirect(url_for("auth.signup_get"))

    if is_bot(request):
        flash("Captcha failed")
        return redirect(url_for("auth.signup_get"))

    # `generate_password_hash` includes a salt in the resulting password hash, see
    # https://en.wikipedia.com/wiki/PBKDF2 for details
    new_usr = User(
        email=email, username=username, password=generate_password_hash(password), phone_number=phone_no
    )
    token = generate_token(email)
    token_urlsafe = parse.quote_plus(token)
    email = {
        "from": "noreply@lovejoysantiques.store",
        "to": email,
        "subject": "Lovejoys Antiques - Verify your email",
        "html": f"""Hello {username}!
Before you can access lovejoys antiques, we need you to verify your email. 


Simply click on <a href="http://127.0.0.1:5000{url_for('auth.confirm_email', token=token_urlsafe)}">this</a> link to verify!


Thank you for signing up for our service!!""",
    }

    resend.Emails.send(email)

    db.session.add(new_usr)
    db.session.commit()

    return redirect(url_for("auth.login_get"))


def generate_token(email):
    serializer = URLSafeTimedSerializer(secret_key)
    return serializer.dumps(email, salt=env["SECURITY_PASSWORD_SALT"])


def confirm_token(token, expiration=1800):
    serializer = URLSafeTimedSerializer(secret_key)
    try:
        email = serializer.loads(
            token, salt=env["SECURITY_PASSWORD_SALT"], max_age=expiration
        )
        return email
    except Exception:
        return False


@auth.route("/signup", methods=["GET"])
def signup_get():
    return render_template("signup.html", captcha_sitekey=env['RECAPTCHA_PUBLIC_KEY'])


@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("main.index"))


@auth.route("/reset-password", methods=["GET"])
def password_reset_get():
    return render_template("reset_password.html", captcha_sitekey=env['RECAPTCHA_PUBLIC_KEY'])


@auth.route("/reset-password", methods=["POST"])
@limiter.limit("5/minute")
def password_reset_post():
    email = request.form.get("email")

    recaptcha_response = request.form.get('g-recaptcha-response')

    data = {
        'secret': env['RECAPTCHA_PRIVATE_KEY'],
        'response': recaptcha_response
    }
    response = requests.post('https://www.google.com/recaptcha/api/siteverify', data=data)
    result = response.json()
    user = User.query.filter_by(email=email).first()

    if not user:
        flash("Could not find that user in the database")
        return redirect(url_for("auth.password_reset_get"))

    if not result['success']:
        flash("Captcha failed")
        return redirect(url_for("auth.signup_get"))

    token = str(uuid4())
    token_urlsafe = parse.quote_plus(token)

    reset = PasswordReset(for_user=user.id, token=token)
    db.session.add(reset)
    db.session.commit()

    email = {
        "from": "noreply@lovejoysantiques.store",
        "to": email,
        "subject": "Lovejoys Antiques - Reset your password",
        "html": f"""Hello {user.username}!
You've requested a password reset, if this wasn't you, please ignore this email. 

Click on the following <a href="http://127.0.0.1:5000/reset-password/{token_urlsafe}">link</a> to reset your password""",
    }
    resend.Emails.send(email)
    
    flash(f"We've sent you an email at {user.username}")
    return redirect(url_for("auth.login_get"))


@auth.route('/reset-password/<token>', methods=["GET"])
@limiter.limit("5/minute")
def handle_password_reset(token):
    reset = PasswordReset.query.filter_by(token=token).first()

    if reset is None: 
        flash("Invalid Token")
        return redirect(url_for("auth.password_reset_get"))
            
    time_elapsed_since_request = datetime.utcnow() - reset.requested

    if time_elapsed_since_request > PASSWORD_RESET_TIMEOUT:
        flash("That token has expired")
        return redirect(url_for("auth.password_reset_get"))

    return render_template('change_password.html', token=token)


@auth.route('/reset-password/<token>', methods=["POST"])
@limiter.limit("5/minute")
def handle_password_reset_post(token):
    reset = PasswordReset.query.filter_by(token=token).first()
    new_password = request.form.get('password')         
    requested_by = User.query.filter_by(id=reset.for_user).first()

    if not password_meets_security_requirements(new_password):
        flash("Password does not meet our security requirements")
        return redirect(url_for('auth.handle_password_reset', token=token))         

    requested_by.password = generate_password_hash(new_password)
    reset.has_reset = True 
    db.session.commit()

    flash("Your password has been reset!")
    return redirect(url_for('auth.login_get'))