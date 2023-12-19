from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_required, current_user

from project.utils import file_signature_valid
from . import db, env
from .models import Image, User
from .config import ALLOWED_FILETYPES
from .utils import is_bot
from .crypto import cipher
import base64

main = Blueprint("main", __name__)


@main.route("/")
def index():
    return render_template("index.html")


@main.route("/profile")
@login_required
def profile():
    return render_template("profile.html", name=current_user.username)

@main.route("/password-policy")
def password_policy():
    return render_template("password_policy.html")



@main.route("/request-evaluation", methods=["GET"])
@login_required
def request_evaluation_get():
    return render_template("request_evaluation.html", captcha_sitekey=env['RECAPTCHA_PUBLIC_KEY'])


@main.route("/request-evaluation", methods=["POST"])
@login_required
def request_evaluation_post():
    image = request.files["image"]
    comments = request.form.get("comments")

    extension = image.filename.split(".")[-1]

    if extension not in ALLOWED_FILETYPES:
        flash(f"{extension} files are not allowed!")
        return redirect(url_for("main.request_evaluation_get"))


    image = image.read()

    # Check the magic bytes of a file to ensure the file is actually 
    # what we expect, as you can easily change the extension of a file 
    # allowing for the upload of executable files. 
    if not file_signature_valid(extension, image):
        flash("Sorry, that file is invalid")
        return redirect(url_for("main.request_evaluation_get"))

    if is_bot(request):
        flash("Invalid Captcha")
        return redirect(url_for('main.request_evaluation_get'))

    evaluation = Image(
        posted_by=current_user.id, comments=comments, image=cipher.encrypt(image), filetype=extension
    )
    db.session.add(evaluation)
    db.session.commit()
    return redirect(url_for("main.profile"))


@main.route("/evaluations")
@login_required
def evaluations():
    # Do not show the page if the user isn't an admin
    if not current_user.is_admin:
        return redirect(url_for("main.profile"))

    images = Image.query.all()
    evaluations = []
    for image in images:
        posted_by = User.query.filter_by(id=image.posted_by).first()
        image_plaintext = cipher.decrypt(image.image)

        evaluations.append((evaluations, posted_by, base64.b64encode(image_plaintext).decode()))

    return render_template("evaluations.html", evaluations=evaluations)
