from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from dotenv import dotenv_values
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

db = SQLAlchemy()
env = dotenv_values(".env")
secret_key = os.urandom(32)
limiter = Limiter(get_remote_address)


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = secret_key
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = "auth.login_get"
    login_manager.init_app(app)

    limiter.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(uid):
        return User.query.get(int(uid))

    from .auth import auth as auth_blueprint

    app.register_blueprint(auth_blueprint)
    from .main import main as main_blueprint

    app.register_blueprint(main_blueprint)

    with app.app_context():
        db.create_all()

    return app
