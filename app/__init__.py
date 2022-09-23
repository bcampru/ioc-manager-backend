from flask import Flask, render_template
from flask_jwt_extended import JWTManager
from flask_sqlalchemy import SQLAlchemy
from config import Config
import os
db = SQLAlchemy()
jwt = JWTManager()


def initTemplates(app):
    @app.route("/iocLogger", methods=['GET'])
    def logger():
        return render_template('iocLogger.html')

    @app.route("/tableVisualizer", methods=['GET'])
    def tableVisualizer():
        return render_template('tableVisualizer.html')

    @app.route("/addIocTemplate")
    def create():
        return render_template('createIoc.html')

    @app.route("/deleteIocTemplate")
    def delete():
        return render_template('deleteIoc.html')

    @app.route("/updateIocTemplate")
    def update():
        return render_template('updateIoc.html')

    @app.route("/")
    def main():
        os.chdir(app.root_path)
        return render_template('index.html', var=os.getenv("logo"))


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # TODO remove templates when frontend is in prod
    initTemplates(app)
    db.init_app(app)
    jwt.init_app(app)

    @app.before_first_request
    def create_tables():
        db.create_all()
    from app.auth import bp as auth_bp
    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    from app.core import bp as core_bp
    app.register_blueprint(core_bp, url_prefix="/api")
    from app.logger import bp as logger_bp
    app.register_blueprint(logger_bp, url_prefix="/api")
    return app


from app.auth import models
