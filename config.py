import os
from datetime import timedelta
basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    SECRET_KEY = '08BAAmhcv6qeIfYzYJId'
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + \
        os.path.join(basedir, "app/data/app_database.sqlite")
    JWT_SECRET_KEY = "Jc8EJhLvfRmcy4onImat"
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ["access", "refresh"]
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
