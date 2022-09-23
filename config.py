import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config(object):
    SECRET_KEY = '08BAAmhcv6qeIfYzYJId'
    SQLALCHEMY_DATABASE_URI = "sqlite:///" + \
        os.path.join(basedir, "data/app_database.db")
    JWT_SECRET_KEY = "Jc8EJhLvfRmcy4onImat"
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ["access", "refresh"]
