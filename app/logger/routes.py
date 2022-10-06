from app.logger import bp
from app.logger.mispLogger import mispLogger
from app.core.misp import misp_instance
from flask import request, current_app, jsonify
import os


@bp.route("/iocLogger/load", methods=['POST'])
def addMispLog():
    os.chdir(current_app.root_path)
    logger = mispLogger()
    if(logger.insert(request.json)):
        return {}, 200
    else:
        return {}, 500


@bp.route("/iocLogger/misp", methods=['GET'])
def getMispLog():
    os.chdir(current_app.root_path)
    logger = mispLogger()
    return jsonify(logger.getData())


@bp.route("/iocLogger/ioc", methods=['GET'])
def getIocLog():
    misp = misp_instance(
        os.getenv("misp_url"), os.getenv("misp_secret"))
    return jsonify(misp.getLogs())
