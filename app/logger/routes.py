from app.logger import bp
from app.logger.mispLogger import mispLogger
from flask import render_template, request, current_app, jsonify
import os


@bp.route("/iocLogger", methods=['POST'])
# @jwt_required()
def postLogger():
    if request.method == 'POST':
        os.chdir(current_app.root_path)
        logger = mispLogger()
        if(logger.insert(request.json)):
            return {}, 200
        else:
            return {}, 500


@bp.route("/iocLogger/<succeed>", methods=['GET'])
# @jwt_required()
def getLogger(succeed):
    if request.method == 'GET':
        os.chdir(current_app.root_path)
        logger = mispLogger()
        return jsonify(logger.getData(succeed))
