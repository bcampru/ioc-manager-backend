from app import jwt
from app.auth import bp
from app.auth.helpers import *
from app.auth.models import Users, InvalidToken
from flask import request, jsonify
from flask_jwt_extended import create_access_token, create_refresh_token, get_jwt_identity, get_jwt, jwt_required


@jwt.token_in_blocklist_loader
def check_if_blacklisted_token(data, decrypted):
    """
    Decorator designed to check for blacklisted tokens
    """
    jti = decrypted['jti']
    return InvalidToken.is_invalid(jti)


@bp.route("/login", methods=["POST"])
def login():
    try:
        username = request.json["username"]
        pwd = request.json["pwd"]
        if username and pwd:
            user = list(filter(lambda x: x["username"] == username and check_pwd(
                pwd, x["pwd"]), get_users()))
            if len(user) == 1:
                token = create_access_token(identity=user[0]["id"])
                refresh_token = create_refresh_token(identity=user[0]["id"])
                return jsonify({"token": token, "refreshToken": refresh_token})
            else:
                return jsonify({"error": "Invalid credentials"})
        else:
            return jsonify({"error": "Invalid Form"})
    except:
        return jsonify({"error": "Invalid Form"})


@bp.route("/register", methods=["POST"])
def register():
    try:
        pwd = encrypt_pwd(request.json['pwd'])
        username = request.json['username']
        users = get_users()
        if len(list(filter(lambda x: x["username"] == username, users))) == 1:
            return jsonify({"error": "Invalid Form"})
        add_user(username, pwd)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)})


@bp.route("/checkiftokenexpire", methods=["POST"])
@jwt_required()
def check_if_token_expire():
    return jsonify({"success": True})


@bp.route("/refreshtoken", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    token = create_access_token(identity=identity)
    return jsonify({"token": token})


@bp.route("/getcurrentuser")
@jwt_required()
def current_user():
    uid = get_jwt_identity()
    return jsonify(get_user(uid))


@bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    """
    End-point to invalidate the token.
    Can be used with both log the user out or for the frontend to call after refreshing the token.
    """
    jti = get_jwt()["jti"]
    try:
        invalid_token = InvalidToken(jti=jti)
        invalid_token.save()
        return jsonify({"success": True})
    except Exception as e:
        print(e)
        return jsonify({"error": str(e)})


@bp.route("/deleteaccount", methods=["DELETE"])
@jwt_required()
def delete_account():
    try:
        user = get_user(get_jwt_identity())
        remove_user(user.id)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)})
