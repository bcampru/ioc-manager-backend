from app import jwt
from app.auth import bp
from app.auth.helpers import *
from app.auth.models import InvalidToken
from flask import request, jsonify
from flask_jwt_extended import create_access_token, unset_jwt_cookies, get_jwt_identity, get_jwt, jwt_required, set_access_cookies
from datetime import datetime, timezone, timedelta


@jwt.token_in_blocklist_loader
def check_if_blacklisted_token(data, decrypted):
    """
    Decorator designed to check for blacklisted tokens
    """
    jti = decrypted['jti']
    return InvalidToken.is_invalid(jti)


@bp.after_request
def refresh_expiring_jwts(response):
    try:
        exp_timestamp = get_jwt()["exp"]
        now = datetime.now(timezone.utc)
        target_timestamp = datetime.timestamp(
            now + timedelta(minutes=30))
        if target_timestamp > exp_timestamp:
            access_token = create_access_token(identity=get_jwt_identity())
            set_access_cookies(response, access_token)
        return response
    except (RuntimeError, KeyError):
        # Case where there is not a valid JWT. Just return the original response
        return response


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
                response = jsonify({"msg": "login successful"})
                set_access_cookies(response, token)
                return response
            else:
                return jsonify({"error": "Invalid credentials"})
        else:
            return jsonify({"error": "Invalid Form"})
    except:
        return jsonify({"error": "Invalid Form"})


@bp.route("/register", methods=["POST"])
def register():
    try:
        username = request.json['username']
        pwd = encrypt_pwd(request.json['pwd'])
        name = request.json['name']
        surname = request.json['surname']
        users = get_users()
        if len(list(filter(lambda x: x["username"] == username, users))) == 1:
            return jsonify({"error": "Invalid Form"})
        add_user(username, pwd, name, surname)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)})


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
        response = jsonify({"msg": "logout successful"})
        unset_jwt_cookies(response)
        return response
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
