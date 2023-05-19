from flask import Blueprint
bp = Blueprint('logger', __name__)
from app.logger import routes
