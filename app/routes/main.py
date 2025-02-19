from flask import Blueprint, url_for, redirect

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return redirect(url_for("auth.login"))