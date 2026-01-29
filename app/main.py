from flask import Blueprint, render_template

main = Blueprint('main', __name__)

@main.app_errorhandler(403)
def access_denied(e):
    return render_template('403.html'), 403

@main.route('/')
def home():
    return render_template('home.html')
