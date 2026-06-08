"""
Web UI blueprint — serves HTML pages at /ui/*.
"""

from flask import Blueprint, render_template, redirect, url_for

web_bp = Blueprint(
    'web',
    __name__,
    url_prefix='/ui',
    template_folder='templates',
    static_folder='static',
    static_url_path='/static',   # served at /ui/static/ via the /ui prefix
)


@web_bp.route('/')
def dashboard():
    return render_template('dashboard.html')


@web_bp.route('/alerts')
def alerts():
    return render_template('alerts.html')


@web_bp.route('/playbooks')
def playbooks():
    return render_template('playbooks.html')


@web_bp.route('/verify')
def verify():
    return render_template('verify.html')


@web_bp.route('/orchestration')
def orchestration():
    return render_template('orchestration.html')


@web_bp.route('')
def ui_root():
    return redirect(url_for('web.dashboard'))
