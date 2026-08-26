# Libraries
import os
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template, request, redirect, url_for

# Logging Format
logging_format = logging.Formatter('%(message)s')

# HTTP Logger
funnel_logger = logging.getLogger('HTTP Logger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('http_audits.log', maxBytes=200000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)


# Baseline Honeypot
def web_honeypot(input_username="admin", input_password="password"):

    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    app = Flask(__name__, template_folder=template_dir)

    # ── LOGIN PAGE ────────────────────────────────────────────────────────────
    @app.route('/')
    def index():
        return render_template('wp-admin.html')

    @app.route('/wp-admin-login', methods=['POST'])
    def login():
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr

        funnel_logger.info(
            f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {ip_address} | {username} | {password}'
        )

        if username == input_username and password == input_password:
            funnel_logger.info(
                f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {ip_address} | LOGIN_SUCCESS | {username}'
            )
            return redirect(url_for('dashboard'))
        else:
            funnel_logger.info(
                f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {ip_address} | LOGIN_FAILED | {username}'
            )
            return render_template('wp-admin.html', error="Invalid credentials. Please try again.")

    # ── TRACKING ENDPOINT ─────────────────────────────────────────────────────
    @app.route('/track', methods=['GET', 'POST'])
    def track():
        action = request.args.get('action', 'unknown')
        time_spent = request.args.get('sec', '')
        ip_address = request.remote_addr
        if time_spent:
            funnel_logger.info(
                f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {ip_address} | SESSION_TIME | {time_spent}s'
            )
        else:
            funnel_logger.info(
                f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {ip_address} | POST-LOGIN | {action}'
            )
        return '', 204

    # ── FAKE WORDPRESS PAGES ──────────────────────────────────────────────────
    @app.route('/wp-dashboard')
    def dashboard():
        return render_template('wp-dashboard.html')

    @app.route('/wp-posts')
    def posts():
        return render_template('wp-posts.html')

    @app.route('/wp-users')
    def users():
        return render_template('wp-users.html')

    @app.route('/wp-plugins')
    def plugins():
        return render_template('wp-plugins.html')

    @app.route('/wp-settings')
    def settings():
        return render_template('wp-settings.html')

    @app.route('/wp-security')
    def security():
        return render_template('wp-security.html')

    @app.route('/wp-media')
    def media():
        return render_template('wp-media.html')

    @app.route('/wp-appearance')
    def appearance():
        return render_template('wp-appearance.html')

    # ── LOGOUT ────────────────────────────────────────────────────────────────
    @app.route('/logout')
    def logout():
        ip_address = request.remote_addr
        funnel_logger.info(
            f'{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | {ip_address} | LOGOUT | —'
        )
        return redirect(url_for('index'))

    return app


def run_web_honeypot(port=8000, input_username="admin", input_password="password"):
    run_web_honeypot_app = web_honeypot(input_username, input_password)
    import webbrowser, threading
    threading.Timer(1.5, lambda: webbrowser.open(f'http://127.0.0.1:{port}')).start()
    run_web_honeypot_app.run(debug=False, port=port, host="0.0.0.0")
    return run_web_honeypot_app


if __name__ == '__main__':
    run_web_honeypot(port=8000, input_username="admin", input_password="password")
