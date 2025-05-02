import os
import sys
# Ensure project root is on path so we can import modules in this directory
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from flask import Flask, request, render_template, redirect, url_for, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import joblib
import pandas as pd

# Instantiate SQLAlchemy
db = SQLAlchemy()

# --- Database model ---
class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip = db.Column(db.String(50))
    user_agent = db.Column(db.String(200))
    username = db.Column(db.String(100))
    password = db.Column(db.String(100))

# --- Feature extraction and model loading ---
# Import train module directly since we're in the same folder
def import_train_module():
    import train
    return train.extract_features

extract_features = import_train_module()

def load_classifier(model_path: str = os.path.join(os.path.dirname(__file__), 'model.joblib')):
    return joblib.load(model_path)

# --- Application factory ---
def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///honeypot_logs.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Initialize extensions
    db.init_app(app)
    with app.app_context():
        db.create_all()

    # Load model once
    app.classifier = load_classifier()

    @app.route('/')
    def home():
        return render_template('home.html')

    @app.route('/classify', methods=['GET', 'POST'])
    def classify():
        url = ''
        result = None
        label = None
        confidence = None
        if request.method == 'POST':
            url = request.form['url']
            feats = pd.DataFrame([extract_features(url)])
            label = int(app.classifier.predict(feats)[0])
            prob = app.classifier.predict_proba(feats)[0]
            confidence = round(prob[label], 4)
            print(f"[DEBUG] url={url} pred_label={label} confidence={confidence}")
            result = '🚩 MALICIOUS' if label == 1 else '✅ SAFE'
        return render_template('classify.html', url=url, result=result,
                               label=label, confidence=confidence)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            attempt = LoginAttempt(
                ip=request.remote_addr,
                user_agent=request.headers.get('User-Agent'),
                username=request.form['username'],
                password=request.form['password']
            )
            db.session.add(attempt)
            db.session.commit()
            return redirect(url_for('report'))
        return render_template('login.html')

    @app.route('/report')
    def report():
        attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).all()
        return render_template('report.html', attempts=attempts)

    @app.route('/api/classify', methods=['POST'])
    def api_classify():
        data = request.get_json() or {}
        url = data.get('url', '')
        feats = pd.DataFrame([extract_features(url)])
        pred = int(app.classifier.predict(feats)[0])
        prob = app.classifier.predict_proba(feats)[0]
        confidence = round(prob[pred], 4)
        return jsonify(url=url, label=pred,
                       prediction=('malicious' if pred == 1 else 'safe'),
                       confidence=confidence)

    return app

if __name__ == '__main__':
    application = create_app()
    application.run(debug=True)
