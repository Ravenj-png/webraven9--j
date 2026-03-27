import os
import secrets
import json
import re
from flask import Flask, request, jsonify, session, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_session import Session

app = Flask(__name__)

# ---------------- CONFIG ----------------
app.config['SECRET_KEY'] = 'secret123'

app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SAMESITE'] = "None"
app.config['SESSION_COOKIE_SECURE'] = True  # REQUIRED for Render

Session(app)

# ---------------- DATABASE ----------------
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voting.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ---------------- CORS ----------------
CORS(app,
     supports_credentials=True,
     origins=["https://webraven9-j.onrender.com"])

# ---------------- VALID REG NUMBERS ----------------
VALID_REG_NUMBERS = {
    "U/BSCS/001",
    "U/BSCS/002",
    "U/BSCS/003"
}

def valid_reg(reg):
    return re.match(r"^U\/[A-Z]{4}\/\d{3}$", reg)

# ---------------- MODELS ----------------
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reg_number = db.Column(db.String(20), unique=True)
    phone = db.Column(db.String(20))
    password_hash = db.Column(db.String(200))
    has_voted = db.Column(db.Boolean, default=False)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    post = db.Column(db.String(50))
    votes = db.Column(db.Integer, default=0)

# ---------------- HELPERS ----------------
def get_data():
    return request.get_json() if request.is_json else request.form.to_dict()

def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Login required'}), 401
        return f(*args, **kwargs)
    return wrap

def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin' not in session:
            return jsonify({'error': 'Admin only'}), 403
        return f(*args, **kwargs)
    return wrap

# ---------------- ROUTES ----------------

@app.route('/')
def home():
    return render_template("index.html")

# ---------- REGISTER ----------
@app.route('/register', methods=['POST'])
def register():
    try:
        data = get_data()
        reg = data.get("reg_number")
        phone = data.get("phone")

        if not reg or not phone:
            return jsonify({'error': 'Missing fields'}), 400

        reg = reg.upper()

        if not valid_reg(reg):
            return jsonify({'error': 'Format must be U/BSCS/001'}), 400

        if reg not in VALID_REG_NUMBERS:
            return jsonify({'error': 'Invalid reg number'}), 403

        if Student.query.filter_by(reg_number=reg).first():
            return jsonify({'error': 'Already registered'}), 400

        password = secrets.token_hex(4)

        student = Student(
            reg_number=reg,
            phone=phone,
            password_hash=generate_password_hash(password)
        )

        db.session.add(student)
        db.session.commit()

        return jsonify({'password': password})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ---------- LOGIN ----------
@app.route('/login', methods=['POST'])
def login():
    try:
        data = get_data()
        reg = data.get("reg_number")
        password = data.get("password")

        if not reg or not password:
            return jsonify({'error': 'Missing data'}), 400

        reg = reg.upper()

        user = Student.query.filter_by(reg_number=reg).first()

        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({'error': 'Invalid login'}), 401

        session['user_id'] = user.id
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ---------- VOTING ----------
@app.route('/voting_data')
@login_required
def voting_data():
    posts = db.session.query(Candidate.post).distinct().all()
    return jsonify({'posts_order': [p[0] for p in posts]})

@app.route('/candidates')
@login_required
def candidates():
    post = request.args.get("post")
    data = Candidate.query.filter_by(post=post).all()
    return jsonify({'candidates': [{'name': c.name} for c in data]})

@app.route('/vote', methods=['POST'])
@login_required
def vote():
    data = request.get_json()
    post = data.get("post")
    index = data.get("candidate_index")

    candidates = Candidate.query.filter_by(post=post).all()

    if index >= len(candidates):
        return jsonify({'error': 'Invalid'}), 400

    candidates[index].votes += 1
    db.session.commit()

    return jsonify({'success': True})

# ---------- RESULTS ----------
@app.route('/results')
def results():
    posts = db.session.query(Candidate.post).distinct().all()
    result = {}
    for (post,) in posts:
        result[post] = [
            {'name': c.name, 'votes': c.votes}
            for c in Candidate.query.filter_by(post=post).all()
        ]
    return jsonify(result)

# ---------- ADMIN ----------
ADMIN_PASSWORDS = ["hunter", "ravenR"]

@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = get_data()
    pwd = data.get("password")

    if pwd in ADMIN_PASSWORDS:
        session['admin'] = True
        return jsonify({'role': pwd})

    return jsonify({'error': 'Wrong password'}), 401

@app.route('/admin/students')
@admin_required
def students():
    return jsonify([
        {'reg_number': s.reg_number, 'has_voted': s.has_voted}
        for s in Student.query.all()
    ])

@app.route('/admin/votes')
@admin_required
def votes():
    posts = db.session.query(Candidate.post).distinct().all()
    result = {}
    for (post,) in posts:
        result[post] = [
            {'name': c.name, 'votes': c.votes}
            for c in Candidate.query.filter_by(post=post).all()
        ]
    return jsonify(result)

@app.route('/admin/reset', methods=['POST'])
@admin_required
def reset():
    for c in Candidate.query.all():
        c.votes = 0
    db.session.commit()
    return jsonify({'success': True})

# ---------- ERROR FIX ----------
@app.errorhandler(500)
def err(e):
    return jsonify({'error': 'Server error'}), 500

# ---------- INIT ----------
with app.app_context():
    db.create_all()
    if Candidate.query.count() == 0:
        db.session.add_all([
            Candidate(name="Alice", post="President"),
            Candidate(name="Bob", post="President"),
            Candidate(name="Eve", post="Secretary")
        ])
        db.session.commit()

# ---------- RUN ----------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
