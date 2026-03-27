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

# ------------------ Configuration ------------------
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secret123')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SAMESITE'] = "None"
app.config['SESSION_COOKIE_SECURE'] = True  # Required for HTTPS (Render)
Session(app)

# ------------------ Database ------------------
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///voting.db')
if app.config['SQLALCHEMY_DATABASE_URI'].startswith("postgres://"):
    app.config['SQLALCHEMY_DATABASE_URI'] = app.config['SQLALCHEMY_DATABASE_URI'].replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ------------------ CORS ------------------
# Allow your Render domain (no trailing slash)
CORS(app,
     supports_credentials=True,
     origins=["https://webraven9-j.onrender.com"])

# ------------------ Validation ------------------
# Regex for registration number: BACS/25D/U/A0000 (uppercase, with slashes)
# Pattern: BACS/ followed by two digits, one letter, slash, one letter, slash, A, then four digits
REG_PATTERN = re.compile(r"^BACS/\d{2}[A-Z]/[A-Z]/A\d{4}$")

def valid_reg_number(reg):
    return bool(REG_PATTERN.match(reg))

# ------------------ Models ------------------
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reg_number = db.Column(db.String(30), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    has_voted = db.Column(db.Boolean, default=False)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    post = db.Column(db.String(50), nullable=False)
    votes = db.Column(db.Integer, default=0)

# ------------------ Helper Functions ------------------
def get_data():
    if request.is_json:
        return request.get_json()
    else:
        return request.form.to_dict()

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

# ------------------ Routes ------------------
@app.route('/')
def home():
    return render_template("index.html")

# ---------- Register ----------
@app.route('/register', methods=['POST'])
def register():
    try:
        data = get_data()
        reg = data.get("reg_number", "").strip().upper()
        phone = data.get("phone", "").strip()

        if not reg or not phone:
            return jsonify({'error': 'Missing fields'}), 400

        # Validate format
        if not valid_reg_number(reg):
            return jsonify({'error': 'Invalid registration number. Must be in format BACS/25D/U/A0000'}), 400

        # Check if already registered
        if Student.query.filter_by(reg_number=reg).first():
            return jsonify({'error': 'Already registered'}), 400

        # Generate a random password (8 chars)
        password = secrets.token_urlsafe(6)[:8]

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

# ---------- Login ----------
@app.route('/login', methods=['POST'])
def login():
    try:
        data = get_data()
        reg = data.get("reg_number", "").strip().upper()
        password = data.get("password", "")

        if not reg or not password:
            return jsonify({'error': 'Missing fields'}), 400

        student = Student.query.filter_by(reg_number=reg).first()
        if not student or not check_password_hash(student.password_hash, password):
            return jsonify({'error': 'Invalid credentials'}), 401

        session['user_id'] = student.id
        return jsonify({'success': True})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ---------- Voting ----------
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
        return jsonify({'error': 'Invalid candidate'}), 400

    candidate = candidates[index]
    candidate.votes += 1
    db.session.commit()
    return jsonify({'success': True})

# ---------- Results ----------
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

# ---------- Admin ----------
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

@app.route('/admin/reset', methods=['POST'])
@admin_required
def reset():
    for c in Candidate.query.all():
        c.votes = 0
    db.session.commit()
    return jsonify({'success': True})

# ------------------ Error Handler ------------------
@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Server error'}), 500

# ------------------ Database Initialization ------------------
with app.app_context():
    db.create_all()
    if Candidate.query.count() == 0:
        # Add default candidates (adjust as needed)
        db.session.add_all([
            Candidate(name="Alice", post="President"),
            Candidate(name="Bob", post="President"),
            Candidate(name="Eve", post="Secretary")
        ])
        db.session.commit()

# ------------------ Run ------------------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 10000)))
