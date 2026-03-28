import os
import secrets
import json
from datetime import datetime   # <-- added
from flask import Flask, request, jsonify, session, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_session import Session

app = Flask(__name__)

# ---------- Configuration ----------
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secret123')
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_COOKIE_SAMESITE'] = "None"
app.config['SESSION_COOKIE_SECURE'] = True
Session(app)

# ---------- Database ----------
db_url = os.environ.get('DATABASE_URL', 'sqlite:///voting.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# ---------- CORS ----------
CORS(app,
     supports_credentials=True,
     origins=["https://webraven9-j.onrender.com"])

# ---------- Allowed Registration Numbers ----------
ALLOWED_REGS = {
    "BACS/25D/U/A0001",
    "BACS/25D/U/A0002",
    "BACS/25D/U/A0003",
    # Add more as needed
}

# ---------- Models ----------
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reg_number = db.Column(db.String(30), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    voted_posts = db.Column(db.Text, default='{}')  # stores {post: candidate_id}
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    post = db.Column(db.String(50), nullable=False)
    votes = db.Column(db.Integer, default=0)

# ---------- Helper Functions ----------
def get_request_data():
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

def admin_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrap(*args, **kwargs):
            if 'admin_role' not in session:
                return jsonify({'error': 'Admin login required'}), 401
            if role and session['admin_role'] != role:
                return jsonify({'error': 'Forbidden'}), 403
            return f(*args, **kwargs)
        return wrap
    return decorator

# ---------- Routes ----------
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    data = get_request_data()
    reg = data.get('reg_number', '').strip().upper()
    phone = data.get('phone', '').strip()
    if not reg or not phone:
        return jsonify({'error': 'Missing fields'}), 400
    if reg not in ALLOWED_REGS:
        return jsonify({'error': 'Invalid registration number'}), 400
    if Student.query.filter_by(reg_number=reg).first():
        return jsonify({'error': 'Already registered'}), 400
    password = secrets.token_urlsafe(6)[:8]
    student = Student(
        reg_number=reg,
        phone=phone,
        password_hash=generate_password_hash(password)
    )
    db.session.add(student)
    db.session.commit()
    return jsonify({'password': password})

@app.route('/login', methods=['POST'])
def login():
    data = get_request_data()
    reg = data.get('reg_number', '').strip().upper()
    password = data.get('password', '')
    student = Student.query.filter_by(reg_number=reg).first()
    if not student or not check_password_hash(student.password_hash, password):
        return jsonify({'error': 'Invalid credentials'}), 401
    session['user_id'] = student.id
    return jsonify({'success': True})

@app.route('/voting_data')
@login_required
def voting_data():
    posts = db.session.query(Candidate.post).distinct().all()
    return jsonify({'posts_order': [p[0] for p in posts]})

@app.route('/candidates')
@login_required
def candidates():
    post = request.args.get('post')
    data = Candidate.query.filter_by(post=post).all()
    return jsonify({'candidates': [{'id': c.id, 'name': c.name} for c in data]})

@app.route('/vote', methods=['POST'])
@login_required
def vote():
    data = get_request_data()
    post = data.get('post')
    candidate_id = data.get('candidate_id')
    student = Student.query.get(session['user_id'])
    voted_posts = json.loads(student.voted_posts) if student.voted_posts else {}
    if post in voted_posts:
        return jsonify({'error': 'You already voted for this post'}), 403
    candidate = Candidate.query.get(candidate_id)
    if not candidate or candidate.post != post:
        return jsonify({'error': 'Invalid candidate'}), 400
    candidate.votes += 1
    voted_posts[post] = candidate.id
    student.voted_posts = json.dumps(voted_posts)
    db.session.commit()
    return jsonify({'success': True})

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
ADMIN_PASSWORDS = {"hunter": "hunter", "ravenR": "ravenR"}

@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = get_request_data()
    pwd = data.get('password')
    if pwd in ADMIN_PASSWORDS.values():
        session['admin_role'] = pwd
        return jsonify({'role': pwd})
    return jsonify({'error': 'Wrong password'}), 401

@app.route('/admin/reset_votes', methods=['POST'])
@admin_required(role='ravenR')
def reset_votes():
    for c in Candidate.query.all():
        c.votes = 0
    for s in Student.query.all():
        s.voted_posts = '{}'
    db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/reset_password', methods=['POST'])
@admin_required(role='ravenR')
def reset_password():
    data = get_request_data()
    reg = data.get('reg_number', '').strip().upper()
    student = Student.query.filter_by(reg_number=reg).first()
    if not student:
        return jsonify({'error': 'Student not found'}), 404
    new_pass = secrets.token_urlsafe(6)[:8]
    student.password_hash = generate_password_hash(new_pass)
    db.session.commit()
    return jsonify({'new_password': new_pass})

@app.route('/admin/students')
@admin_required(role='ravenR')
def students():
    return jsonify([
        {'reg_number': s.reg_number, 'phone': s.phone, 'has_voted': bool(json.loads(s.voted_posts))}
        for s in Student.query.all()
    ])

@app.route('/admin/votes')
@admin_required(role='hunter')
def admin_votes():
    # Same as /results but for hunter
    posts = db.session.query(Candidate.post).distinct().all()
    result = {}
    for (post,) in posts:
        result[post] = [
            {'name': c.name, 'votes': c.votes}
            for c in Candidate.query.filter_by(post=post).all()
        ]
    return jsonify(result)

# ---------- Database Initialization ----------
with app.app_context():
    db.create_all()
    if Candidate.query.count() == 0:
        # Add default candidates (you can change these)
        default_candidates = [
            Candidate(name='Alice', post='President'),
            Candidate(name='Bob', post='President'),
            Candidate(name='Charlie', post='Secretary'),
            Candidate(name='David', post='Secretary'),
        ]
        db.session.add_all(default_candidates)
        db.session.commit()

# ---------- Run ----------
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 10000)))
