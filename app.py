import os
import secrets
import json
from flask import Flask, request, jsonify, session, render_template
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime

app = Flask(__name__)
CORS(app)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key')

db_url = os.environ.get('DATABASE_URL')
if db_url:
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voting.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reg_number = db.Column(db.String(20), unique=True, nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    has_voted = db.Column(db.Boolean, default=False)
    voted_posts = db.Column(db.Text, default='{}')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    post = db.Column(db.String(50), nullable=False)
    img = db.Column(db.String(200), default='https://via.placeholder.com/60')
    votes = db.Column(db.Integer, default=0)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Not logged in'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'admin_role' not in session:
                return jsonify({'error': 'Unauthorized'}), 401
            if role and session['admin_role'] != role:
                return jsonify({'error': 'Forbidden'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    reg = data.get('reg_number')
    phone = data.get('phone')

    if not reg or not phone:
        return jsonify({'error': 'Missing fields'}), 400

    if Student.query.filter_by(reg_number=reg).first():
        return jsonify({'error': 'Already registered'}), 400

    password = secrets.token_urlsafe(6)[:8]

    student = Student(
        reg_number=reg.upper(),
        phone=phone,
        password_hash=generate_password_hash(password)
    )

    db.session.add(student)
    db.session.commit()

    return jsonify({'password': password}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    reg = data.get('reg_number')
    password = data.get('password')

    student = Student.query.filter_by(reg_number=reg).first()

    if not student or not check_password_hash(student.password_hash, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    session['user_id'] = student.id
    return jsonify({'success': True}), 200

@app.route('/voting_data', methods=['GET'])
@login_required
def voting_data():
    student = Student.query.get(session['user_id'])
    posts = db.session.query(Candidate.post).distinct().all()
    posts_order = [p[0] for p in posts]
    voted_posts = json.loads(student.voted_posts) if student.voted_posts else {}
    return jsonify({'posts_order': posts_order, 'voted_posts': voted_posts})

@app.route('/candidates')
@login_required
def candidates():
    post = request.args.get('post')
    data = Candidate.query.filter_by(post=post).all()
    return jsonify({'candidates': [
        {'name': c.name, 'img': c.img, 'votes': c.votes}
        for c in data
    ]})

@app.route('/vote', methods=['POST'])
@login_required
def vote():
    data = request.get_json()
    post = data.get('post')
    index = data.get('candidate_index')

    student = Student.query.get(session['user_id'])
    voted_posts = json.loads(student.voted_posts) if student.voted_posts else {}

    if post in voted_posts:
        return jsonify({'error': 'Already voted'}), 403

    candidates = Candidate.query.filter_by(post=post).all()
    candidate = candidates[index]

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

# ---------- ADMIN ----------
ADMIN_PASSWORDS = ["hunter", "ravenR"]

@app.route('/admin/login', methods=['POST'])
def admin_login():
    pwd = request.get_json().get('password')
    if pwd in ADMIN_PASSWORDS:
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
        s.has_voted = False
    db.session.commit()
    return jsonify({'success': True})

@app.route('/admin/students')
@admin_required(role='ravenR')
def students():
    return jsonify([
        {
            'reg': s.reg_number,
            'phone': s.phone
        } for s in Student.query.all()
    ])

@app.route('/admin/reset_password', methods=['POST'])
@admin_required(role='ravenR')
def reset_password():
    reg = request.get_json().get('reg_number')
    student = Student.query.filter_by(reg_number=reg).first()

    if not student:
        return jsonify({'error': 'Not found'}), 404

    new_pass = secrets.token_urlsafe(6)[:8]
    student.password_hash = generate_password_hash(new_pass)
    db.session.commit()

    return jsonify({'new_password': new_pass})

def init_db():
    with app.app_context():
        db.create_all()
        if Candidate.query.count() == 0:
            db.session.add_all([
                Candidate(name='Alice', post='Guild'),
                Candidate(name='Bob', post='Guild'),
                Candidate(name='Charlie', post='Guild'),
                Candidate(name='Dave', post='Vice Guild'),
                Candidate(name='Eve', post='Vice Guild'),
                Candidate(name='Hank', post='Secretary'),
                Candidate(name='Ivy', post='Secretary')
            ])
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
