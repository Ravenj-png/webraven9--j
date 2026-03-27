import os
import secrets
import json
import re
from flask_cors import CORS
from flask import render_template
from datetime import datetime
from flask import Flask, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
CORS(app)  # allow cross-origin for local testing
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///voting.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

@app.route('/')
def index():
    return render_template('f.html')  # your HTML file

# ------------------ MODELS ------------------
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

class AllowedReg(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reg_number = db.Column(db.String(20), unique=True, nullable=False)

# ------------------ HELPERS ------------------
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

# Always true for now, can implement real timing later
def voting_window_active():
    return True

import re

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    reg = data.get('reg_number')
    phone = data.get('phone')

    if not reg or not phone:
        return jsonify({'error': 'Missing fields'}), 400

    # Regex pattern for allowed format: e.g., BACS/25D/U/A0487
    pattern = r'^BACS/\d+[A-Z]?/[A-Z]/A\d+$'
    if not re.match(pattern, reg, re.IGNORECASE):
        return jsonify({'error': 'Registration number not recognized, please visit the office'}), 403

    # Check if already registered
    if Student.query.filter_by(reg_number=reg).first():
        return jsonify({'error': 'Already registered'}), 400

    # Generate password and create student
    password = secrets.token_urlsafe(6)[:8]
    student = Student(
        reg_number=reg.upper(),
        phone=phone,
        password_hash=generate_password_hash(password)
    )
    db.session.add(student)
    db.session.commit()

    return jsonify({'message': 'Registered successfully', 'password': password}), 200
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    reg = data.get('reg_number')
    password = data.get('password')
    if not reg or not password:
        return jsonify({'error': 'Missing credentials'}), 400

    student = Student.query.filter_by(reg_number=reg).first()
    if not student or not check_password_hash(student.password_hash, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    session['user_id'] = student.id
    return jsonify({'success': True}), 200

import secrets
from werkzeug.security import generate_password_hash

@app.route('/admin/reset_password', methods=['POST'])
@admin_required(role='ravenR')
def reset_student_password():
    data = request.get_json()
    reg = data.get('reg_number')

    student = Student.query.filter_by(reg_number=reg).first()
    if not student:
        return jsonify({'error': 'Student not found'}), 404

    # Generate new password
    new_password = secrets.token_urlsafe(6)[:8]
    student.password_hash = generate_password_hash(new_password)
    db.session.commit()

    # Return new password to admin
    return jsonify({'new_password': new_password, 'reg_number': student.reg_number, 'phone': student.phone}), 200

@app.route('/voting_data', methods=['GET'])
@login_required
def voting_data():
    student = Student.query.get(session['user_id'])
    posts = db.session.query(Candidate.post).distinct().order_by(Candidate.post).all()
    posts_order = [p[0] for p in posts]
    voted_posts = json.loads(student.voted_posts) if student.voted_posts else {}
    return jsonify({'posts_order': posts_order, 'voted_posts': voted_posts}), 200

@app.route('/candidates', methods=['GET'])
@login_required
def get_candidates():
    post = request.args.get('post')
    if not post:
        return jsonify({'error': 'Missing post'}), 400
    candidates = Candidate.query.filter_by(post=post).all()
    return jsonify({'candidates': [{'id': c.id, 'name': c.name, 'img': c.img, 'votes': c.votes} for c in candidates]}), 200

@app.route('/vote', methods=['POST'])
@login_required
def vote():
    if not voting_window_active():
        return jsonify({'error': 'Voting is not active'}), 403

    data = request.get_json()
    post = data.get('post')
    candidate_index = data.get('candidate_index')
    if post is None or candidate_index is None:
        return jsonify({'error': 'Missing data'}), 400

    student = Student.query.get(session['user_id'])
    voted_posts = json.loads(student.voted_posts) if student.voted_posts else {}
    if post in voted_posts:
        return jsonify({'error': 'Already voted for this post'}), 403

    candidates = Candidate.query.filter_by(post=post).order_by(Candidate.id).all()
    if candidate_index < 0 or candidate_index >= len(candidates):
        return jsonify({'error': 'Invalid candidate index'}), 400

    candidate = candidates[candidate_index]
    candidate.votes += 1
    voted_posts[post] = candidate.id
    student.voted_posts = json.dumps(voted_posts)

    total_posts = Candidate.query.with_entities(Candidate.post).distinct().count()
    if len(voted_posts) >= total_posts:
        student.has_voted = True

    db.session.commit()
    return jsonify({'success': True}), 200

@app.route('/results', methods=['GET'])
def results():
    posts = db.session.query(Candidate.post).distinct().all()
    result = {}
    for (post,) in posts:
        candidates = Candidate.query.filter_by(post=post).all()
        result[post] = [{'name': c.name, 'votes': c.votes} for c in candidates]
    return jsonify(result), 200

@app.route('/recover', methods=['POST'])
def recover():
    data = request.get_json()
    phone = data.get('phone')
    student = Student.query.filter_by(phone=phone).first()
    if not student:
        return jsonify({'error': 'Phone number not found'}), 404
    # In real life, send SMS; here, return password for simplicity
    return jsonify({'password': '***hidden***'}), 200

# ------------------ ADMIN ROUTES ------------------
ADMIN_CREDENTIALS = {'hunter': 'hunter', 'ravenR': 'ravenR'}

@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    password = data.get('password')
    if not password:
        return jsonify({'error': 'Missing password'}), 400

    if password in ADMIN_CREDENTIALS.values():
        session['admin_role'] = password
        return jsonify({'role': password}), 200
    return jsonify({'error': 'Invalid password'}), 401

@app.route('/admin/reset', methods=['POST'])
@admin_required(role='ravenR')
def reset_votes():
    Candidate.query.update({Candidate.votes: 0})
    Student.query.update({Student.has_voted: False, Student.voted_posts: '{}'})
    db.session.commit()
    return jsonify({'success': True}), 200

@app.route('/admin/students', methods=['GET'])
@admin_required(role='ravenR')
def admin_students():
    students = Student.query.all()
    return jsonify([{'reg_number': s.reg_number, 'has_voted': s.has_voted} for s in students]), 200

@app.route('/admin/votes', methods=['GET'])
@admin_required()
def admin_votes():
    posts = db.session.query(Candidate.post).distinct().all()
    result = {}
    for (post,) in posts:
        candidates = Candidate.query.filter_by(post=post).all()
        result[post] = [{'name': c.name, 'votes': c.votes} for c in candidates]
    return jsonify(result), 200

# ------------------ INIT ------------------
def init_db():
    with app.app_context():
        db.create_all()
        if Candidate.query.count() == 0:
            default_candidates = [
                {'name': 'Alice', 'post': 'Guild'},
                {'name': 'Bob', 'post': 'Guild'},
                {'name': 'Charlie', 'post': 'Guild'},
                {'name': 'Dave', 'post': 'Vice Guild'},
                {'name': 'Eve', 'post': 'Vice Guild'},
                {'name': 'Hank', 'post': 'Secretary'},
                {'name': 'Ivy', 'post': 'Secretary'},
            ]
            for c in default_candidates:
                db.session.add(Candidate(**c))
            db.session.commit()
        if AllowedReg.query.count() == 0:
            for reg in ['BAECS/25D/U/V9999', 'BAIT/26W/M/R2222', 'BAMA/24D/P/A1111', 'BACS/25D/U/A0001']:
                db.session.add(AllowedReg(reg_number=reg))
            db.session.commit()

if __name__ == '__main__':
    init_db()
    app.run(debug=True)