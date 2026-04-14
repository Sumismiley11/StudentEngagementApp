from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'student', 'teacher', 'admin'

    # Security Question for Forgot Password
    security_question = db.Column(db.String(200), nullable=True)
    security_answer = db.Column(db.String(200), nullable=True)

    # Profile Management Fields
    name = db.Column(db.String(100), nullable=True)
    address = db.Column(db.Text, nullable=True)
    dob = db.Column(db.String(20), nullable=True)
    preferences = db.Column(db.Text, nullable=True)
    wallet_balance = db.Column(db.Float, default=0.0)
    kyc_status = db.Column(db.String(20), default='Unverified')  # Unverified, In Process, Verified
    id_proof_path = db.Column(db.String(300), nullable=True)
    id_proof_filename = db.Column(db.String(300), nullable=True)

class Course(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    periods_per_week = db.Column(db.Integer, default=3)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    teacher = db.relationship('User', foreign_keys=[teacher_id], backref='taught_courses')

class Enrollment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=False)

    student = db.relationship('User', foreign_keys=[student_id], backref='enrollments')
    course = db.relationship('Course', foreign_keys=[course_id], backref='course_enrollments')

class Assignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    course_id = db.Column(db.Integer, db.ForeignKey('course.id'), nullable=True)
    teacher_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    attachment_path = db.Column(db.String(300), nullable=True)
    attachment_filename = db.Column(db.String(300), nullable=True)

    course = db.relationship('Course', foreign_keys=[course_id], backref='assignments')
    teacher = db.relationship('User', foreign_keys=[teacher_id], backref='created_assignments')

class Submission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    assignment_id = db.Column(db.Integer, db.ForeignKey('assignment.id'), nullable=False)
    file_path = db.Column(db.String(300), nullable=False)
    file_name = db.Column(db.String(300), nullable=True)
    marks = db.Column(db.Integer, nullable=True)
    feedback = db.Column(db.Text, nullable=True)

    student = db.relationship('User', foreign_keys=[student_id], backref='submissions')
    assignment = db.relationship('Assignment', backref='submissions')
