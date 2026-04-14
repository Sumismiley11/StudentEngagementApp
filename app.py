from flask import Flask, render_template, request, redirect, session, flash, send_from_directory
from models.db_setup import db, User, Assignment, Submission, Course, Enrollment
import os
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", "sqlite:///database.db")
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "fallback-secret")

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
ALLOWED_EXTENSIONS = {'pdf', 'py', 'txt', 'zip', 'docx', 'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

db.init_app(app)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

if __name__ != "__main__":
    with app.app_context():
        db.create_all()

        # Pre-defined Admin — cannot be registered
        if not User.query.filter_by(role='admin').first():
            default_admin = User(
                username='admin',
                password='admin123',
                role='admin',
                kyc_status='Verified'
            )
            db.session.add(default_admin)
            db.session.commit()

        # Default Courses
        if not Course.query.first():
            db.session.add_all([
                Course(name='Mathematics 101', periods_per_week=5),
                Course(name='Physics Fundamentals', periods_per_week=4),
                Course(name='Computer Science Basics', periods_per_week=3),
            ])
            db.session.commit()


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def is_locked_out():
    attempts = session.get('login_attempts', 0)
    lockout_until = session.get('lockout_until')
    if lockout_until:
        lockout_until_dt = datetime.fromisoformat(lockout_until)
        if datetime.utcnow() < lockout_until_dt:
            remaining = int((lockout_until_dt - datetime.utcnow()).total_seconds())
            return True, remaining
        else:
            session.pop('lockout_until', None)
            session['login_attempts'] = 0
    return False, 0


@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response


# ──────────────────── AUTH ──────────────────── #

@app.route('/')
def home():
    return redirect('/login')


@app.route('/login', methods=['GET', 'POST'])
def login():
    role_hint = request.args.get('role', '')

    if 'user_id' in session:
        r = session.get('role')
        if r == 'admin': return redirect('/admin')
        return redirect('/student' if r == 'student' else '/teacher')

    locked, remaining = is_locked_out()
    if locked:
        mins = remaining // 60
        secs = remaining % 60
        flash(f'Too many failed attempts. Try again in {mins}m {secs}s.', 'error')
        return render_template('login.html', locked=True, role_hint=role_hint)

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role_hint = request.form.get('role_hint', '')

        if not username or not password:
            flash('Both username and password are required.', 'error')
            return render_template('login.html', locked=False, role_hint=role_hint)

        user = User.query.filter_by(username=username, password=password).first()

        if user:
            # Enforce role match when hint given
            if role_hint and user.role != role_hint:
                flash(f'This account is not a {role_hint} account.', 'error')
                return render_template('login.html', locked=False, role_hint=role_hint)

            session.clear()
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            if user.role == 'admin': return redirect('/admin')
            return redirect('/teacher' if user.role == 'teacher' else '/student')

        session['login_attempts'] = session.get('login_attempts', 0) + 1
        attempts_left = MAX_LOGIN_ATTEMPTS - session['login_attempts']

        if session['login_attempts'] >= MAX_LOGIN_ATTEMPTS:
            session['lockout_until'] = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
            session.clear()
            session['lockout_until'] = (datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
            session['login_attempts'] = MAX_LOGIN_ATTEMPTS
            flash(f'Account locked for {LOCKOUT_MINUTES} minutes.', 'error')
            return render_template('login.html', locked=True, role_hint=role_hint)

        flash(f'Invalid credentials. {attempts_left} attempt(s) remaining.', 'error')

    return render_template('login.html', locked=False, role_hint=role_hint)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        role = request.form.get('role', 'student')
        sec_question = request.form.get('security_question', '').strip()
        sec_answer = request.form.get('security_answer', '').strip().lower()

        # Block admin registration
        if role == 'admin':
            flash('Admin accounts cannot be registered.', 'error')
            return render_template('register.html')

        if not username or not password or not sec_question or not sec_answer:
            flash('All fields are required.', 'error')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already taken. Please choose another.', 'error')
            return render_template('register.html')

        user = User(username=username, password=password, role=role,
                    security_question=sec_question, security_answer=sec_answer)
        db.session.add(user)
        db.session.commit()
        flash('Account created! Please log in.', 'success')
        return redirect('/login')

    return render_template('register.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        step = request.form.get('step')
        if step == '1':
            username = request.form.get('username').strip()
            user = User.query.filter_by(username=username).first()
            if user:
                return render_template('forgot_password.html', step=2, username=username, question=user.security_question)
            flash('Username not found.', 'error')
            return render_template('forgot_password.html', step=1)
        elif step == '2':
            username = request.form.get('username')
            answer = request.form.get('answer').strip().lower()
            new_password = request.form.get('new_password')
            user = User.query.filter_by(username=username).first()
            if user and user.security_answer == answer:
                user.password = new_password
                db.session.commit()
                flash('Password reset successfully.', 'success')
                return redirect('/login')
            else:
                flash('Incorrect security answer.', 'error')
                return render_template('forgot_password.html', step=2, username=username, question=user.security_question if user else '')
    return render_template('forgot_password.html', step=1)


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect('/login')


# ──────────────────── PROFILE ──────────────────── #

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect('/login')
    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        address = request.form.get('address', '').strip()
        dob = request.form.get('dob', '').strip()
        preferences = request.form.get('preferences', '').strip()
        current_password = request.form.get('current_password', '')

        if current_password and current_password != user.password:
            flash('Incorrect current password.', 'error')
            return redirect('/profile')

        requires_kyc = (name != (user.name or '')) or (address != (user.address or '')) or (dob != (user.dob or ''))

        file = request.files.get('id_proof')
        if requires_kyc:
            if not file or file.filename == '':
                flash('ID/Address proof is mandatory for Name, Address, or DoB changes.', 'error')
                return redirect('/profile')
            if file and allowed_file(file.filename):
                filename = secure_filename(f"kyc_{user.id}_{file.filename}")
                path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(path)
                user.id_proof_path = path
                user.id_proof_filename = file.filename
                user.kyc_status = 'In Process'

        user.name = name
        user.address = address
        user.dob = dob
        user.preferences = preferences
        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect('/profile')

    return render_template('profile.html', user=user)


# ──────────────────── SETUP (Course List) ──────────────────── #

@app.route('/setup')
def setup():
    if 'user_id' not in session:
        return redirect('/login')
    courses = Course.query.all()
    return render_template('setup.html', courses=courses)


# ──────────────────── ADMIN ──────────────────── #

@app.route('/admin')
def admin_dashboard():
    if 'user_id' not in session or session.get('role') != 'admin':
        flash('Admin access required.', 'error')
        return redirect('/login')

    pending_kyc = User.query.filter(User.kyc_status == 'In Process').all()
    courses = Course.query.all()
    teachers = User.query.filter_by(role='teacher').all()
    students = User.query.filter_by(role='student').all()
    all_users = User.query.filter(User.role != 'admin').all()

    return render_template('admin.html',
                           pending_kyc=pending_kyc,
                           courses=courses,
                           teachers=teachers,
                           students=students,
                           all_users=all_users)


@app.route('/admin/kyc_view/<int:user_id>')
def admin_kyc_view(user_id):
    if session.get('role') != 'admin':
        return redirect('/login')
    user = User.query.get_or_404(user_id)
    return render_template('admin_kyc_view.html', user=user)


@app.route('/approve_kyc/<int:user_id>', methods=['POST'])
def approve_kyc(user_id):
    if session.get('role') != 'admin':
        return redirect('/login')
    user = User.query.get_or_404(user_id)
    user.kyc_status = 'Verified'
    db.session.commit()
    flash(f'KYC verified for {user.username}.', 'success')
    return redirect('/admin')


@app.route('/reject_kyc/<int:user_id>', methods=['POST'])
def reject_kyc(user_id):
    if session.get('role') != 'admin':
        return redirect('/login')
    user = User.query.get_or_404(user_id)
    user.kyc_status = 'Unverified'
    user.id_proof_path = None
    user.id_proof_filename = None
    db.session.commit()
    flash(f'KYC rejected for {user.username}.', 'error')
    return redirect('/admin')


@app.route('/assign_course', methods=['POST'])
def assign_course():
    if session.get('role') != 'admin':
        return redirect('/login')

    course_id = request.form.get('course_id')
    user_id = request.form.get('user_id')
    action_type = request.form.get('action_type')

    course = Course.query.get_or_404(course_id)
    user = User.query.get_or_404(user_id)

    if action_type == 'teacher':
        course.teacher_id = user.id
        flash(f'Assigned {user.username} as teacher for {course.name}.', 'success')
    elif action_type == 'student':
        existing = Enrollment.query.filter_by(student_id=user.id, course_id=course.id).first()
        if not existing:
            enrollment = Enrollment(student_id=user.id, course_id=course.id)
            db.session.add(enrollment)
            flash(f'Enrolled {user.username} in {course.name}.', 'success')
        else:
            flash('Student is already enrolled in this course.', 'error')

    db.session.commit()
    return redirect('/admin')


@app.route('/remove_enrollment/<int:enrollment_id>', methods=['POST'])
def remove_enrollment(enrollment_id):
    if session.get('role') != 'admin':
        return redirect('/login')
    e = Enrollment.query.get_or_404(enrollment_id)
    db.session.delete(e)
    db.session.commit()
    flash('Enrollment removed.', 'success')
    return redirect('/admin')


@app.route('/admin/add_course', methods=['POST'])
def admin_add_course():
    if session.get('role') != 'admin':
        return redirect('/login')
    name = request.form.get('course_name', '').strip()
    periods = request.form.get('periods_per_week', 3)
    if not name:
        flash('Course name is required.', 'error')
        return redirect('/admin')
    db.session.add(Course(name=name, periods_per_week=int(periods)))
    db.session.commit()
    flash(f'Course "{name}" added.', 'success')
    return redirect('/admin')


# ──────────────────── STUDENT ──────────────────── #

@app.route('/student')
def student():
    if 'user_id' not in session or session.get('role') != 'student':
        return redirect('/login')

    enrollments = Enrollment.query.filter_by(student_id=session['user_id']).all()
    my_courses = [e.course for e in enrollments]
    my_course_ids = [c.id for c in my_courses]

    # Only show assignments for enrolled courses
    assignments = Assignment.query.filter(Assignment.course_id.in_(my_course_ids)).all() if my_course_ids else []
    submissions = Submission.query.filter_by(student_id=session['user_id']).all()
    submitted_ids = {s.assignment_id for s in submissions}
    submission_map = {s.assignment_id: s for s in submissions}

    user = User.query.get(session['user_id'])

    return render_template('student.html',
                           assignments=assignments,
                           submissions=submissions,
                           submitted_ids=submitted_ids,
                           submission_map=submission_map,
                           my_courses=my_courses,
                           user=user)


@app.route('/submit/<int:assignment_id>', methods=['POST'])
def submit(assignment_id):
    if 'user_id' not in session or session.get('role') != 'student':
        return redirect('/login')
    file = request.files.get('file')
    if not file or file.filename == '':
        flash('Please select a file to upload.', 'error')
        return redirect('/student')
    if not allowed_file(file.filename):
        flash(f'File type not allowed. Allowed: {", ".join(ALLOWED_EXTENSIONS)}', 'error')
        return redirect('/student')

    # Check already submitted
    existing = Submission.query.filter_by(student_id=session['user_id'], assignment_id=assignment_id).first()
    if existing:
        flash('You have already submitted this assignment.', 'error')
        return redirect('/student')

    filename = secure_filename(f"sub_{session['user_id']}_{assignment_id}_{file.filename}")
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(path)
    submission = Submission(student_id=session['user_id'], assignment_id=assignment_id,
                            file_path=path, file_name=file.filename, marks=None)
    db.session.add(submission)
    db.session.commit()
    flash('Assignment submitted successfully!', 'success')
    return redirect('/student')


# ──────────────────── TEACHER ──────────────────── #

@app.route('/teacher')
def teacher():
    if 'user_id' not in session or session.get('role') != 'teacher':
        return redirect('/login')

    my_courses = Course.query.filter_by(teacher_id=session['user_id']).all()
    my_course_ids = [c.id for c in my_courses]

    assignments = Assignment.query.filter(Assignment.course_id.in_(my_course_ids)).all() if my_course_ids else []
    total_subs = Submission.query.join(Assignment).filter(Assignment.course_id.in_(my_course_ids)).count() if my_course_ids else 0

    # All students enrolled in my courses
    enrolled_students = []
    seen_ids = set()
    for course in my_courses:
        for e in course.course_enrollments:
            if e.student_id not in seen_ids:
                seen_ids.add(e.student_id)
                enrolled_students.append(e.student)

    return render_template('teacher.html',
                           assignments=assignments,
                           total_subs=total_subs,
                           my_courses=my_courses,
                           enrolled_students=enrolled_students)


@app.route('/teacher/student/<int:student_id>')
def teacher_student_detail(student_id):
    if 'user_id' not in session or session.get('role') != 'teacher':
        return redirect('/login')

    student_user = User.query.get_or_404(student_id)
    my_courses = Course.query.filter_by(teacher_id=session['user_id']).all()
    my_course_ids = [c.id for c in my_courses]

    # Assignments for this student in teacher's courses
    assignments = Assignment.query.filter(Assignment.course_id.in_(my_course_ids)).all() if my_course_ids else []
    submissions = Submission.query.filter_by(student_id=student_id).all()
    submission_map = {s.assignment_id: s for s in submissions}

    return render_template('teacher_student.html',
                           student_user=student_user,
                           assignments=assignments,
                           submission_map=submission_map,
                           my_courses=my_courses)


@app.route('/create_assignment', methods=['POST'])
def create_assignment():
    if 'user_id' not in session or session.get('role') != 'teacher':
        return redirect('/login')
    title = request.form.get('title', '').strip()
    desc = request.form.get('description', '').strip()
    course_id = request.form.get('course_id', '')

    if not title:
        flash('Assignment title is required.', 'error')
        return redirect('/teacher')
    if not course_id:
        flash('Please select a course for this assignment.', 'error')
        return redirect('/teacher')

    # Verify teacher owns this course
    course = Course.query.filter_by(id=course_id, teacher_id=session['user_id']).first()
    if not course:
        flash('You are not authorized to create assignments for that course.', 'error')
        return redirect('/teacher')

    assignment = Assignment(title=title, description=desc, course_id=course_id, teacher_id=session['user_id'])

    # Optional file attachment
    file = request.files.get('attachment')
    if file and file.filename != '' and allowed_file(file.filename):
        filename = secure_filename(f"assign_{session['user_id']}_{file.filename}")
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(path)
        assignment.attachment_path = path
        assignment.attachment_filename = file.filename

    db.session.add(assignment)
    db.session.commit()
    flash('Assignment created successfully!', 'success')
    return redirect('/teacher')


@app.route('/submissions/<int:assignment_id>')
def submissions(assignment_id):
    if 'user_id' not in session or session.get('role') != 'teacher':
        return redirect('/login')
    assignment = Assignment.query.get_or_404(assignment_id)
    subs = Submission.query.filter_by(assignment_id=assignment_id).all()
    return render_template('submissions.html', submissions=subs, assignment=assignment)


@app.route('/grade/<int:sub_id>', methods=['POST'])
def grade(sub_id):
    if 'user_id' not in session or session.get('role') != 'teacher':
        return redirect('/login')
    sub = Submission.query.get_or_404(sub_id)
    feedback = request.form.get('feedback', '').strip()
    try:
        marks_input = request.form.get('marks', '')
        if marks_input == '':
            raise ValueError
        marks = int(marks_input)
        if marks < 0 or marks > 100:
            raise ValueError
        sub.marks = marks
        sub.feedback = feedback
        db.session.commit()
        flash('Marks and feedback saved.', 'success')
    except ValueError:
        flash('Marks must be a valid number between 0 and 100.', 'error')
    return redirect(f'/submissions/{sub.assignment_id}')


@app.route('/delete_assignment/<int:id>', methods=['POST'])
def delete_assignment(id):
    if 'user_id' not in session or session.get('role') != 'teacher':
        return redirect('/login')
    assignment = Assignment.query.get_or_404(id)
    Submission.query.filter_by(assignment_id=id).delete()
    db.session.delete(assignment)
    db.session.commit()
    flash('Assignment deleted.', 'success')
    return redirect('/teacher')


# ──────────────────── FILE DOWNLOAD ──────────────────── #

@app.route('/download/<path:filename>')
def download_file(filename):
    if 'user_id' not in session:
        return redirect('/login')
    return send_from_directory(app.config['UPLOAD_FOLDER'], os.path.basename(filename), as_attachment=True)


if __name__ == "__main__":
    import os
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
