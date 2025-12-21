import traceback
from flask import request, render_template, redirect, url_for, session, Blueprint, flash, abort, current_app
from app import db, bcrypt
from app.models import User
from app.forms import LoginForm, RegisterForm, ChangePasswordForm
import bleach
from flask_login import login_user, logout_user, login_required, current_user
from functools import wraps
from datetime import datetime, timedelta
from sqlalchemy import text

main = Blueprint('main', __name__)

@main.route('/')
def home():
    return render_template('home.html')

@main.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
#----------------------- bcrypt hash and login check --------------------------------------------------------------
        row = db.session.execute(text("SELECT * FROM user WHERE username=:user"), {"user": username}).mappings().first()
        user = User.query.get(row["id"]) if row else None
        if user:
            pw_pepper = password + current_app.PEPPER
            if bcrypt.check_password_hash(user.password, pw_pepper):
                session.clear()
                login_user(user)
                session['user'] = user.username
                session['role'] = user.role
                session['bio'] = user.bio
                current_app.logger.info(f"Validation successful | username={username} | at time {datetime.utcnow().isoformat()} | {request.remote_addr} ")
                flash('login successful!')
                return redirect(url_for('main.dashboard'))
#------------------------------- returns for failed logic check -----------------------------------------------------
            current_app.logger.warning(f"Login_failed | username={username} | ip={request.remote_addr} | "
                                       f"at time {datetime.utcnow().isoformat()}")
            flash('Login credentials are invalid, please try again')
        return render_template('login.html', form=form)
    current_app.logger.warning(f"Login_failed | ip={request.remote_addr}"
                               f"| at time {datetime.utcnow().isoformat()}")
    flash('Invalid username or password!')
    return render_template('login.html', form=form)

#--------------------------------------------------------------------------------------------------------------------

@main.route('/logout')
def logout():
    logout_user()
    session.clear()
    flash('you have been logged out')
    return redirect(url_for('main.login'))


@main.route('/dashboard')
@login_required
def dashboard():
    username = current_user.username
    bio = current_user.bio
    decrypted_value = current_app.fernet.decrypt(current_user.bio.encode()).decode()
    return render_template('dashboard.html', username=username, bio=decrypted_value)

@main.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
#----------------------------------------form validation check--------------------------------------------------
    if form.validate_on_submit():
        row = db.session.execute(text("SELECT id FROM user WHERE username=:user"),
                                 {"user": form.username.data}).mappings().first()
        existing_user = User.query.get(row["id"]) if row else None
        if existing_user:
            flash("This username already exists. Please choose another.", "error")
            return render_template('register.html', form=form)

        pw_pepper = form.password.data + current_app.PEPPER
        hashed_pw = bcrypt.generate_password_hash(pw_pepper).decode('utf-8')

        bio = bleach.clean(
            form.bio.data,
            tags=['b', 'i', 'u', 'em', 'strong', 'a', 'p', 'ul', 'ol', 'li', 'br'],
            attributes={'a': ['href', 'title']},
            strip=True)
        encrypted_bio = current_app.fernet.encrypt(bio.encode()).decode()
        user = User(username=form.username.data,
                    password=hashed_pw,
                    bio=encrypted_bio,
                    role=form.role.data)
        db.session.add(user)
        db.session.commit()
        flash("Account created successfully")
        return redirect(url_for('main.login'))
    return render_template('register.html', form=form)
#--------------------------------------------------------------------------------------------------------

#------------------------------------ wrappers ----------------------------------------------------------
def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):     # decorator for role_required
            if session.get('role') != role:
                stack = ''.join(traceback.format_stack(limit=25))
                current_app.logger.warning(f"access denied | required={role} |"       # logs relevant secure information
                                           f" user_id={getattr(current_user, 'id', None)} | {request.remote_addr}"
                                           f"| at time {datetime.utcnow().isoformat()}")
                abort(403, description=f"Access denied.\n\n--- STACK ---\n{stack}")
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def errorhandler(code, template):
    def decorator(f):
        @wraps(f)
        def wrapper(error):
            stack = traceback.format_exc()
            current_app.logger.error(
                f"[{datetime.utcnow().isoformat()}] ERROR {code}: {error}\n{stack}")
            return render_template(template, code=code), code
        return wrapper
    return decorator

#----------------------------------------------------------------------------------------------------------
@main.app_errorhandler(400)
@errorhandler(404, '404.html')
def page_not_found(error):
    return render_template('404.html'), 404

@main.app_errorhandler(403)
@errorhandler(403, '403.html')
def forbidden(error):
    return render_template('403.html'), 403

@main.app_errorhandler(500)
@errorhandler(500, '500.html')
def internal_error(error):
    app.logger.error(f"Internal error: {error}", exec_info = True)
    render_template('500.html'), 500

@main.route('/admin-panel')
@login_required
@role_required('admin')
def admin():
    return render_template('admin.html')

@main.route('/moderator')
@login_required
@role_required('moderator')
def moderator():
    return render_template('moderator.html')

@main.route('/user-dashboard')
@login_required
@role_required('user')
def user_dashboard():
    return render_template('user_dashboard.html', username=session.get('user'))


@main.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        current_password = form.current_password.data
        new_password = form.new_password.data
        current_pepper = current_password + current_app.PEPPER

        # Enforce: current password must be valid for user
        if not bcrypt.check_password_hash(current_user.password, current_pepper):
            current_app.logger.warning(f"Password change failed | reason=wrong_current | user_id={current_user.id} | "
                                       f"ip={request.remote_addr} | at time {datetime.utcnow().isoformat()}")
            flash('Current password is incorrect', 'error')
            return render_template('change_password.html', form=form)

        # Enforce: new password must be different from current password
        if new_password == current_password:
            current_app.logger.info(f"Password changed successfully | user_id={current_user.id} | "
                                    f"ip={request.remote_addr} | at time {datetime.utcnow().isoformat()}")
            flash('New password must be different from the current password', 'error')
            return render_template('change_password.html', form=form)

        new_pw_pepper = new_password + current_app.PEPPER
        hashed_pw = bcrypt.generate_password_hash(new_pw_pepper).decode('utf-8')
        current_user.password = hashed_pw
        db.session.commit()

        flash('Password changed successfully', 'success')
        return redirect(url_for('main.dashboard', form=form))

    return render_template('change_password.html', form=form)





