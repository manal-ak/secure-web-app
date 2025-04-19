#This file contains all the web page logic
#Each @app.route() function handles a specific URL:
#/register: user registration logic
#/login: user login logic
#/dashboard: what user sees when logged in
#/logout: ends the session
from flask import render_template, redirect, url_for, flash, request
from flask import abort
from app import app, db, bcrypt
from app.models import User
from flask_login import login_user, logout_user, login_required, current_user

@app.route('/')
def home():
    return redirect(url_for('login'))

"""
import hashlib  

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # ❌ Weak password hashing using MD5 
        hashed_password = hashlib.md5(password.encode()).hexdigest()

        new_user = User(username=username, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')
"""

#strong hashing mechanism(bycrypt)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

"""
SQL Injection

from sqlalchemy import text

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # ❌ Deliberately vulnerable to SQL injection (demo)
        query = text(f"SELECT * FROM user WHERE username = '{username}' AND password = '{password}'")
        result = db.session.execute(query).fetchone()

        if result:
            # 👇 Build the user manually from the result
            user = User.query.get(result.id)
            login_user(user)

            if user.role == 'admin':
                return redirect(url_for('admin_panel'))
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your credentials.', 'danger')

    return render_template('login.html')
    """
"""
Weak Password Storage for the md5 password storing
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # ❌ Match weak MD5 password
        hashed_input_password = hashlib.md5(password.encode()).hexdigest()
        user = User.query.filter_by(username=username, password=hashed_input_password).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_panel'))
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your credentials.', 'danger')

    return render_template('login.html')
"""
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # ✅ Safe query using SQLAlchemy ORM (prevents SQL injection)
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_panel'))
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your credentials.', 'danger')

    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        current_user.comment = request.form['comment']
        db.session.commit()
        flash("Comment posted!", "success")
        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', username=current_user.username, comment=current_user.comment)

"""
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)
"""

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin')
@login_required
def admin_panel():
    if current_user.role != 'admin':
        abort(403)
    flash('Welcome, Admin!', 'success')
    return render_template('admin.html', username=current_user.username)

@app.route('/admin-button')
@login_required
def admin_button():
    if current_user.role != 'admin':
        flash('Access Denied: You are not an admin.', 'danger')
        return redirect(url_for('dashboard'))
    return redirect(url_for('admin_panel'))
