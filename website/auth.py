from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db   ##means from __init__.py import db
from flask_login import login_user, login_required, logout_user, current_user
import ast


auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        data_string = request.data.decode("UTF-8")
        data = ast.literal_eval(data_string)
        email = data['email']
        password = data['password']

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('Logged in successfully!', category='success')
                login_user(user, remember=True)
                return {'status':True, 'message':''}
            else:
                flash('Incorrect password, try again.', category='error')
                return {'status':False, 'message':'Incorrect password, try again.' }
        else:
            flash('Email does not exist.', category='error')
            return {'status':False, 'message':'Email does not exist.'}

    return {'status':False, 'message':''}


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        data_string = request.data.decode("UTF-8")
        data = ast.literal_eval(data_string)
        email = data['email']
        # NIK = request.form.get('NIK')
        password1 = data['password1']
        password2 = data['password2']

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')
            return {'status':False, 'message':'Email already exists.'}
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
            return {'status':False, 'message':'Email must be greater than 3 characters.'}
        # elif len(NIK) < 16:
        #     flash('NIK must be greater than 16.', category='error')
        #     return {'status':False, 'message':'Email already exists.'}
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
            return {'status':False, 'message':'Password Dont match.'}
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
            return {'status':False, 'message':'Email already exists.'}
        else:
            new_user = User(email=email, password=generate_password_hash(
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('Account created!', category='success')
            return {'status':True, 'message':'Account Created'}

    return {'status':False, 'message':''}
