from sre_constants import SUCCESS
from flask import Blueprint, render_template,request,flash,redirect,url_for
from . import db
from flask_login import login_user,logout_user,login_required,current_user

from .models import User
from werkzeug.security import generate_password_hash,check_password_hash

auth= Blueprint('auth', __name__)

@auth.route('/login',methods=["GET","POST"])
def login():
    if request.method=="POST":
        email=request.form.get('email')
        password=request.form.get('password')
        user=User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password,password):
            flash("You are now logged in",category=SUCCESS)
            login_user(user,remember=True)

            return redirect(url_for('views.home'))
        else:
            flash("Incorect username or password",category="error")
    
    return render_template('login.html',user="current_user")
@auth.route('/logout')
@login_required
def logout():
    return redirect(url_for('auth.login'))
@auth.route('/signup',methods=["GET","POST"])
def signup():
    if request.method =='POST':
        email = request.form.get('email')
        firstname = request.form.get('firstName')
        password1=request.form.get('password1')
        password2=request.form.get('password2')
    
        if password1!=password2:
            flash('Passwords do not match',category='error')
            return redirect(url_for('auth.signup'))
        new_user=User(firstname=firstname,email=email,password=generate_password_hash(password1,method='sha256'))
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user,remember=True)
        
        flash("You have successfully signed up",category='success')
        return redirect(url_for('views.home'))
    return render_template("signup.html",user="current_user")
