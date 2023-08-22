from flask import Flask, request, Response, redirect, render_template, abort, make_response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import re
import os
import jinja2
import hashlib
import hmac
import random
import string

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users_date.db'
app.config['SQLALCHEMY_TRACK_MODIFICATION'] = False
db = SQLAlchemy(app)

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

USER_NAME = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
USER_PASSWORD = re.compile(r"^.{3,20}$")
USER_EMAIL = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
SECRET = "imsosecret"

class users_data(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username = db.Column(db.String(50), unique = True)
    password = db.Column(db.String(50), unique = False)

def make_salt():
    return ''.join(random.choice(string.ascii_letters) for x in range(5))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name.encode('utf-8') + pw.encode('utf-8') + salt.encode('utf-8')).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    input_pw = make_pw_hash(name, pw, salt)
    if h == input_pw:
        return True
    return False

def hash_str(s):
    return hmac.new(SECRET.encode('utf-8'), s.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()

def make_secure_val(s):
    return "%s,%s" % (s, hash_str(s))

def check_secure_val(h):
    value = h.split(',')[0]
    if h == make_secure_val(value):
        return value

def valid_username(username):
    return USER_NAME.match(username)

def valid_password(password):
    return USER_PASSWORD.match(password)

def passwords_match(password, verify_password):
    if password == verify_password:
        return password
    else:
        return None

def valid_email(email):
    if email != '':
        return USER_EMAIL.match(email)
    return True

@app.route("/")
def redirecting():
    return redirect("/signup")

@app.route("/signup", methods=['GET', 'POST'])
def form():
    t = jinja_env.get_template("signUp.html")
    if request.method == 'POST':
        user_name = request.form["username"] 
        user_password = request.form["password"]
        user_verify_password = request.form["verify"]
        user_email = request.form["email"]

        username = valid_username(user_name)
        password = valid_password(user_password)
        verify_password = passwords_match(user_password, user_verify_password)
        email = valid_email(user_email)
        if not username:
            if not password:
                return t.render(invalid_password="Password is invalid!", invalid_username="Username is invalid!", user_name=user_name)
            if not verify_password:
                return t.render(passwords_missmatch="Passwords didn't match!", invalid_username="Username is invalid!", user_name=user_name)
            return t.render(invalid_username="Username is invalid!", user_name=user_name)
        if not password:
            return t.render(invalid_password="Password is invalid!", user_name=user_name)
        if not verify_password:
            return t.render(passwords_missmatch="Passwords didn't match!", user_name=user_name)
        if not email:
            return t.render(invalid_email="Email is invalid!", user_email=user_email, user_name=user_name)
        else:
            if not users_data.query.filter(users_data.username == user_name).all():
                user_data = users_data(username=user_name, password=make_pw_hash(user_name, user_password))
                db.session.add(user_data)
                db.session.commit()
                user_id = str(user_data.id)
                new_cookie_val = make_secure_val(str(user_id))
                response = redirect("/welcome")
                response.headers['Set-Cookie'] = 'user_id=%s' % new_cookie_val
                return response
            else:
                return t.render(invalid_username="User already exists", user_name=user_name)
    return t.render()

@app.route("/login", methods=['GET', 'POST'])
def login():
    t = jinja_env.get_template("login.html")
    if request.method == 'POST':
        user_name = request.form["username"] 
        user_password = request.form["password"]
        if users_data.query.filter_by(username=user_name).first().username:
            h = users_data.query.filter_by(username=user_name).first().password
            if valid_pw(user_name, user_password, h):
                user_id = users_data.query.filter_by(username=user_name).first().id
                new_cookie_val = make_secure_val(str(user_id))
                response = redirect("/welcome")
                response.headers['Set-Cookie'] = 'user_id=%s' % new_cookie_val
                return response
            else:
                return t.render(invalid_login="Invalid login!")
    return t.render()

@app.route("/welcome")
def welcome_page():
    t = jinja_env.get_template("welcome.html")
    
    if request.cookies.get('user_id'):
        user_id_cookie_str = request.cookies.get('user_id')
        if user_id_cookie_str:
            cookie_val = check_secure_val(user_id_cookie_str)
            if cookie_val:
                user_id = int(cookie_val)
            else:
                return redirect("/signup")
        username = users_data.query.filter_by(id=user_id).first().username
        return t.render(username=username)
    return redirect("/login")

@app.route("/logout")
def logout():
    response = redirect("/login")
    response.set_cookie('user_id', '', expires=0)
    return response

if __name__ == "__main__":
    app.run()