from logging import exception, log
from flask import Flask, render_template, request, redirect, url_for, flash, g
from flask.helpers import make_response
from flask_recaptcha import ReCaptcha
import mariadb
import time
from datetime import datetime, timedelta
from uuid import uuid4
from random import randrange
import re
from secrets import token_urlsafe
from jwt import encode, decode

from os import getenv
from dotenv import load_dotenv

from bcrypt import gensalt, hashpw, checkpw

load_dotenv()
SQL_HOST = "mariadb"
SQL_USR = "root"
SQL_PASS = getenv("SQL_PASS")
SQL_DB = "db"
SECRET_KEY = getenv("SECRET_KEY")
SESSION_MAX_AGE = 1800
MAX_LOGIN_ATTEMPTS = 3
RECAPTCHA_SITE_KEY = getenv("RECAPTCHA_SITE_KEY")
RECAPTCHA_SECRET_KEY = getenv("RECAPTCHA_SECRET_KEY")
HONEYPOT_USER = getenv("HONEYPOT_USER")
HONEYPOT_PASS = getenv("HONEYPOT_PASS")
HONEYPOT_HASH = getenv("HONEYPOT_HASH")
HONEYPOT_EMAIL = getenv("HONEYPOT_EMAIL")

FIELD_REGEX = '^[A-Za-z0-9!@#$%^&*,.=_|:+\/\\\-]*$'

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update({
    "RECAPTCHA_SITE_KEY": RECAPTCHA_SITE_KEY,
    "RECAPTCHA_SECRET_KEY": RECAPTCHA_SECRET_KEY,
    "RECAPTCHA_ENABLED": True
})
recaptcha = ReCaptcha(app=app)

db = None
cursor = None

def generate_password_reset_token(login):
    payload = {
        "reset_pass_for":login,
        "exp":datetime.utcnow() + timedelta(seconds = 900)
    }
    token = encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def decode_password_reset_token(token):
    try:
        decoded = decode(token, SECRET_KEY, algorithms=['HS256'])
        return decoded
    except:
        return None

def user_exists(login):
    ret = None
    cursor.execute("SELECT EXISTS(SELECT 1 FROM users WHERE login = ?)", (login,))
    for (record, ) in cursor:
        ret = record
    return ret

def save_user(login, password, masterhash, email):
    try:
        hashed = hashpw(password.encode(), gensalt()).decode()
        cursor.execute("INSERT INTO users (login, hashedpass, hashedmasterpass, loginattempts, email) VALUES (?, ?, ?, ?, ?)", (login, hashed, masterhash, 0, email))
        db.commit()
        return True
    except:
        return False

def change_user_password(login, password):
    try:
        hashed = hashpw(password.encode(), gensalt()).decode()
        cursor.execute("UPDATE users SET hashedpass=? WHERE login=?", (hashed, login))
        db.commit()
        return True
    except:
        return False

def get_login_attempts(login):
    try:
        cursor.execute("SELECT loginattempts FROM users WHERE login=?", (login,))
        attempts = None
        for (a,) in cursor:
            attempts = a
        if attempts is None:
            return 0
        return attempts
    except:
        return 0
def get_user_email(login):
    try:
        cursor.execute("SELECT email FROM users WHERE login=?", (login,))
        email = None
        for (e,) in cursor:
            email = e
        return email
    except:
        return None
def check_password(login, password):
    try:
        cursor.execute("SELECT hashedpass FROM users WHERE login=?", (login,))
        hpass = None
        for (h,) in cursor:
            hpass = h
        if hpass is None:
            time.sleep(randrange(400, 700)/1000)
            return False
        attempts = get_login_attempts(login)
        time.sleep(randrange(200, 700)/1000)
        passcorr = checkpw(password.encode(), hpass.encode())
        if not passcorr:
            cursor.execute("UPDATE users SET loginattempts=? WHERE login=?", (attempts+1, login))
            db.commit()
        else:
            cursor.execute("UPDATE users SET loginattempts=? WHERE login=?", (0, login))
            db.commit()
        return passcorr 
    except:
        return False

def get_masterhash(login):
    try:
        cursor.execute("SELECT hashedmasterpass FROM users WHERE login=?", (login,))
        hash = None
        for (h,) in cursor:
            hash = h
        return hash
    except:
        return None

def add_password(login, name, encpass, salt, iv):
    try:
        cursor.execute("INSERT INTO passwords (name, encryptedpw, login, salt, iv) VALUES (?, ?, ?, ?, ?)", ( name, encpass, login, salt, iv))
        db.commit()
        return True
    except:
        return False

def get_user_passwords(login):
    try:
        cursor.execute("SELECT name, encryptedpw, salt, iv FROM passwords WHERE login=?", (login,))
        passwords = {}
        for (n, p, s, i) in cursor:
            passwords[n] = {}
            passwords[n]["encryptedpw"] = str(p)[2:-1]
            passwords[n]["arraypass"] = list(p)
            passwords[n]["salt"] = list(s)
            passwords[n]["iv"] = list(i)
        return passwords
    except Exception as e:
        return None

def create_session(login, ip, device, csrftoken):
    try:
        sid = str(uuid4())
        logtime = int(time.time())
        exp = logtime + SESSION_MAX_AGE
        cursor.execute("INSERT INTO sessions (sid, login, logtime, expires, ip, useragent, csrftoken) VALUES (?, ?, ?, ?, ?, ?, ?)", (sid, login, logtime, exp, ip, device, csrftoken))
        db.commit()
        return sid
    except Exception as e:
        return None

def get_data_from_session(sid):
    try:
        cursor.execute("SELECT login, expires, csrftoken FROM sessions WHERE sid=?", (sid,))
        login = None
        exp = None
        csrftoken = None
        for (l,e,c) in cursor:
            login = l
            exp = e
            csrftoken = c
        if exp < int(time.time()):
            return (None, None)
        return (login, csrftoken)
    except:
        return (None, None)   

def expire_session(sid):
    try:
        cursor.execute("UPDATE sessions SET expires=? WHERE sid=?", (-1,sid))
        db.commit()
        return True
    except:
        return False

def get_user_sessions(login):
    try:
        cursor.execute("SELECT logtime, expires, ip, useragent FROM sessions WHERE login=?", (login,))
        sessions = []
        for (l, e, i, u) in cursor:
            session = {}
            session["logtime"] = datetime.utcfromtimestamp(l).strftime('%Y-%m-%d %H:%M:%S')
            if e < int(time.time()):
                session["expired"] = True
            else:
                session["expired"] = False
            session["ip"] = i
            session["useragent"] = u
            sessions.insert(0, session)
        return sessions
    except Exception as e:
        return None

try:
    time.sleep(3)
    db = mariadb.connect(host=SQL_HOST,user=SQL_USR, password=SQL_PASS, database=SQL_DB)
    cursor = db.cursor()
except:
    initdb = mariadb.connect(host=SQL_HOST,user=SQL_USR, password=SQL_PASS)
    coursor = initdb.cursor()
    coursor.execute(f"DROP DATABASE IF EXISTS {SQL_DB}")
    coursor.execute(f"CREATE DATABASE {SQL_DB}")
    coursor.execute(f"USE {SQL_DB}")
    coursor.execute("DROP TABLE IF EXISTS users")
    coursor.execute("CREATE TABLE users (id INT PRIMARY KEY AUTO_INCREMENT, login VARCHAR(32), hashedpass VARCHAR(128), hashedmasterpass VARCHAR(128), loginattempts INT, email VARCHAR(128), UNIQUE (login))")
    coursor.execute("DROP TABLE IF EXISTS sessions")
    coursor.execute("CREATE TABLE sessions (id INT PRIMARY KEY AUTO_INCREMENT, sid VARCHAR(128), login VARCHAR(32), logtime BIGINT, expires BIGINT, ip VARCHAR(32), useragent VARCHAR(512), csrftoken VARCHAR(128))")
    coursor.execute("DROP TABLE IF EXISTS passwords")
    coursor.execute("CREATE TABLE passwords (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(128), encryptedpw VARBINARY(512), login VARCHAR(32), salt VARBINARY(32), iv VARBINARY(32))")
    initdb.commit()
    initdb.close()
    db = mariadb.connect(host=SQL_HOST,user=SQL_USR, password=SQL_PASS, database=SQL_DB)
    cursor = db.cursor()
    save_user(HONEYPOT_USER, HONEYPOT_PASS, HONEYPOT_HASH, HONEYPOT_EMAIL)


@app.before_request
def before_request():
    sid = request.cookies.get('session_id', None)
    (login, csrftoken) = get_data_from_session(sid)
    g.user = login
    g.csrf = csrftoken

@app.route('/', methods=["GET"])
def index():
    return render_template("index.html")

@app.route('/login', methods=["GET"])
def login():
    if g.user is not None:
        return redirect(url_for('logout'))
    captcha = request.args.get('captcha')
    if captcha == "True":
        captcha = True
    else:
        captcha = False
    return render_template("login.html", captcha=captcha)

@app.route('/login', methods=["POST"])
def login_post():
    login = request.form.get("login")
    password = request.form.get("password")
    if login is None:
        return "No login provided", 400
    if password is None:
        return "No password provided", 400
    if len(login) < 3 or len(login) > 20:
        return "Wrong login length", 400
    if len(password) < 8 or len(password) > 40:
        return "Wrong password length", 400
    if not re.compile(FIELD_REGEX).match(login):
        return "Invalid character in login", 400
    if not re.compile(FIELD_REGEX).match(password):
        return "Invalid character in password", 400
    attempts = get_login_attempts(login)
    captcha = False
    if attempts > MAX_LOGIN_ATTEMPTS:
        captcha=True
    if captcha and not recaptcha.verify():
        flash("Zbyt wiele prób logowania, wypełnij Captcha")
        return redirect(url_for('login', captcha=captcha))
    success = check_password(login, password)
    if not success:
        flash("Niepoprawny login lub hasło")
        return redirect(url_for('login', captcha=captcha))
    ip = request.remote_addr
    device = request.headers.get("User-Agent")
    csrftoken = token_urlsafe(32)
    sid = create_session(login, ip, device, csrftoken)
    if sid is None:
        flash("Błąd podczas tworzenia sesji użytkownika")
        return redirect(url_for('login', captcha=captcha))
    if login == HONEYPOT_USER:
        print("!!!KTOŚ ZALOGOWAŁ SIĘ NA KONTO PUŁAPKĘ!!!", flush=True)
    response = make_response('', 303)
    response.set_cookie("session_id", sid, httponly=True, secure=True, max_age=SESSION_MAX_AGE)
    response.headers["Location"] = url_for("dashboard")
    return response

@app.route('/logout', methods=["GET"])
def logout():
    if g.user is None:
        return redirect(url_for('index'))
    sid = request.cookies.get('session_id', None)
    success = expire_session(sid)
    if not success:
        flash("Błąd podczas wylogowywania")
        return redirect(url_for('index'))
    response = make_response('', 303)
    response.set_cookie("session_id", "", max_age=-1)
    response.headers["Location"] = url_for("index")
    return response

@app.route('/signup', methods=["GET"])
def signup():
    return render_template("signup.html")

@app.route('/signup', methods=["POST"])
def signup_post():
    login = request.form.get("login")
    password = request.form.get("password")
    masterhash = request.form.get("masterhash")
    email = request.form.get("email")
    if login is None:
        return "No login provided", 400
    if password is None:
        return "No password provided", 400
    if masterhash is None:
        return "No master password hash provided", 400
    if email is None:
        return "No email provided", 400
    if len(login) < 3 or len(login) > 20:
        return "Wrong login length", 400
    if len(password) < 8 or len(password) > 40:
        return "Wrong password length", 400
    if len(masterhash) < 1 or len(masterhash) > 100:
        return "Wrong master password hash length", 400
    if len(email) < 3 or len(email) > 100:
        return "Wrong email length", 400
    if not re.compile(FIELD_REGEX).match(login):
        return "Invalid character in login", 400
    if not re.compile(FIELD_REGEX).match(password):
        return "Invalid character in password", 400
    if not re.compile(FIELD_REGEX).match(masterhash):
        return "Invalid character in masterhash", 400
    if not re.compile(FIELD_REGEX).match(email):
        return "Invalid character in email", 400
    try: 
        s = user_exists(login)
    except:
        flash("Nie można połączyć się z bazą danych")
        return redirect(url_for('signup'))
    if s == 1:
        flash("Użytkownik już istnieje")
        return redirect(url_for('signup'))
    success = save_user(login, password, masterhash, email)
    if not success:
        flash("Błąd podczas rejestracji użytkownika")
        return redirect(url_for('signup'))
    return redirect(url_for('login'))
    
@app.route('/dashboard', methods=["GET"])
def dashboard():
    if g.user is None:
        return redirect(url_for('login'))
    passwords = get_user_passwords(g.user)
    if passwords is None:
        flash("Nie można pobrać listy haseł")
    return render_template("dashboard.html", passwords=passwords, csrf = g.csrf)

@app.route('/dashboard', methods=["POST"])
def dashboard_post():
    if g.user is None:
        return "Unauthorized", 401
    csrf = request.form.get("csrf-token")
    name = request.form.get("name")
    encryptedpw = request.form.get("encryptedpw")
    salt = request.form.get("salt")
    iv = request.form.get("iv")
    if csrf is None:
        return "No csrf token provided", 400
    if csrf != g.csrf:
        return "Incorrect csrf token", 400
    if name is None:
        return "No service name provided", 400
    if encryptedpw is None:
        return "No encrypted password provided", 400
    if salt is None:
        return "No salt provided", 400
    if iv is None:
        return "No iv provided", 400
    if len(name) < 1 or len(name) > 100:
        return "Wrong service name length", 400
    if len(csrf) < 1 or len(csrf) > 128:
        return "Wrong csrf token length", 400
    if not re.compile(FIELD_REGEX).match(name):
        return "Invalid character in name", 400
    if not re.compile(FIELD_REGEX).match(csrf):
        return "Invalid character in csrf token", 400
    if not re.compile('^[0-9,]*$').match(encryptedpw):
        return "Invalid encrypted password provided", 400
    if not re.compile('^[0-9,]*$').match(salt):
        return "Invalid salt provided", 400
    if not re.compile('^[0-9,]*$').match(iv):
        return "Invalid iv provided", 400
    bencryptedpw = bytes(list(map(int, encryptedpw.split(","))))
    bsalt = bytes(list(map(int, salt.split(","))))
    biv = bytes(list(map(int, iv.split(","))))
    if len(bencryptedpw) < 1 or len(bencryptedpw) > 500:
        return "Wrong encrypted password length", 400
    if len(bsalt) < 1 or len(bsalt) > 30:
        return "Wrong salt length", 400
    if len(biv) < 1 or len(biv) > 30:
        return "Wrong iv length", 400
    success = add_password(g.user, name, bencryptedpw, bsalt,biv)
    if not success:
        flash("Błąd podczas dodawania hasła")
        return redirect(url_for('dashboard'))
    return redirect(url_for('dashboard'))

@app.route('/masterhash', methods=["GET"])
def masterhash():
    if g.user is None:
        return "Unauthorized", 401
    hash = get_masterhash(g.user)
    if hash is None:
        return "Cannot get hash", 500
    return hash, 200

@app.route('/sessions', methods=["GET"])
def sessions():
    if g.user is None:
        return redirect(url_for('login'))
    sessions = get_user_sessions(g.user)
    if sessions is None:
        flash("Nie można pobrać listy sesji")
    return render_template('sessions.html', sessions=sessions)

@app.route('/reset', methods=["GET"])
def reset_password():
    return render_template('reset.html')


@app.route('/reset', methods=["POST"])
def reset_password_post():
    login = request.form.get("login")
    if login is None:
        return "No login provided", 400
    if len(login) < 3 or len(login) > 20:
        return "Wrong login length", 400
    if not re.compile(FIELD_REGEX).match(login):
        return "Invalid character in login", 400
    try: 
        s = user_exists(login)
    except:
        flash("Nie można połączyć się z bazą danych")
        return redirect(url_for('index'))
    if s == 1:
        email = get_user_email(login)
        token = generate_password_reset_token(login)
        url = request.base_url + "/" + token
        print("!!! RESET HASLA !!!", flush=True)
        print(f"Wysłałbym wiadomość pod adres {email} o treści: Aby zresetować swoje hasło przejdź pod link {url}",flush=True)
        print("!!! RESET HASLA !!!", flush=True)
    return redirect(url_for('index'))

@app.route('/reset/<token>', methods=["GET"])
def reset_password_token(token):
    decoded = decode_password_reset_token(token)
    if decoded is None:
        return "Wrong password reset token", 400
    return render_template('reset_token.html', token=token)

@app.route('/reset/<token>', methods=["POST"])
def reset_password_token_post(token):
    decoded = decode_password_reset_token(token)
    if decoded is None:
        return "Wrong password reset token", 400
    login = decoded.get("reset_pass_for")
    password = request.form.get("password")
    if password is None:
        return "No password provided", 400
    if len(password) < 8 or len(password) > 40:
        return "Wrong password length", 400
    if not re.compile(FIELD_REGEX).match(password):
        return "Invalid character in password", 400
    success = change_user_password(login, password)
    if not success:
        flash("Nie można zmienić hasła, spróbuj ponownie później")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host="0.0.0.0")