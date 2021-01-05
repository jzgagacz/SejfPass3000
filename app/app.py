from flask import Flask, render_template, request, redirect, url_for, flash, g
from flask.helpers import make_response
from flask_recaptcha import ReCaptcha
import mariadb
import time
from uuid import uuid4
from random import randrange

from os import getenv
from dotenv import load_dotenv

from bcrypt import gensalt, hashpw, checkpw
from Crypto.Cipher import AES

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
    coursor.execute("CREATE TABLE users (id INT PRIMARY KEY AUTO_INCREMENT, login VARCHAR(32), hashedpass VARCHAR(128), hashedmasterpass VARCHAR(128), loginattempts INT, UNIQUE (login))")
    coursor.execute("DROP TABLE IF EXISTS sessions")
    coursor.execute("CREATE TABLE sessions (id INT PRIMARY KEY AUTO_INCREMENT, sid VARCHAR(128), login VARCHAR(32), expires BIGINT)")
    coursor.execute("DROP TABLE IF EXISTS passwords")
    coursor.execute("CREATE TABLE passwords (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(128), encryptedpw VARBINARY(128), login VARCHAR(32), salt VARBINARY(32), iv VARBINARY(32))")
    initdb.commit()
    initdb.close()
    db = mariadb.connect(host=SQL_HOST,user=SQL_USR, password=SQL_PASS, database=SQL_DB)
    cursor = db.cursor()

def user_exists(login):
    ret = None
    cursor.execute("SELECT EXISTS(SELECT 1 FROM users WHERE login = ?)", (login,))
    for (record, ) in cursor:
        ret = record
    return ret

def save_user(login, password, masterhash):
    try:
        hashed = hashpw(password.encode(), gensalt()).decode()
        cursor.execute("INSERT INTO users (login, hashedpass, hashedmasterpass, loginattempts) VALUES (?, ?, ?, ?)", (login, hashed, masterhash, 0))
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
        print(f"{e}", flush=True)
        return None

def create_session(login):
    try:
        sid = str(uuid4())
        exp = int(time.time()) + SESSION_MAX_AGE
        cursor.execute("INSERT INTO sessions (sid, login, expires) VALUES (?, ?, ?)", (sid, login, exp))
        db.commit()
        return sid
    except:
        return None

def get_data_from_session(sid):
    try:
        cursor.execute("SELECT login, expires FROM sessions WHERE sid=?", (sid,))
        login = None
        exp = None
        for (l,e) in cursor:
            login = l
            exp = e
        if exp < int(time.time()):
            cursor.execute("DELETE FROM sessions WHERE sid=?", (sid,))
            db.commit()
            login = None
        return login
    except:
        return None

def delete_session(sid):
    try:
        cursor.execute("DELETE FROM sessions WHERE sid=?", (sid,))
        db.commit()
        return True
    except:
        return False

@app.before_request
def before_request():
    sid = request.cookies.get('session_id', None)
    login = get_data_from_session(sid)
    g.user = login

@app.route('/', methods=["GET"])
def index():
    print(recaptcha.secret_key, flush=True)
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
    sid = create_session(login)
    if sid is None:
        flash("Błąd podczas tworzenia sesji użytkownika")
        return redirect(url_for('login', captcha=captcha))
    response = make_response('', 303)
    response.set_cookie("session_id", sid, httponly=True, secure=True, max_age=SESSION_MAX_AGE)
    response.headers["Location"] = url_for("dashboard")
    return response

@app.route('/logout', methods=["GET"])
def logout():
    if g.user is None:
        return redirect(url_for('index'))
    sid = request.cookies.get('session_id', None)
    success = delete_session(sid)
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
    if login is None:
        return "No login provided", 400
    if password is None:
        return "No password provided", 400
    if masterhash is None:
        return "No master password hash provided", 400
    try: 
        s = user_exists(login)
    except:
        flash("Nie można połączyć się z bazą danych")
        return redirect(url_for('signup'))
    if s == 1:
        flash("Użytkownik już istnieje")
        return redirect(url_for('signup'))
    success = save_user(login, password, masterhash)
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
    return render_template("dashboard.html", passwords=passwords)

@app.route('/dashboard', methods=["POST"])
def dashboard_post():
    if g.user is None:
        return "Unauthorized", 401
    name = request.form.get("name")
    encryptedpw = request.form.get("encryptedpw")
    salt = request.form.get("salt")
    iv = request.form.get("iv")
    if name is None:
        return "No service name provided", 400
    if encryptedpw is None:
        return "No encrypted password provided", 400
    if salt is None:
        return "No salt provided", 400
    if iv is None:
        return "No iv provided", 400
    bencryptedpw = bytes(list(map(int, encryptedpw.split(","))))
    bsalt = bytes(list(map(int, salt.split(","))))
    biv = bytes(list(map(int, iv.split(","))))
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

if __name__ == '__main__':
    app.run(host="0.0.0.0")