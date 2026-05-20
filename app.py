
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import sqlite3
import os
import qrcode
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime

app = Flask(__name__)
app.secret_key = "professional_project_secret"

UPLOAD_FOLDER = "static/uploads"
SIGNATURE_FOLDER = "static/signatures"
QRCODE_FOLDER = "static/qrcodes"
KEY_FOLDER = "keys"

ALLOWED_EXTENSIONS = {"pdf", "txt", "docx"}

def init_db():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT,
            timestamp TEXT
        )
    ''')

    conn.commit()
    conn.close()

def log_action(username, action):
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute(
        "INSERT INTO logs(username, action, timestamp) VALUES(?,?,?)",
        (username, action, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )

    conn.commit()
    conn.close()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_keys(username):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    with open(f"{KEY_FOLDER}/{username}_private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(f"{KEY_FOLDER}/{username}_public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def load_private_key(username):
    with open(f"{KEY_FOLDER}/{username}_private.pem", "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

def load_public_key(username):
    with open(f"{KEY_FOLDER}/{username}_public.pem", "rb") as key_file:
        return serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']

        conn = sqlite3.connect("database.db")
        cur = conn.cursor()

        try:
            cur.execute(
                "INSERT INTO users(username,password,role) VALUES(?,?,?)",
                (username, password, role)
            )

            conn.commit()
            generate_keys(username)
            log_action(username, "Registered")

            return redirect(url_for('login'))

        except:
            return "Username already exists"

    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=?", (username,))
        user = cur.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['username'] = username
            session['role'] = user[3]

            log_action(username, "Logged In")

            return redirect(url_for('dashboard'))

    return render_template("login.html")

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    return render_template("dashboard.html", username=session['username'])

@app.route('/logout')
def logout():
    if 'username' in session:
        log_action(session['username'], "Logged Out")

    session.clear()
    return redirect(url_for('home'))

@app.route('/sign', methods=['GET', 'POST'])
def sign():
    signed_file = None
    qr_code = None

    if request.method == 'POST':

        file = request.files['file']

        if file and allowed_file(file.filename):

            filename = secure_filename(file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)

            file.save(filepath)

            private_key = load_private_key(session['username'])

            with open(filepath, "rb") as f:
                data = f.read()

            signature = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            sig_path = os.path.join(SIGNATURE_FOLDER, filename + ".sig")

            with open(sig_path, "wb") as sig_file:
                sig_file.write(signature)

            qr_data = f"Verified File: {filename} | Signed By: {session['username']}"

            qr_img = qrcode.make(qr_data)
            qr_filename = filename + "_qr.png"

            qr_path = os.path.join(QRCODE_FOLDER, qr_filename)
            qr_img.save(qr_path)

            signed_file = filename + ".sig"
            qr_code = qr_filename

            log_action(session['username'], f"Signed file {filename}")

    return render_template(
        "sign.html",
        signed_file=signed_file,
        qr_code=qr_code
    )

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    result = None

    if request.method == 'POST':

        username = request.form['username']
        file = request.files['file']
        signature_file = request.files['signature']

        filepath = os.path.join(UPLOAD_FOLDER, secure_filename(file.filename))
        sigpath = os.path.join(SIGNATURE_FOLDER, secure_filename(signature_file.filename))

        file.save(filepath)
        signature_file.save(sigpath)

        public_key = load_public_key(username)

        with open(filepath, "rb") as f:
            data = f.read()

        with open(sigpath, "rb") as f:
            signature = f.read()

        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            result = "Signature Verified Successfully"
            log_action(username, f"Verified file {file.filename}")

        except:
            result = "Tampered File or Invalid Signature"
            log_action(username, f"Verification failed for {file.filename}")

    return render_template("verify.html", result=result)

@app.route('/logs')
def logs():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute("SELECT * FROM logs ORDER BY id DESC")
    logs = cur.fetchall()

    conn.close()

    return render_template("logs.html", logs=logs)

@app.route('/download/signature/<filename>')
def download_signature(filename):
    return send_from_directory(SIGNATURE_FOLDER, filename, as_attachment=True)

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
