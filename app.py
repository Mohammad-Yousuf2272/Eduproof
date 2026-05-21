
from flask import Flask, render_template

app = Flask(__name__)

# Home Page
@app.route('/')
def home():
    return render_template('index.html')


# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html')


# Register Page
@app.route('/register', methods=['GET', 'POST'])
def register():
    return render_template('register.html')


# Dashboard Page
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


# Verify Certificate Page
@app.route('/verify', methods=['GET', 'POST'])
def verify():
    return render_template('verify.html')




import os

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
