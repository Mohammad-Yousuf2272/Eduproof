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


if __name__ == '__main__':
    app.run(debug=True)

   
