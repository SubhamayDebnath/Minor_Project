from flask import Flask, render_template, request, flash, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import random
import string
import re
import time

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Mail configuration


db = SQLAlchemy(app)
mail = Mail(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(100), nullable=False)
    otp_verified = db.Column(db.Boolean, default=False)

class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    otp_code = db.Column(db.String(6), nullable=False)
    expiry_time = db.Column(db.Float, nullable=False)

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    msg = Message('Your OTP Code', sender='your_email@gmail.com', recipients=[email])
    msg.body = f'Your OTP is {otp}. It will expire in 5 minutes.'
    mail.send(msg)

@app.route('/')
def HOMEPAGE():
    return render_template('home/index.html')

phone_regex = re.compile(r"^\+91[789]\d{9}$")
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]{6,}@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

def is_valid_password(password):
    password_regex = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
    return re.match(password_regex, password) is not None


# Register
@app.route('/register', methods=['GET', 'POST'])
def REGISTER():
    try:
        if request.method == 'POST':
            name = request.form.get('name')
            email = request.form.get('email')
            phone = request.form.get('phone')
            password = request.form.get('password')
            
            # Validation checks
            if not name or len(name) < 2:
                flash('Name must be at least 2 characters long!', 'error')
                return redirect(url_for('register'))
            if not phone or not phone_regex.match(phone):
                flash('Please enter a valid Indian phone number!', 'error')
                return redirect(url_for('register'))
            if not email or not is_valid_email(email):
                flash('Please enter a valid email address!', 'error')
                return redirect(url_for('register'))
            if not password or not is_valid_password(password):
                flash('Password must be at least 8 characters long, contain at least one letter, one number, and one special character!', 'error')
                return redirect(url_for('register'))
            
            # Generate OTP and save to DB
            otp = generate_otp()
            otp_expiry = time.time() + 300  # 5 minutes expiry time
            new_otp = OTP(email=email, otp_code=otp, expiry_time=otp_expiry)
            db.session.add(new_otp)
            db.session.commit()
            
            # Send OTP email
            send_otp_email(email, otp)
            flash('OTP sent to your email. Please verify to complete registration.', 'info')
            return redirect(url_for('verify_otp', email=email))

    except Exception as error:
        print('Register error', error)  

    return render_template('auth/register.html')


# OTP verification
@app.route('/verify_otp/<email>', methods=['GET', 'POST'])
def VERIFY_OTP(email):
    try:
        if request.method == 'POST':
            otp = request.form.get('otp')
            otp_entry = OTP.query.filter_by(email=email).first()
            
            if otp_entry:
                if time.time() > otp_entry.expiry_time:
                    flash('OTP has expired. Please request a new OTP.', 'error')
                    return redirect(url_for('register'))
                
                if otp == otp_entry.otp_code:
                    password = request.form.get('password')
                    hashed_password = generate_password_hash(password)
                    
                    user = User(name=request.form.get('name'), email=email, phone=request.form.get('phone'),
                                password=hashed_password, otp_verified=True)
                    db.session.add(user)
                    db.session.commit()
                    db.session.delete(otp_entry)
                    db.session.commit()
                    flash('Registration successful! You can now log in.', 'success')
                    return redirect(url_for('login'))
                else:
                    flash('Invalid OTP. Please try again.', 'error')
                    return redirect(url_for('verify_otp', email=email))
            
            else:
                flash('No OTP found for this email.', 'error')
                return redirect(url_for('register'))
        
        return render_template('auth/verify_otp.html', email=email)

    except Exception as error:
        print('Verify OTP error', error)
        flash('Error occurred while verifying OTP. Please try again.', 'error')
        return redirect(url_for('register'))


# Login
@app.route('/login', methods=['GET', 'POST'])
def LOGIN():
    try:
        if request.method == 'POST':
            email = request.form.get('email')
            password = request.form.get('password')

            if not email or not password:
                flash('Please enter both email and password to log in.', 'error')
                return redirect(url_for('login'))

            user = User.query.filter_by(email=email).first()
            if user and check_password_hash(user.password, password): 
                session['user_id'] = user.id
                session['user_email'] = user.email 
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid email or password!', 'error') 
                return redirect(url_for('login'))

    except Exception as error:
        print('Login error', error)

    return render_template('auth/login.html')


# Dashboard
@app.route('/dashboard')
def DASHBOARD():
    if 'user_id' not in session:
        flash('Please log in first.', 'error')
        return redirect(url_for('login'))
    
    return render_template('dashboard.html')



if __name__ == "__main__":
    app.run(debug=True, use_reloader=True)
