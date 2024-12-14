from flask import Flask, render_template, request, flash, redirect, url_for, session
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import random
import string
import re
import time

app = Flask(__name__)

# Use a proper secret key for the app
app.config["SECRET_KEY"] = "your_secret_key_here"  # Change this to a real secret key

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Setup URLSafeTimedSerializer for generating reset tokens
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Mail configuration (example)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_email_password'

# Initialize
db = SQLAlchemy(app)
mail = Mail(app)
bcrypt = Bcrypt(app)

# User and OTP models
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

# Utility functions
def generate_otp():
    return "".join(random.choices(string.digits, k=6))

def send_otp_email(email, otp):
    msg = Message("Your OTP Code", sender="your_email@gmail.com", recipients=[email])
    msg.body = f"Your OTP is {otp}. It will expire in 5 minutes."
    try:
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")
        flash("There was an issue sending the OTP. Please try again.", "error")

# Phone and email validation
phone_regex = re.compile(r"^\+91[789]\d{9}$")

def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]{6,}@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None

def is_valid_password(password):
    password_regex = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@#$!%*?&])[A-Za-z\d@$!%*?&]{6,}$'
    return re.match(password_regex, password) is not None

# Routes
@app.route("/")
def home():
    return render_template("home/index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(request.referrer or url_for("dashboard"))
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        phone = request.form.get("phone")
        password = request.form.get("password")

        if not name or len(name) < 2:
            flash("Name must be at least 2 characters long!", "error")
            return redirect(url_for("register"))
        if not phone or not phone_regex.match(phone):
            flash("Please enter a valid Indian phone number!", "error")
            return redirect(url_for("register"))
        if not email or not is_valid_email(email):
            flash("Please enter a valid email address!", "error")
            return redirect(url_for("register"))
        if not password or not is_valid_password(password):
            flash("Password must be at least 6 characters long, contain at least one letter, one number, and one special character!", "error")
            return redirect(url_for("register"))

        session["name"] = name
        session["email"] = email
        session["phone"] = phone
        session["password"] = password

        otp = generate_otp()
        otp_expiry = time.time() + 300
        new_otp = OTP(email=email, otp_code=otp, expiry_time=otp_expiry)
        db.session.add(new_otp)
        db.session.commit()

        send_otp_email(email, otp)
        flash("OTP sent to your email. Please verify to complete registration.", "info")
        return redirect(url_for("verify_otp", email=email))

    return render_template("auth/register.html")

@app.route("/verify_otp/<email>", methods=["GET", "POST"])
def verify_otp(email):
    if "user_id" in session:
        return redirect(request.referrer or url_for("dashboard"))
    if request.method == "POST":
        otp = request.form.get("otp").strip()
        otp_entry = OTP.query.filter_by(email=email).first()

        name = session.get("name")
        email = session.get("email")
        phone = session.get("phone")
        password = session.get("password")
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        password = hashed_password

        if otp_entry:
            if time.time() > otp_entry.expiry_time:
                flash("OTP has expired. Please request a new OTP.", "error")
                return redirect(url_for("register"))
            if otp == otp_entry.otp_code:
                user = User(name=name, email=email, phone=phone, password=password, otp_verified=True)
                db.session.add(user)
                db.session.commit()
                db.session.delete(otp_entry)
                db.session.commit()
                flash("Registration successful! You can now log in.", "success")
                return redirect(url_for("login"))
            else:
                flash("Invalid OTP. Please try again.", "error")
                return redirect(url_for("verify_otp", email=email))
        else:
            flash("No OTP found for this email.", "error")
            return redirect(url_for("register"))

    return render_template("auth/verify_otp.html", email=email)

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(request.referrer or url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        if not email or not password:
            flash("Please enter both email and password to log in.", "error")
            return redirect(url_for("login"))

        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["user_email"] = user.email
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password!", "error")
            return redirect(url_for("login"))

    return render_template("auth/login.html")

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if "user_id" in session:
        return redirect(request.referrer or url_for("dashboard"))
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps(email, salt='password-reset')
            reset_link = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request', sender='your_email@gmail.com', recipients=[email])
            msg.body = f'Click the following link to reset your password: {reset_link}'
            try:
                mail.send(msg)
                flash('A password reset link has been sent to your email address.', 'success')
                return redirect(url_for('forgot_password'))
            except:
                flash('There was an error sending the email. Please try again later.', 'danger')
                return redirect(url_for('forgot_password'))
        else:
            flash('No account found with this email address.', 'error')
            return redirect(url_for('forgot_password'))
    return render_template('auth/forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset', max_age=3600)
        if request.method == 'POST':
            password = request.form.get("password")
            if not password or not is_valid_password(password):
                flash("Password must be at least 6 characters long, contain at least one letter, one number, and one special character!", "danger")
                return render_template("auth/reset_password.html", token=token)
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            user = User.query.filter_by(email=email).first()

            if user:
                user.password = hashed_password
                db.session.commit()
                flash('Your password has been successfully reset!', 'success')
                return redirect(url_for('login'))
            else:
                flash('User not found. Please try again.', 'danger')
                return redirect(url_for('forgot_password'))
        return render_template('auth/reset_password.html', token=token)
    except SignatureExpired:
        flash('The password reset link has expired.', 'danger')
        return redirect(url_for('forgot_password'))
    except Exception as e:
        flash('The password reset link is invalid.', 'danger')
        return redirect(url_for('forgot_password'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))
    return render_template("admin/dashboard.html")

with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True, use_reloader=True)
