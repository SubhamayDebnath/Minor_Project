from flask import Flask, render_template, request, flash, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import random
import string
import re
import time

app = Flask(__name__)
app.secret_key = "worldHello"  # Change this to a real secret key

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///users.db"  # Change the database URI if needed
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Mail configuration


# Initialize database
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
    # Create the Message object
    msg = Message("Your OTP Code", sender="your_email@gmail.com", recipients=[email])
    msg.body = f"Your OTP is {otp}. It will expire in 5 minutes."

    # Send the message using the Flask-Mail send() method
    try:
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")
        flash("There was an issue sending the OTP. Please try again.", "error")


# Phone validation regex (for Indian phone numbers)
phone_regex = re.compile(r"^\+91[789]\d{9}$")

# Email validation regex
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9_.+-]{6,}@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None


# Password validation regex
def is_valid_password(password):
    password_regex = r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@#$!%*?&])[A-Za-z\d@$!%*?&]{6,}$'
    return re.match(password_regex, password) is not None


# HomePage route
@app.route("/")
def home():
    return render_template("home/index.html")


# Register route
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Retrieve data from Form
        name = request.form.get("name")
        email = request.form.get("email")
        phone = request.form.get("phone")
        password = request.form.get("password")

        # Validation checks
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
            flash(
                "Password must be at least 6 characters long, contain at least one letter, one number, and one special character!",
                "error",
            )
            return redirect(url_for("register"))

        # Store user data in session
        session["name"] = name
        session["email"] = email
        session["phone"] = phone
        session["password"] = password

        # Generate OTP and save it to DB
        otp = generate_otp()
        otp_expiry = time.time() + 300  # 5 minutes expiry time
        new_otp = OTP(email=email, otp_code=otp, expiry_time=otp_expiry)
        db.session.add(new_otp)
        db.session.commit()

        # Send OTP email
        send_otp_email(email, otp)
        flash("OTP sent to your email. Please verify to complete registration.", "info")
        return redirect(url_for("verify_otp", email=email))

    return render_template("auth/register.html")


# OTP Verification route
@app.route("/verify_otp/<email>", methods=["GET", "POST"])
def verify_otp(email):
    if request.method == "POST":
        otp = request.form.get("otp").strip()
        otp_entry = OTP.query.filter_by(email=email).first()

        # Retrieve data from session
        name = session.get("name")
        email = session.get("email")
        phone = session.get("phone")
        password = session.get("password")
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        password=hashed_password
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


# Login route
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Retrieve data from Form
        email = request.form.get("email")
        password = request.form.get("password")
        # Validation checks
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


# Dashboard route (only accessible after login)
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))
    return render_template("admin/dashboard.html")


# Run the application
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True, use_reloader=True)
