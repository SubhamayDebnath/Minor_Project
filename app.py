from flask import Flask, render_template, request, flash, redirect, url_for, session
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import random
import string
import re
import time
from datetime import datetime


app = Flask(__name__)

# Use a proper secret key for the app
app.config["SECRET_KEY"] = "your_secret_key_here"  # Change this to a real secret key

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Setup URLSafeTimedSerializer for generating reset tokens
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])



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
    rescuer = db.Column(db.Boolean, default=True)  
    is_admin = db.Column(db.Boolean, default=True) 

class DisasterReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    alert = db.Column(db.String(100), nullable=False)
    status = db.Column(db.Boolean, default=True)
    date_reported = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    latitude = db.Column(db.Float, nullable=True)  
    longitude = db.Column(db.Float, nullable=True)
    range = db.Column(db.Float, nullable=True)   

class Skill(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    skill_name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    isAvailable = db.Column(db.Boolean, default=True, nullable=False)
   

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

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error/404.html',referrer=request.referrer), 404
# Routes
@app.route("/")
def home():
    userID=session.get("user_id")
    isLoggedIn = False
    if userID:
        isLoggedIn = True
    return render_template("home/index.html",isLoggedIn=isLoggedIn)

@app.route('/alert')
def homePageReport():
    userID=session.get("user_id")
    isLoggedIn = False
    if userID:
        isLoggedIn = True
    disaster_reports = DisasterReport.query.all()
    return render_template("home/report.html",disaster_reports=disaster_reports,isLoggedIn=isLoggedIn)

@app.route('/alert_report/<int:report_id>')
def alert_report(report_id):
    userID=session.get("user_id")
    isLoggedIn = False
    if userID:
        isLoggedIn = True
    report = DisasterReport.query.get_or_404(report_id)
    return render_template("home/show_alert.html",isLoggedIn=isLoggedIn,report=report)

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
            if user.is_admin:
                return redirect(url_for("dashboard"))
            else:
                return redirect('/')
        else:
            flash("Invalid email or password!", "error")
            return redirect(url_for("login"))

    return render_template("auth/login.html")

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))
    Skills_len=len(Skill.query.all())
    disaster_reports_len=len(DisasterReport.query.all())
    user_len = len(User.query.all())
    return render_template("admin/dashboard.html",disaster_reports_len=disaster_reports_len,Skills_len=Skills_len,user_len=user_len)

@app.route("/report", methods=["GET", "POST"])
def alert():
    if "user_id" not in session:
        flash("Please log in first.", "error")
        return redirect(url_for("login"))

    if request.method == 'POST':
        title = request.form['type']  
        description = request.form['desc']  
        location = request.form['location'] 
        status = request.form.get('status') == '1'  # Ensures status is handled properly
        alert = request.form['alert']
        latitude = request.form.get('latitude')  # Adding latitude if it's part of the form
        longitude = request.form.get('longitude')
        range = request.form.get('range')  # Adding longitude if it's part of the form
        user_id = session.get("user_id")
        date_reported = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # Creating a new disaster report instance
        new_report = DisasterReport(
                title=title,
                description=description,
                location=location,
                status=status,
                alert=alert,
                date_reported=date_reported,
                user_id=user_id,
                latitude=latitude if latitude else None,  
                longitude=longitude if longitude else None,
                range=range
        )

        db.session.add(new_report)
        db.session.commit()

        return redirect('/report') 

    disaster_reports = DisasterReport.query.all()
    return render_template("admin/alert.html", disaster_reports=disaster_reports)  

@app.route('/update_report/<int:id>', methods=['GET', 'POST'])
def update_report(id):
    disaster_report = DisasterReport.query.get_or_404(id)
    if request.method == 'POST':
        title = request.form['type']  
        description = request.form['desc']  
        location = request.form['location']
        status = True if request.form['status'] == '1' else False  
        alert_level = request.form['alert'] 
        user_id = session.get("user_id") 
        date_reported = datetime.now().strftime('%Y-%m-%d %H:%M:%S')  
        disaster_report.title = title
        disaster_report.description = description
        disaster_report.location = location
        disaster_report.status = status
        disaster_report.alert = alert_level
        disaster_report.date_reported = date_reported
        disaster_report.user_id = user_id 
        db.session.commit()

        return redirect('/report') 

    return render_template('form/update_report.html', disaster_report=disaster_report)


@app.route('/delete_disaster/<int:id>', methods=['GET', 'POST'])
def delete_disaster(id):
    disaster_report = DisasterReport.query.get_or_404(id) 
    db.session.delete(disaster_report)  
    db.session.commit() 
    return redirect('/report')

@app.route('/skills', methods=['GET', 'POST'])
def skills():
    if request.method == 'POST':
        skill_name = request.form['skill']
        isAvailable = request.form['isAvailable']
        if not skill_name or not isAvailable:
            flash('Please fill in all fields', 'error')
            return redirect(url_for('skills'))
        else:
            new_skill = Skill(skill_name=skill_name, isAvailable=isAvailable == 'on')
            db.session.add(new_skill)
            db.session.commit()
            return redirect(url_for('skills'))
    skill_list=Skill.query.all()
    return render_template('admin/skills.html',skill_list=skill_list)
 
@app.route('/update_skill/<int:id>', methods=['GET', 'POST']) 
def update_skill(id):
    skill = Skill.query.get_or_404(id) 
    if request.method == 'POST':
        skill.skill_name = request.form['skill']
        skill.isAvailable = request.form['isAvailable'] == 'on' 
        skill.updated_at = datetime.utcnow()
        db.session.commit() 
        flash('Skill updated successfully.', 'success') 
        return redirect(url_for('skills')) 
    return render_template('form/update_skill.html', skill=skill)


@app.route('/delete_skill/<int:id>', methods=['GET', 'POST'])
def delete_skill(id):
    skill = Skill.query.get(id) 
    if skill:
        db.session.delete(skill) 
        db.session.commit()
        flash('Skill has been deleted successfully.', 'success') 
    else:
        flash('Skill not found.', 'danger') 

    return redirect(url_for('skills'))
@app.route('/users',methods=['GET', 'POST'])
def users():
    users = User.query.all()
    user_id=session.get('user_id')
    return render_template('admin/user.html', users=users,user_id=user_id)

@app.route('/delete_user/<int:id>', methods=['GET', 'POST'])
def delete_user(id):
    user = User.query.get(id) 
    if user:
        db.session.delete(user) 
        db.session.commit()
        flash('User has been deleted successfully.', 'success') 
    else:
        flash('User not found.', 'danger') 

    return redirect('/users')

@app.route('/update_user/<int:id>',  methods=['GET', 'POST'])
def update_user_admin(id):
    user = User.query.get(id)
    if not user:
        flash('User not found.', 'danger') 
        return redirect(url_for('users'))
    if request.method == 'POST':
        is_rescuer = request.form.get('rescuer') 
        is_admin = request.form.get('is_admin') 
        print(is_rescuer,is_admin)
        user.rescuer = is_rescuer == 'on'
        user.is_admin = is_admin == 'on'
        db.session.commit()
        flash('User updated successfully.', 'success')
        return redirect('/users')
    return render_template('form/update_user.html', user=user)




with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True, use_reloader=True)
