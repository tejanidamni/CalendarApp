from flask import Flask, redirect, url_for, session, request, jsonify
from authlib.integrations.flask_client import OAuth
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.exc import IntegrityError
from flask_cors import CORS
import requests
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from oauthlib.oauth2 import WebApplicationClient
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import os
import datetime
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
CORS(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'
google_client_id = '168013803245-7sblomrmgj7l71qeciq80tv1l60sok9a.apps.googleusercontent.com'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'flaskcalenderapp@gmail.com'  
app.config['MAIL_PASSWORD'] = 'uqsdaxsxdrdjdvuj'  
app.config['MAIL_DEFAULT_SENDER'] = 'flaskcalenderapp@gmail.com'  
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
google_client = WebApplicationClient(google_client_id)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['JWT_SECRET_KEY'])
scheduler = BackgroundScheduler()
scheduler.start()

class User(db.Model):
    email = db.Column(db.String(120), primary_key=True, nullable=False)
    password = db.Column(db.String(128), nullable=True)

class CalendarItem(db.Model):
  id = db.Column(db.Integer, primary_key=True)
  title = db.Column(db.String(120), nullable=False)
  start = db.Column(db.DateTime, nullable=False)
  end = db.Column(db.DateTime, nullable=False)
  user_email = db.Column(db.Integer, db.ForeignKey('user.email'), nullable=False)
  user = db.relationship('User', backref=db.backref('calendar_items'), lazy=True)

with app.app_context():
    db.create_all()

@app.route('/calendar-items', methods=['GET'])
@jwt_required()
def get_calendar_items():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()
    items = CalendarItem.query.filter_by(user_email=current_user['email']).all()
    return jsonify([{
        'title': item.title,
        'start': item.start.isoformat(),
        'end': item.end.isoformat(),
    } for item in items])


@app.route('/calendar-item', methods=['POST'])
@jwt_required()
def add_calendar_item():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()
    print(user)
    data = request.get_json()
    new_item = CalendarItem(
        title=data['title'],
        start=datetime.datetime.fromisoformat(data['start']),
        end=datetime.datetime.fromisoformat(data['end']),
        user_email=current_user['email']
    )

    db.session.add(new_item)
    db.session.commit()
    return jsonify({
        'title': new_item.title,
        'start': new_item.start.isoformat(),
        'end': new_item.end.isoformat(),
    })

@app.route('/calendar-item', methods=['DELETE'])
@jwt_required()
def delete_calendar_item():
    current_user = get_jwt_identity()
    user = User.query.filter_by(email=current_user['email']).first()
    data = request.get_json()
    item = CalendarItem.query.filter_by(
        title=data['title'],
        start=datetime.datetime.fromisoformat(data['start']),
        end=datetime.datetime.fromisoformat(data['end']),
        user_email=current_user['email']
    ).first()
    if not item:
      return jsonify({'message':'Item not found'}), 404
    db.session.delete(item)
    db.session.commit()
    return jsonify({'message':'Item deleted successfully'}), 200


def send_email_reminders():
  with app.app_context():
    now = datetime.datetime.now()
    all_items= CalendarItem.query.all()

    for item in all_items:
      if (item.start >= now and item.start < (now + datetime.timedelta(minutes=360))):
        msg = Message('Reminder: ' + item.title, recipients=[item.user_email])
        msg.body = f'Reminder for your event "{item.title}" starting at {item.start}'
        print(msg.body)
        mail.send(msg)
  
scheduler.add_job(send_email_reminders, 'interval', minutes=1)
scheduler.start

@app.route('/reset-password/<token>', methods=['POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=7600)
    except SignatureExpired:
        return jsonify({'message': 'The token has expired'}), 400
    except BadSignature:
        return jsonify({'message': 'Invalid token'}), 400
    data = request.get_json()
    new_password = data.get('newPassword')
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404
    user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
    db.session.commit()
    return jsonify({'message': 'Password reset successful'}), 200

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Email not found'}), 404
    token = s.dumps(email, salt='password-reset-salt')
    reset_link = f"http://localhost:3000/reset-password/{token}"
    msg = Message('Password Reset Request', recipients=[email])
    msg.body = f'Please click the link to reset your password: {reset_link}'
    mail.send(msg)
    return jsonify({'message': 'Password reset email sent'}), 200

@app.route('/login', methods=['POST'])
def login():

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if user:
        if user.password:
            if bcrypt.check_password_hash(user.password, password):
                access_token = create_access_token(identity={'email': email})
                return jsonify({'access_token': access_token}), 200
            else:
                return jsonify({'message': 'Invalid email or password'}), 401
        else:
            return jsonify({'message': 'Please register or login through Google'}), 401
    else:
        return jsonify({'message': 'Please register or login through Google'}), 401


    1

@app.route('/google-login', methods=['POST'])
def google_login():
    data = request.get_json()
    token = data.get('token')

    # Verify the token with Google
    google_token_url = f"https://oauth2.googleapis.com/tokeninfo?id_token={token}"
    response = requests.get(google_token_url)

    if response.status_code != 200:
        return jsonify({'message': 'Invalid Google token'}), 401

    google_user_info = response.json()
    email = google_user_info['email']
    user = User.query.filter_by(email=email).first()
    if not user:
        # Register the user if not already registered
        user = User(email=email)
        db.session.add(user)
        db.session.commit()

    access_token = create_access_token(identity={'email': email})
    return jsonify({'access_token': access_token, 'email':email}), 200

 

@app.route('/register', methods=['POST'])
def register():

    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'message': 'Email and password are required'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(email=email, password=hashed_password)
    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'Registration successful!'}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'message': 'Email already registered'}), 400

if __name__ == '__main__':
    app.run(debug=True)