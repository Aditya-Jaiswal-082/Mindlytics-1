from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    surveys = db.relationship('SurveyResponse', backref='user', lazy=True)

class SurveyResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sleep_hours = db.Column(db.Integer)
    diet = db.Column(db.String(20))
    exercise_frequency = db.Column(db.String(20))
    stress_level = db.Column(db.String(20))
    social_media_time = db.Column(db.Integer)
    negative_emotions = db.Column(db.Boolean)
    late_night_scrolling = db.Column(db.Boolean)
    engagement_frequency = db.Column(db.String(20))
    result = db.Column(db.String(10))
    timestamp = db.Column(db.DateTime)
