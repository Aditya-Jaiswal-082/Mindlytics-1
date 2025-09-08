import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from flask_bcrypt import Bcrypt
from chatterbot import ChatBot
from chatterbot.trainers import ChatterBotCorpusTrainer

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change_this_secret')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

class SurveyResponse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
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

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()

chatbot = ChatBot('MentalHealthBot',
                  storage_adapter='chatterbot.storage.SQLStorageAdapter',
                  database_uri='sqlite:///chatbot_db.sqlite3')

trainer = ChatterBotCorpusTrainer(chatbot)
trainer.train("chatterbot.corpus.english")
trainer.train("./my_corpus.mental_health.yml")  # Your custom corpus path


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            return render_template('signup.html', error='Email already registered.')
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid email or password.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/survey', methods=['GET', 'POST'])
@login_required
def survey():
    if request.method == 'POST':
        sleep_hours = int(request.form['sleep_hours'])
        diet = request.form['diet']
        exercise_frequency = request.form['exercise_frequency']
        stress_level = request.form['stress_level']
        social_media_time = int(request.form['social_media_time'])
        negative_emotions = request.form['negative_emotions'] == 'Yes'
        late_night_scrolling = request.form['late_night_scrolling'] == 'Yes'
        engagement_frequency = request.form['engagement_frequency']

        risk = assess_risk(sleep_hours, diet, exercise_frequency, stress_level,
                          social_media_time, negative_emotions, late_night_scrolling, engagement_frequency)

        response = SurveyResponse(
            user_id=current_user.id,
            sleep_hours=sleep_hours,
            diet=diet,
            exercise_frequency=exercise_frequency,
            stress_level=stress_level,
            social_media_time=social_media_time,
            negative_emotions=negative_emotions,
            late_night_scrolling=late_night_scrolling,
            engagement_frequency=engagement_frequency,
            result=risk,
            timestamp=datetime.now()
        )
        db.session.add(response)
        db.session.commit()

        tips = get_tips(risk, sleep_hours, diet, exercise_frequency, stress_level,
                        social_media_time, negative_emotions, late_night_scrolling)
        return render_template('survey.html', risk=risk, tips=tips, submitted=True)

    return render_template('survey.html')


def assess_risk(sleep_hours, diet, exercise_frequency, stress_level,
                social_media_time, negative_emotions, late_night_scrolling, engagement_frequency):
    score = 0
    if sleep_hours < 6:
        score += 2
    elif sleep_hours < 8:
        score += 1
    if diet == 'Unhealthy':
        score += 2
    elif diet == 'Moderate':
        score += 1
    if exercise_frequency == 'Never':
        score += 2
    elif exercise_frequency == 'Sometimes':
        score += 1
    if stress_level == 'High':
        score += 2
    elif stress_level == 'Medium':
        score += 1
    if social_media_time > 4:
        score += 2
    elif social_media_time > 2:
        score += 1
    if negative_emotions:
        score += 2
    if late_night_scrolling:
        score += 1
    if engagement_frequency == 'Frequently':
        score += 1

    if score >= 7:
        return 'High'
    elif score >= 4:
        return 'Moderate'
    else:
        return 'Low'


def get_tips(risk, sleep_hours, diet, exercise_frequency, stress_level,
             social_media_time, negative_emotions, late_night_scrolling):
    tips = []
    if risk == 'High':
        tips.append("Consider talking to a mental health professional.")
        tips.append("Practice mindfulness and relaxation daily.")
    if sleep_hours < 6:
        tips.append("Aim for at least 7 hours of sleep each night for better well-being.")
    if diet == 'Unhealthy':
        tips.append("Try to incorporate more nutritious foods into your diet.")
    if exercise_frequency == 'Never':
        tips.append("Introduce light exercises or daily walks to your routine.")
    if stress_level == 'High':
        tips.append("Practice deep breathing and stress-reducing activities.")
    if social_media_time > 4:
        tips.append("Reduce your daily social media use; try digital breaks.")
    if negative_emotions:
        tips.append("Be mindful about your feelings after social media; consider reducing usage.")
    if late_night_scrolling:
        tips.append("Avoid using social media late at night to improve sleep quality.")
    return tips


@app.route('/dashboard')
@login_required
def dashboard():
    surveys = SurveyResponse.query.filter_by(user_id=current_user.id).order_by(SurveyResponse.timestamp.desc()).all()
    return render_template('dashboard.html', surveys=surveys)

def get_latest_user_profile(user_id):
    survey = SurveyResponse.query.filter_by(user_id=user_id).order_by(SurveyResponse.timestamp.desc()).first()
    if not survey:
        return {}
    return {
        'sleep_hours': survey.sleep_hours,
        'stress_level': survey.stress_level,
    }

@app.route('/api/chatbot', methods=['POST'])
@login_required
def chatbot_api():
    data = request.get_json()
    user_message = data.get('message', '').lower()
    profile = get_latest_user_profile(current_user.id)

    if any(kw in user_message for kw in ["sleep", "sleep cycle", "hours of sleep"]):
        sleep_hours = profile.get('sleep_hours')
        if sleep_hours:
            reply = f"Your last reported sleep duration was {sleep_hours} hours."
        else:
            reply = "I don't have your sleep data yet. Please complete the survey."
        return jsonify({'response': reply})

    elif any(kw in user_message for kw in ["stress", "anxiety", "stressed"]):
        stress = profile.get('stress_level')
        if stress:
            reply = f"Your last reported stress level was {stress}. Remember to take breaks and relax."
        else:
            reply = "I don't have your stress info yet. Please complete the survey."
        return jsonify({'response': reply})

    bot_response = str(chatbot.get_response(user_message))
    return jsonify({'response': bot_response})

@app.route('/chatbot')
@login_required
def chatbot_view():
    return render_template('chatbot.html')

app.add_url_rule('/chatbot', endpoint='chatbot', view_func=login_required(chatbot_view))


if __name__ == '__main__':
    import os

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))  # default to 5000 if PORT unset
    app.run(host='0.0.0.0', port=port)        # bind to all interfaces
