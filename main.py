from flask import Flask, render_template, request, redirect, url_for, session
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_
import os
import random
import csv
from collections import defaultdict
from flask_session import Session

app = Flask(__name__)

# Dynamische Datenbank-URI
database_url = os.environ.get('DATABASE_URL', 'sqlite:///quiz.db')
if database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

is_production = os.environ.get('FLASK_ENV') == 'production'
app.config.update(
    SESSION_COOKIE_SECURE=is_production,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SECRET_KEY=os.environ.get('SECRET_KEY', os.urandom(24).hex())
)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    highscore = db.Column(db.Integer, default=0)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(150), nullable=False)
    question = db.Column(db.String(500), unique=True, nullable=False)
    true = db.Column(db.String(150), nullable=False)
    wrong1 = db.Column(db.String(150), nullable=False)
    wrong2 = db.Column(db.String(150), nullable=False)
    wrong3 = db.Column(db.String(150), nullable=False)

# Serverseitige Session-Konfiguration
app.config['SESSION_TYPE'] = 'sqlalchemy'
app.config['SESSION_SQLALCHEMY'] = db
app.config['SESSION_PERMANENT'] = False
server_session = Session(app)

bcrypt = Bcrypt(app)

# Automatische Datenbankinitialisierung beim App-Start
def initialize_database():
    """Erstellt Tabellen und importiert Fragen bei Bedarf"""
    with app.app_context():
        # Erstelle alle Tabellen, falls nicht vorhanden
        db.create_all()
        
        # Prüfe, ob bereits Fragen vorhanden sind
        if Question.query.count() == 0:
            print("Importiere Fragen...")
            categories = [
                'sport', 
                'geschichte', 
                'film', 
                'geographie', 
                'musik', 
                'wissenschaft'
            ]
            
            for category in categories:
                csv_file = f"{category}_fragen.csv"
                try:
                    with open(csv_file, 'r', encoding='utf-8') as file:
                        reader = csv.DictReader(file, delimiter=';')
                        for row in reader:
                            if not all(key in row for key in ['subject', 'question', 'true', 'wrong1', 'wrong2', 'wrong3']):
                                continue
                                
                            # Prüfe, ob Frage bereits existiert
                            if not Question.query.filter_by(question=row['question'].strip()).first():
                                new_question = Question(
                                    subject=row['subject'].strip(),
                                    question=row['question'].strip(),
                                    true=row['true'].strip(),
                                    wrong1=row['wrong1'].strip(),
                                    wrong2=row['wrong2'].strip(),
                                    wrong3=row['wrong3'].strip()
                                )
                                db.session.add(new_question)
                        db.session.commit()
                    print(f"Fragen für {category} importiert")
                except Exception as e:
                    print(f"Fehler beim Import von {csv_file}: {str(e)}")
            print("Datenbankinitialisierung abgeschlossen")

# Initialisierung beim App-Start
initialize_database()

# Ab hier bleiben alle Routes unverändert
@app.route('/')
def index():
    if 'username' in session: 
        return redirect(url_for('homepage')) 
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username'].strip()
    password = request.form['password'].strip()

    if username and password:
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            session['username'] = username
            return redirect(url_for('homepage')) 
        return render_template('index.html', error='Ungültige Anmeldedaten')
    return render_template('index.html', error='Bitte fülle alle Felder aus')

@app.route('/register', methods=['POST'])
def register():
    username = request.form['username'].strip()
    password = request.form['password'].strip()

    if username and password:
        if User.query.filter_by(username=username).first():
            return render_template('index.html', error='Benutzername bereits vergeben')
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        session['username'] = username
        return redirect(url_for('homepage'))
    return render_template('index.html', error='Bitte fülle alle Felder aus')

@app.route('/homepage')
def homepage():
    if 'username' in session:
        error = request.args.get('error')
        user = User.query.filter_by(username=session['username']).first()
        return render_template(
            'homepage.html',
            username=session['username'],
            highscore=user.highscore if user else 0,
            error=error
        )
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/start_custom_quiz', methods=['POST'])
def start_custom_quiz():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    selected_topics = request.form.getlist('topics')
    
    if not selected_topics:
        return redirect(url_for('homepage', error='Bitte wähle mindestens ein Thema aus'))

    conditions = [func.lower(Question.subject) == func.lower(topic) for topic in selected_topics]
    all_questions = Question.query.filter(or_(*conditions)).all()

    if not all_questions:
        return redirect(url_for('homepage', error='Keine Fragen für die ausgewählten Themen gefunden'))

    questions_by_topic = defaultdict(list)
    for q in all_questions:
        questions_by_topic[q.subject.lower()].append(q)
    
    selected_questions = []
    target_per_topic = max(1, 30 // len(selected_topics))
    
    for topic in selected_topics:
        topic_questions = questions_by_topic.get(topic.lower(), [])
        random.shuffle(topic_questions)
        selected_questions.extend(topic_questions[:target_per_topic])
    
    remaining = 30 - len(selected_questions)
    if remaining > 0:
        extra_questions = [q for q in all_questions if q not in selected_questions]
        random.shuffle(extra_questions)
        selected_questions.extend(extra_questions[:remaining])
    
    random.shuffle(selected_questions)
    num_questions = min(30, len(selected_questions))

    session['quiz_data'] = {
        'subject': ', '.join(selected_topics),
        'questions': [q.id for q in selected_questions],
        'current_index': 0,
        'total_questions': num_questions,
        'score': 0
    }
    
    return redirect(url_for('show_question'))

@app.route('/show_question')
def show_question():
    if 'quiz_data' not in session:
        return redirect(url_for('homepage'))
    
    quiz_data = session['quiz_data']
    current_index = quiz_data['current_index']
    question = Question.query.get(quiz_data['questions'][current_index])
    
    options = [question.true, question.wrong1, question.wrong2, question.wrong3]
    random.shuffle(options)
    
    was_correct = session.pop('last_answer_correct', False)
    
    return render_template(
        'quiz.html',
        subject=quiz_data['subject'],
        question=question,
        options=options,
        progress=current_index + 1,
        total_questions=quiz_data['total_questions'],
        score=quiz_data['score'],
        was_correct=was_correct
    )

@app.route('/next_question', methods=['POST'])
def next_question():
    if 'quiz_data' not in session or 'username' not in session:
        return redirect(url_for('homepage'))
    
    quiz_data = session['quiz_data']
    question = Question.query.get(quiz_data['questions'][quiz_data['current_index']])
    user_answer = request.form.get('answer')
    
    if user_answer == question.true:
        quiz_data['score'] += 1
        session['last_answer_correct'] = True
    
    quiz_data['current_index'] += 1
    session['quiz_data'] = quiz_data
    
    if quiz_data['current_index'] < quiz_data['total_questions']:
        return redirect(url_for('show_question'))
    return redirect(url_for('evaluate_quiz'))

@app.route('/evaluate')
def evaluate_quiz():
    if 'quiz_data' not in session or 'username' not in session:
        return redirect(url_for('homepage'))
    
    quiz_data = session.pop('quiz_data', None)
    score = quiz_data.get('score', 0)
    total = quiz_data.get('total_questions', 0)
    
    # Highscore-Logik
    user = User.query.filter_by(username=session['username']).first()
    new_highscore = False
    
    if user:
        if score > user.highscore:
            user.highscore = score
            new_highscore = True
            db.session.commit()
    
    return render_template(
        'evaluate.html',
        score=score,
        total=total,
        new_highscore=new_highscore,
        highscore=user.highscore if user else score
    )

@app.route('/cancel_quiz', methods=['POST'])
def cancel_quiz():
    if 'quiz_data' in session:
        session.pop('quiz_data', None)
    return '', 204

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)